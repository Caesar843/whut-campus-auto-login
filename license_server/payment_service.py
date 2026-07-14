from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from license_client.constants import PAID_LICENSE_DAYS
from license_server.db import connect, write_transaction
from license_server.license_service import create_license, latest_paid_license
from license_server.payment import (
    ANNUAL_V1,
    OrderStatus,
    PaymentDomainError,
    PaymentEvidence,
    PaymentEvidenceSource,
    get_product,
)
from license_server.payment_gateway import (
    MOCK_APP_ID,
    MOCK_MCH_ID,
    CreateNativeOrderRequest,
    PaymentGateway,
    QueryOrderOutcome,
    QueryOrderResult,
    mock_code_url,
)
from license_server.signer import datetime_text
from license_server.wechat_payment import WechatPaymentError


PROVIDER_QUERY_RETRY_SECONDS = 10


class PaymentServiceError(RuntimeError):
    def __init__(self, code: str, *, status_code: int = 400, commit: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.commit = commit


@dataclass(frozen=True)
class PaymentOrderResult:
    order_id: str
    product_code: str
    amount_fen: int
    currency: str
    provider: str
    status: str
    code_url: str | None
    created_at: str
    expires_at: str
    paid_at: str | None


@dataclass(frozen=True)
class PaymentConfirmationResult:
    order_id: str
    status: str
    license_id: int
    grant_id: int
    expires_at: str
    idempotent: bool


def create_or_restore_order(
    database_path: Path,
    *,
    device_fingerprint_hash: str,
    product_code: str,
    provider: str | None,
    ttl_minutes: int,
    gateway: PaymentGateway,
    notify_url: str = "https://mock.invalid/notify",
    expected_appid: str | None = None,
    expected_mchid: str | None = None,
    now: datetime | None = None,
) -> PaymentOrderResult:
    product = _product(product_code)
    if provider is None:
        raise PaymentServiceError("payment_provider_not_configured", status_code=503)
    if provider not in {"mock", "wechat_native"}:
        raise PaymentServiceError("payment_provider_not_supported", status_code=503)
    now = _utc(now)
    row = _payment_transaction(
        database_path,
        lambda connection: _prepare_local_order(
            connection,
            device_fingerprint_hash=device_fingerprint_hash,
            product_code=product.product_code,
            provider=provider,
            ttl_minutes=ttl_minutes,
            now=now,
        ),
    )
    if str(row["status"]) != OrderStatus.CREATED.value:
        return _order_result(row)
    order_id = str(row["order_id"])
    expires_at = _parse_utc(str(row["expires_at"]))
    if expires_at is None:
        _record_retryable_gateway_error(
            database_path,
            order_id=order_id,
            code="invalid_expires_at",
            now=now,
        )
        raise PaymentServiceError("invalid_expires_at", status_code=409)
    claimed = _payment_transaction(
        database_path,
        lambda connection: _claim_native_create(
            connection,
            order_id=order_id,
            now=now,
        ),
    )
    if not claimed:
        return _restore_claimed_order(
            database_path,
            order_id=order_id,
            gateway=gateway,
            expected_appid=expected_appid,
            expected_mchid=expected_mchid,
            now=now,
        )
    try:
        gateway_order = gateway.create_native_order(
            CreateNativeOrderRequest(
                out_trade_no=order_id,
                description="WHUT Campus Auto Login annual license",
                amount_fen=ANNUAL_V1.amount_fen,
                currency=ANNUAL_V1.currency,
                notify_url=notify_url,
                expires_at=expires_at,
                attach=product.product_code,
            )
        )
    except WechatPaymentError as exc:
        if exc.result_unknown:
            return _recover_unknown_create_result(
                database_path,
                order_id=order_id,
                gateway=gateway,
                expected_appid=expected_appid,
                expected_mchid=expected_mchid,
                now=now,
            )
        code = exc.code.casefold()
        _record_retryable_gateway_error(
            database_path,
            order_id=order_id,
            code=code,
            now=now,
        )
        raise PaymentServiceError(code, status_code=502) from exc
    except Exception as exc:
        _record_retryable_gateway_error(
            database_path,
            order_id=order_id,
            code="payment_gateway_failed",
            now=now,
        )
        raise PaymentServiceError("payment_gateway_failed", status_code=502) from exc
    if gateway_order.provider_order_id != order_id:
        _record_retryable_gateway_error(
            database_path,
            order_id=order_id,
            code="payment_create_order_mismatch",
            now=now,
        )
        raise PaymentServiceError("payment_create_order_mismatch", status_code=502)
    return _persist_create_result(
        database_path,
        order_id=order_id,
        gateway_order=gateway_order,
        now=now,
    )


def _prepare_local_order(
    connection,
    *,
    device_fingerprint_hash: str,
    product_code: str,
    provider: str,
    ttl_minutes: int,
    now: datetime,
):
    _close_expired_open_orders(connection, now=now)
    row = _open_order(connection, device_fingerprint_hash, now=now)
    if row is None:
        row = _insert_local_order(
            connection,
            device_fingerprint_hash=device_fingerprint_hash,
            product_code=product_code,
            provider=provider,
            ttl_minutes=ttl_minutes,
            now=now,
        )
    return row


def _claim_native_create(connection, *, order_id: str, now: datetime) -> bool:
    now_text = datetime_text(now)
    cursor = connection.execute(
        """
        UPDATE payment_orders
        SET provider_create_claimed_at = ?,
            provider_create_attempt_count = 1,
            updated_at = ?
        WHERE order_id = ?
          AND status = 'CREATED'
          AND provider_create_attempt_count = 0
          AND provider_create_claimed_at IS NULL
        """,
        (now_text, now_text, order_id),
    )
    return cursor.rowcount == 1


def _restore_claimed_order(
    database_path: Path,
    *,
    order_id: str,
    gateway: PaymentGateway,
    expected_appid: str | None,
    expected_mchid: str | None,
    now: datetime,
) -> PaymentOrderResult:
    row, query_claimed = _payment_transaction(
        database_path,
        lambda connection: _claim_provider_query(
            connection,
            order_id=order_id,
            now=now,
        ),
    )
    if not query_claimed:
        return _order_result(row)
    try:
        query = gateway.query_order(order_id)
    except Exception:
        query = QueryOrderResult(
            outcome=QueryOrderOutcome.HTTP_UNKNOWN,
            out_trade_no=order_id,
        )
    return _apply_provider_query_result(
        database_path,
        order_id=order_id,
        query=query,
        expected_appid=expected_appid,
        expected_mchid=expected_mchid,
        now=now,
        query_attempt_recorded=True,
    )


def _claim_provider_query(connection, *, order_id: str, now: datetime):
    row = _order_by_id(connection, order_id)
    if row is None:
        raise PaymentServiceError("payment_order_not_found", status_code=404)
    if str(row["status"]) != OrderStatus.CREATED.value:
        return row, False
    now_text = datetime_text(now)
    cursor = connection.execute(
        """
        UPDATE payment_orders
        SET last_provider_query_at = ?,
            next_provider_query_at = ?,
            provider_query_attempt_count = provider_query_attempt_count + 1,
            updated_at = ?
        WHERE order_id = ?
          AND status = 'CREATED'
          AND provider_create_attempt_count = 1
          AND provider_create_claimed_at IS NOT NULL
          AND next_provider_query_at IS NOT NULL
          AND next_provider_query_at <= ?
        """,
        (
            now_text,
            datetime_text(now + timedelta(seconds=PROVIDER_QUERY_RETRY_SECONDS)),
            now_text,
            order_id,
            now_text,
        ),
    )
    return _order_by_id(connection, order_id), cursor.rowcount == 1


def get_order_for_device(
    database_path: Path,
    *,
    order_id: str,
    device_fingerprint_hash: str,
    now: datetime | None = None,
) -> PaymentOrderResult:
    now = _utc(now)
    with write_transaction(database_path) as connection:
        _close_expired_open_orders(connection, now=now)
        row = connection.execute(
            """
            SELECT * FROM payment_orders
            WHERE order_id = ? AND device_fingerprint_hash = ?
            """,
            (order_id, device_fingerprint_hash),
        ).fetchone()
        if row is None:
            raise PaymentServiceError("payment_order_not_found", status_code=404)
        return _order_result(row)


def confirm_paid_order(
    database_path: Path,
    evidence: PaymentEvidence,
    *,
    notification_id: str | None = None,
    issued_by: str = "mock",
    now: datetime | None = None,
) -> PaymentConfirmationResult:
    return _payment_transaction(
        database_path,
        lambda connection: _confirm_paid_order_in_transaction(
            connection,
            evidence,
            notification_id=notification_id,
            issued_by=issued_by,
            now=_utc(now),
        ),
    )


def _insert_local_order(
    connection,
    *,
    device_fingerprint_hash: str,
    product_code: str,
    provider: str,
    ttl_minutes: int,
    now: datetime,
):
    order_id = f"pay_{uuid4().hex}"
    expires_at = now + timedelta(minutes=ttl_minutes)
    try:
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, provider_order_id,
                provider_transaction_id, provider_trade_state, created_at,
                updated_at, expires_at, paid_at, closed_at, security_error_code
            ) VALUES (?, ?, ?, ?, ?, ?, 'CREATED', 'open', NULL, NULL,
                      NULL, ?, ?, ?, NULL, NULL, NULL)
            """,
            (
                order_id,
                device_fingerprint_hash,
                product_code,
                ANNUAL_V1.amount_fen,
                ANNUAL_V1.currency,
                provider,
                datetime_text(now),
                datetime_text(now),
                datetime_text(expires_at),
            ),
        )
    except sqlite3.IntegrityError:
        existing = _open_order(connection, device_fingerprint_hash, now=now)
        if existing is not None:
            return existing
        raise

    return _order_by_id(connection, order_id)


def _persist_create_result(
    database_path: Path,
    *,
    order_id: str,
    gateway_order,
    now: datetime,
) -> PaymentOrderResult:
    def action(connection):
        connection.execute(
            """
            UPDATE payment_orders
            SET status = 'WAITING_PAYMENT',
                provider_order_id = ?,
                provider_trade_state = ?,
                provider_code_url = ?,
                updated_at = ?,
                security_error_code = NULL,
                next_provider_query_at = NULL
            WHERE order_id = ? AND status = 'CREATED'
              AND provider_create_attempt_count = 1
              AND provider_create_claimed_at IS NOT NULL
              AND provider_code_url IS NULL
            """,
            (
                gateway_order.provider_order_id,
                gateway_order.provider_trade_state,
                gateway_order.code_url,
                datetime_text(now),
                order_id,
            ),
        )
        row = _order_by_id(connection, order_id)
        if row is None:
            raise PaymentServiceError("payment_order_not_found", status_code=404)
        return _order_result(row)

    return _payment_transaction(database_path, action)


def _recover_unknown_create_result(
    database_path: Path,
    *,
    order_id: str,
    gateway: PaymentGateway,
    expected_appid: str | None,
    expected_mchid: str | None,
    now: datetime,
) -> PaymentOrderResult:
    try:
        query = gateway.query_order(order_id)
    except Exception:
        query = QueryOrderResult(
            outcome=QueryOrderOutcome.HTTP_UNKNOWN,
            out_trade_no=order_id,
        )
    return _apply_provider_query_result(
        database_path,
        order_id=order_id,
        query=query,
        expected_appid=expected_appid,
        expected_mchid=expected_mchid,
        now=now,
    )


def _apply_provider_query_result(
    database_path: Path,
    *,
    order_id: str,
    query: QueryOrderResult,
    expected_appid: str | None,
    expected_mchid: str | None,
    now: datetime,
    query_attempt_recorded: bool = False,
) -> PaymentOrderResult:
    def action(connection):
        order = _order_by_id(connection, order_id)
        if order is None:
            raise PaymentServiceError("payment_order_not_found", status_code=404)
        if query_attempt_recorded:
            connection.execute(
                """
                UPDATE payment_orders
                SET provider_trade_state = COALESCE(?, provider_trade_state)
                WHERE order_id = ?
                """,
                (query.trade_state, order_id),
            )
        else:
            _record_provider_query(connection, order_id, query, now=now)
        if str(order["status"]) in {OrderStatus.PAID.value, OrderStatus.CLOSED.value}:
            return _order_result(_order_by_id(connection, order_id))
        if query.outcome in {QueryOrderOutcome.PAID, QueryOrderOutcome.CLOSED}:
            if _provider_query_conflicts(
                order,
                query,
                expected_appid=expected_appid,
                expected_mchid=expected_mchid,
            ):
                _mark_order_abnormal(connection, order_id, "payment_query_conflict", now)
                raise PaymentServiceError(
                    "payment_query_conflict",
                    status_code=409,
                    commit=True,
                )
        if query.outcome == QueryOrderOutcome.PAID:
            connection.execute(
                """
                UPDATE payment_orders
                SET status = 'WAITING_PAYMENT',
                    provider_order_id = ?,
                    provider_trade_state = ?,
                    updated_at = ?,
                    security_error_code = NULL,
                    next_provider_query_at = NULL
                WHERE order_id = ? AND status = 'CREATED'
                """,
                (query.out_trade_no, query.trade_state, datetime_text(now), order_id),
            )
            _confirm_paid_order_in_transaction(
                connection,
                PaymentEvidence(
                    source=PaymentEvidenceSource.WECHAT_QUERY,
                    out_trade_no=order_id,
                    provider_transaction_id=str(query.transaction_id),
                    trade_type=str(query.trade_type),
                    trade_state=str(query.trade_state),
                    amount_fen=int(query.amount_total),
                    currency=str(query.currency),
                    paid_at=query.success_time,
                    appid=str(query.appid),
                    mchid=str(query.mchid),
                ),
                notification_id=None,
                issued_by="wechat_query",
                now=now,
            )
            return _order_result(_order_by_id(connection, order_id))
        if query.outcome == QueryOrderOutcome.CLOSED:
            now_text = datetime_text(now)
            connection.execute(
                """
                UPDATE payment_orders
                SET status = 'CLOSED', open_slot = NULL, provider_trade_state = ?,
                    closed_at = ?, updated_at = ?, security_error_code = NULL,
                    next_provider_query_at = NULL
                WHERE order_id = ? AND status IN ('CREATED', 'WAITING_PAYMENT')
                """,
                (query.trade_state, now_text, now_text, order_id),
            )
            return _order_result(_order_by_id(connection, order_id))
        codes = {
            QueryOrderOutcome.NOT_FOUND: "payment_order_not_found_upstream",
            QueryOrderOutcome.SIGNATURE_INVALID: "payment_response_signature_invalid",
            QueryOrderOutcome.UNPAID: "payment_create_result_unknown",
            QueryOrderOutcome.UNCLEAR: "payment_result_unknown",
            QueryOrderOutcome.HTTP_UNKNOWN: "payment_result_unknown",
        }
        code = codes.get(query.outcome, "payment_result_unknown")
        connection.execute(
            """
            UPDATE payment_orders
            SET security_error_code = ?, next_provider_query_at = ?, updated_at = ?
            WHERE order_id = ? AND status IN ('CREATED', 'WAITING_PAYMENT')
            """,
            (
                code,
                datetime_text(now + timedelta(seconds=PROVIDER_QUERY_RETRY_SECONDS)),
                datetime_text(now),
                order_id,
            ),
        )
        raise PaymentServiceError(code, status_code=502, commit=True)

    return _payment_transaction(database_path, action)


def _record_provider_query(
    connection,
    order_id: str,
    query: QueryOrderResult,
    *,
    now: datetime,
) -> None:
    connection.execute(
        """
        UPDATE payment_orders
        SET last_provider_query_at = ?,
            provider_query_attempt_count = provider_query_attempt_count + 1,
            provider_trade_state = COALESCE(?, provider_trade_state)
        WHERE order_id = ?
        """,
        (datetime_text(now), query.trade_state, order_id),
    )


def _provider_query_conflicts(
    order,
    query: QueryOrderResult,
    *,
    expected_appid: str | None,
    expected_mchid: str | None,
) -> bool:
    common = (
        query.out_trade_no != str(order["order_id"])
        or query.trade_type != "NATIVE"
        or query.amount_total != int(order["amount_fen"])
        or query.currency != str(order["currency"])
        or not expected_appid
        or query.appid != expected_appid
        or not expected_mchid
        or query.mchid != expected_mchid
    )
    if common:
        return True
    return query.outcome == QueryOrderOutcome.PAID and (
        query.trade_state != "SUCCESS"
        or not query.transaction_id
        or query.success_time is None
    )


def _record_retryable_gateway_error(
    database_path: Path,
    *,
    order_id: str,
    code: str,
    now: datetime,
) -> None:
    with write_transaction(database_path) as connection:
        connection.execute(
            """
            UPDATE payment_orders
            SET security_error_code = ?, next_provider_query_at = ?, updated_at = ?
            WHERE order_id = ? AND status = 'CREATED'
            """,
            (
                code,
                datetime_text(now + timedelta(seconds=PROVIDER_QUERY_RETRY_SECONDS)),
                datetime_text(now),
                order_id,
            ),
        )


def _confirm_paid_order_in_transaction(
    connection,
    evidence: PaymentEvidence,
    *,
    notification_id: str | None,
    issued_by: str,
    now: datetime,
) -> PaymentConfirmationResult:
    order = _order_by_id(connection, evidence.out_trade_no)
    if order is None:
        raise PaymentServiceError("payment_order_not_found", status_code=404)

    _validate_evidence(connection, order, evidence, now=now)

    existing_grant = connection.execute(
        "SELECT * FROM license_grants WHERE source_order_id = ?",
        (evidence.out_trade_no,),
    ).fetchone()
    if existing_grant is not None:
        existing_license = connection.execute(
            "SELECT * FROM licenses WHERE id = ?",
            (int(existing_grant["license_id"]),),
        ).fetchone()
        if existing_license is None or str(order["status"]) != OrderStatus.PAID.value:
            raise PaymentServiceError("payment_grant_inconsistent", status_code=409)
        return PaymentConfirmationResult(
            order_id=evidence.out_trade_no,
            status=OrderStatus.PAID.value,
            license_id=int(existing_grant["license_id"]),
            grant_id=int(existing_grant["id"]),
            expires_at=str(existing_grant["new_expire_at"]),
            idempotent=True,
        )

    if str(order["status"]) == OrderStatus.PAID.value:
        raise PaymentServiceError("paid_order_missing_grant", status_code=409)

    device = connection.execute(
        """
        SELECT * FROM devices
        WHERE device_fingerprint_hash = ?
        """,
        (str(order["device_fingerprint_hash"]),),
    ).fetchone()
    if device is None:
        _mark_order_abnormal(connection, evidence.out_trade_no, "device_not_found", now)
        raise PaymentServiceError("device_not_found", status_code=409, commit=True)

    previous_paid = latest_paid_license(connection, int(device["id"]))
    previous_expires_at = (
        _parse_utc(str(previous_paid["expires_at"])) if previous_paid is not None else None
    )
    if (
        previous_paid is not None
        and str(previous_paid["status"]) == "active"
        and previous_expires_at is not None
        and previous_expires_at > now
    ):
        new_expires_at = previous_expires_at + timedelta(days=PAID_LICENSE_DAYS)
    else:
        new_expires_at = now + timedelta(days=PAID_LICENSE_DAYS)

    license_row = create_license(
        connection,
        device_id=int(device["id"]),
        license_type="paid",
        source="payment",
        starts_at=now,
        expires_at=new_expires_at,
        order_id=evidence.out_trade_no,
    )
    cursor = connection.execute(
        """
        INSERT INTO license_grants (
            source_order_id, device_fingerprint_hash, license_id, product_code,
            grant_days, previous_expire_at, new_expire_at, granted_at, issued_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evidence.out_trade_no,
            str(order["device_fingerprint_hash"]),
            int(license_row["id"]),
            str(order["product_code"]),
            PAID_LICENSE_DAYS,
            datetime_text(previous_expires_at) if previous_expires_at else None,
            datetime_text(new_expires_at),
            datetime_text(now),
            issued_by,
        ),
    )
    connection.execute(
        """
        UPDATE payment_orders
        SET status = 'PAID',
            open_slot = NULL,
            provider_transaction_id = ?,
            provider_trade_state = ?,
            paid_at = ?,
            updated_at = ?,
            security_error_code = NULL
        WHERE order_id = ?
        """,
        (
            evidence.provider_transaction_id,
            evidence.trade_state,
            datetime_text(evidence.paid_at),
            datetime_text(now),
            evidence.out_trade_no,
        ),
    )
    if notification_id:
        connection.execute(
            """
            UPDATE payment_notifications
            SET process_status = 'PROCESSED',
                processed_at = ?
            WHERE provider_notification_id = ?
            """,
            (datetime_text(now), notification_id),
        )
    return PaymentConfirmationResult(
        order_id=evidence.out_trade_no,
        status=OrderStatus.PAID.value,
        license_id=int(license_row["id"]),
        grant_id=int(cursor.lastrowid),
        expires_at=datetime_text(new_expires_at),
        idempotent=False,
    )


def _order_product_error(order) -> str | None:
    try:
        product = get_product(str(order["product_code"]))
        amount_fen = int(order["amount_fen"])
    except (PaymentDomainError, TypeError, ValueError):
        return "product_mismatch"
    if amount_fen != product.amount_fen:
        return "product_amount_mismatch"
    if str(order["currency"]) != product.currency:
        return "product_currency_mismatch"
    if product.duration_days != PAID_LICENSE_DAYS:
        return "product_duration_mismatch"
    return None


def _committed_payment_chain_is_valid_in_transaction(
    connection,
    order,
    *,
    expected_issued_by: str | None = None,
) -> bool:
    if (
        str(order["status"]) != OrderStatus.PAID.value
        or order["open_slot"] is not None
        or _order_product_error(order) is not None
    ):
        return False
    grant = connection.execute(
        "SELECT * FROM license_grants WHERE source_order_id = ?",
        (str(order["order_id"]),),
    ).fetchone()
    if grant is None:
        return False
    license_row = connection.execute(
        "SELECT licenses.*, "
        "devices.device_fingerprint_hash AS license_device_fingerprint_hash "
        "FROM licenses JOIN devices ON devices.id = licenses.device_id "
        "WHERE licenses.id = ?",
        (int(grant["license_id"]),),
    ).fetchone()
    if license_row is None:
        return False
    try:
        grant_days = int(grant["grant_days"])
        granted_at = _parse_utc(str(grant["granted_at"] or ""))
        new_expires_at = _parse_utc(str(grant["new_expire_at"] or ""))
        previous_expires_at = (
            _parse_utc(str(grant["previous_expire_at"]))
            if grant["previous_expire_at"] is not None
            else None
        )
        license_starts_at = _parse_utc(str(license_row["starts_at"] or ""))
        license_expires_at = _parse_utc(str(license_row["expires_at"] or ""))
    except (TypeError, ValueError):
        return False
    if (
        grant_days != PAID_LICENSE_DAYS
        or granted_at is None
        or new_expires_at is None
        or license_starts_at is None
        or license_expires_at is None
        or (
            grant["previous_expire_at"] is not None
            and previous_expires_at is None
        )
    ):
        return False
    base = (
        max(granted_at, previous_expires_at)
        if previous_expires_at is not None
        else granted_at
    )
    return bool(
        new_expires_at == base + timedelta(days=PAID_LICENSE_DAYS)
        and license_starts_at == granted_at
        and license_expires_at == new_expires_at
        and str(grant["source_order_id"]) == str(order["order_id"])
        and str(grant["device_fingerprint_hash"])
        == str(order["device_fingerprint_hash"])
        and str(grant["product_code"]) == str(order["product_code"])
        and (
            expected_issued_by is None
            or str(grant["issued_by"]) == expected_issued_by
        )
        and str(license_row["license_device_fingerprint_hash"])
        == str(grant["device_fingerprint_hash"])
        and str(license_row["license_type"]) == "paid"
        and str(license_row["status"]) == "active"
        and str(license_row["source"]) == "payment"
        and str(license_row["order_id"] or "") == str(grant["source_order_id"])
    )


def _validate_evidence(connection, order, evidence: PaymentEvidence, *, now: datetime) -> None:
    code = _evidence_error(connection, order, evidence, now=now)
    if code is None:
        return
    if code == "payment_order_expired":
        _mark_order_expired(connection, str(order["order_id"]), now)
        raise PaymentServiceError(code, status_code=409, commit=True)
    if str(order["status"]) != OrderStatus.PAID.value:
        _mark_order_abnormal(connection, str(order["order_id"]), code, now)
        raise PaymentServiceError(code, status_code=409, commit=True)
    raise PaymentServiceError(code, status_code=409)


def _evidence_error(connection, order, evidence: PaymentEvidence, *, now: datetime) -> str | None:
    status = str(order["status"])
    if status == OrderStatus.CLOSED.value:
        return "closed_order"
    expires_at = _parse_utc(str(order["expires_at"]))
    if status in {OrderStatus.CREATED.value, OrderStatus.WAITING_PAYMENT.value}:
        if expires_at is None:
            return "invalid_expires_at"
        if expires_at <= now:
            return "payment_order_expired"
    if (
        status == OrderStatus.CREATED.value
        and evidence.source != PaymentEvidenceSource.WECHAT_CALLBACK
    ):
        return "order_not_waiting_payment"
    if status == OrderStatus.PAID.value:
        existing_txn = str(order["provider_transaction_id"] or "")
        if existing_txn and existing_txn != evidence.provider_transaction_id:
            return "provider_transaction_conflict"
    product_error = _order_product_error(order)
    if product_error is not None:
        return product_error
    if _provider_for(evidence.source) != str(order["provider"]):
        return "provider_mismatch"
    if evidence.amount_fen != int(order["amount_fen"]):
        return "amount_mismatch"
    if evidence.currency != str(order["currency"]):
        return "currency_mismatch"
    if evidence.trade_type != "NATIVE":
        return "trade_type_mismatch"
    if evidence.trade_state != "SUCCESS":
        return "trade_state_not_success"
    if evidence.source == PaymentEvidenceSource.MOCK and (
        evidence.appid != MOCK_APP_ID or evidence.mchid != MOCK_MCH_ID
    ):
        return "merchant_identity_mismatch"
    conflict = connection.execute(
        """
        SELECT order_id FROM payment_orders
        WHERE provider_transaction_id = ? AND order_id <> ?
        """,
        (evidence.provider_transaction_id, evidence.out_trade_no),
    ).fetchone()
    if conflict is not None:
        return "provider_transaction_conflict"
    return None


def _provider_for(source: PaymentEvidenceSource) -> str:
    if source == PaymentEvidenceSource.MOCK:
        return "mock"
    return "wechat_native"


def _payment_transaction(database_path: Path, action):
    connection = connect(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        result = action(connection)
    except PaymentServiceError as exc:
        if exc.commit:
            connection.commit()
        else:
            connection.rollback()
        raise
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()
        return result
    finally:
        connection.close()


def _close_expired_open_orders(connection, *, now: datetime) -> None:
    now_text = datetime_text(now)
    connection.execute(
        """
        UPDATE payment_orders
        SET status = 'CLOSED',
            open_slot = NULL,
            closed_at = ?,
            updated_at = ?,
            security_error_code = 'expired'
        WHERE status IN ('CREATED', 'WAITING_PAYMENT')
          AND expires_at <= ?
        """,
        (now_text, now_text, now_text),
    )


def _open_order(connection, device_fingerprint_hash: str, *, now: datetime):
    return connection.execute(
        """
        SELECT * FROM payment_orders
        WHERE device_fingerprint_hash = ?
          AND open_slot = 'open'
          AND status IN ('CREATED', 'WAITING_PAYMENT', 'ABNORMAL')
          AND (status = 'ABNORMAL' OR expires_at > ?)
        ORDER BY id DESC
        LIMIT 1
        """,
        (device_fingerprint_hash, datetime_text(now)),
    ).fetchone()


def _mark_order_abnormal(connection, order_id: str, code: str, now: datetime) -> None:
    connection.execute(
        """
        UPDATE payment_orders
        SET status = 'ABNORMAL',
            open_slot = 'open',
            security_error_code = ?,
            updated_at = ?
        WHERE order_id = ? AND status IN ('CREATED', 'WAITING_PAYMENT', 'ABNORMAL')
        """,
        (code, datetime_text(now), order_id),
    )


def _mark_order_expired(connection, order_id: str, now: datetime) -> None:
    now_text = datetime_text(now)
    connection.execute(
        """
        UPDATE payment_orders
        SET status = 'CLOSED',
            open_slot = NULL,
            closed_at = ?,
            updated_at = ?,
            security_error_code = 'expired'
        WHERE order_id = ? AND status IN ('CREATED', 'WAITING_PAYMENT')
        """,
        (now_text, now_text, order_id),
    )


def _order_by_id(connection, order_id: str):
    return connection.execute(
        "SELECT * FROM payment_orders WHERE order_id = ?",
        (order_id,),
    ).fetchone()


def _order_result(row) -> PaymentOrderResult:
    provider = str(row["provider"])
    stored_code_url = row["provider_code_url"]
    return PaymentOrderResult(
        order_id=str(row["order_id"]),
        product_code=str(row["product_code"]),
        amount_fen=int(row["amount_fen"]),
        currency=str(row["currency"]),
        provider=provider,
        status=str(row["status"]),
        code_url=(
            str(stored_code_url)
            if stored_code_url
            else mock_code_url(str(row["order_id"])) if provider == "mock" else None
        ),
        created_at=str(row["created_at"]),
        expires_at=str(row["expires_at"]),
        paid_at=row["paid_at"],
    )


def _product(product_code: str):
    try:
        return get_product(product_code)
    except PaymentDomainError as exc:
        raise PaymentServiceError("unknown_product", status_code=400) from exc


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).replace(microsecond=0)
