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
    mock_code_url,
)
from license_server.signer import datetime_text


OPEN_STATUSES = (
    OrderStatus.CREATED.value,
    OrderStatus.WAITING_PAYMENT.value,
    OrderStatus.ABNORMAL.value,
)


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
    now: datetime | None = None,
) -> PaymentOrderResult:
    product = _product(product_code)
    if provider is None:
        raise PaymentServiceError("payment_provider_not_configured", status_code=503)
    if provider != "mock":
        raise PaymentServiceError("payment_provider_not_supported", status_code=503)
    now = _utc(now)
    def action(connection):
        _close_expired_open_orders(connection, now=now)
        row = _open_order(connection, device_fingerprint_hash, now=now)
        if row is None:
            row = _insert_order_with_gateway(
                connection,
                device_fingerprint_hash=device_fingerprint_hash,
                product_code=product.product_code,
                provider=provider,
                ttl_minutes=ttl_minutes,
                gateway=gateway,
                now=now,
            )
        return _order_result(row)

    return _payment_transaction(database_path, action)


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
        lambda connection: _confirm_paid_order(
            connection,
            evidence,
            notification_id=notification_id,
            issued_by=issued_by,
            now=_utc(now),
        ),
    )


def _insert_order_with_gateway(
    connection,
    *,
    device_fingerprint_hash: str,
    product_code: str,
    provider: str,
    ttl_minutes: int,
    gateway: PaymentGateway,
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

    try:
        gateway_order = gateway.create_native_order(
            CreateNativeOrderRequest(
                order_id=order_id,
                description="WHUT Campus Auto Login annual license",
                amount_fen=ANNUAL_V1.amount_fen,
                currency=ANNUAL_V1.currency,
                expires_at=expires_at,
            )
        )
    except Exception as exc:
        _mark_order_abnormal(connection, order_id, "payment_gateway_failed", now)
        raise PaymentServiceError(
            "payment_gateway_failed",
            status_code=502,
            commit=True,
        ) from exc

    connection.execute(
        """
        UPDATE payment_orders
        SET status = 'WAITING_PAYMENT',
            provider_order_id = ?,
            provider_trade_state = ?,
            updated_at = ?
        WHERE order_id = ?
        """,
        (
            gateway_order.provider_order_id,
            gateway_order.provider_trade_state,
            datetime_text(now),
            order_id,
        ),
    )
    return _order_by_id(connection, order_id)


def _confirm_paid_order(
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
    if status == OrderStatus.CREATED.value:
        return "order_not_waiting_payment"
    if status == OrderStatus.PAID.value:
        existing_txn = str(order["provider_transaction_id"] or "")
        if existing_txn and existing_txn != evidence.provider_transaction_id:
            return "provider_transaction_conflict"
    try:
        product = get_product(str(order["product_code"]))
    except PaymentDomainError:
        return "product_mismatch"
    if int(order["amount_fen"]) != product.amount_fen:
        return "product_amount_mismatch"
    if str(order["currency"]) != product.currency:
        return "product_currency_mismatch"
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
    return PaymentOrderResult(
        order_id=str(row["order_id"]),
        product_code=str(row["product_code"]),
        amount_fen=int(row["amount_fen"]),
        currency=str(row["currency"]),
        provider=provider,
        status=str(row["status"]),
        code_url=mock_code_url(str(row["order_id"])) if provider == "mock" else None,
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
