from __future__ import annotations

import hmac
import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from license_server.db import connect
from license_server.device_proof import bearer_token, verify_device_proof_token
from license_server.payment import ANNUAL_V1, PaymentEvidence, PaymentEvidenceSource
from license_server.payment_gateway import (
    MOCK_APP_ID,
    MOCK_MCH_ID,
    PaymentGateway,
    mock_code_url,
)
from license_server.payment_reconciliation_repository import (
    ClaimOrderOutcome,
    EnsureReadyOutcome,
    PaymentReconciliationRepositoryError,
    claim_order,
    ensure_ready,
    get as get_reconciliation,
)
from license_server.payment_reconciliation_service import (
    PaymentReconciliationPolicy,
    PaymentReconciliationService,
    ReconciliationOutcome,
)
from license_server.payment_service import (
    PaymentOrderResult,
    PaymentServiceError,
    confirm_paid_order,
    create_or_restore_order,
)
from license_server.signer import datetime_text
from license_server.signer import LicenseSigningIdentity


_REFRESH_INTERVAL_SECONDS = 10
_REFRESH_CLAIM_LEASE_SECONDS = 60
_REFRESH_WORKER_ID = "manual-refresh"
_REFRESH_POLICY = PaymentReconciliationPolicy(
    query_retry_base_seconds=_REFRESH_INTERVAL_SECONDS,
    query_retry_max_seconds=60,
    max_query_attempts=5,
    close_retry_base_seconds=_REFRESH_INTERVAL_SECONDS,
    close_retry_max_seconds=60,
    max_close_attempts=3,
)


def _server_utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class PaymentOrderCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_code: str


class MockPayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PaymentRefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


def create_payment_router(
    *,
    database_path: Path,
    signing_identity: LicenseSigningIdentity,
    payment_provider: str | None,
    payment_mock_admin_token: str | None,
    gateway: PaymentGateway | None,
    notify_url: str | None,
    expected_appid: str | None,
    expected_mchid: str | None,
    payment_order_ttl_minutes: int,
    clock: Callable[[], datetime] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/payment")
    utc_now = clock or _server_utc_now
    reconciliation_service = _reconciliation_service(
        database_path=database_path,
        payment_provider=payment_provider,
        gateway=gateway,
        expected_appid=expected_appid,
        expected_mchid=expected_mchid,
    )

    @router.post("/orders")
    def create_order(
        request: PaymentOrderCreateRequest,
        authorization: str = Header(default=""),
    ):
        _require_payment_provider(payment_provider, gateway)
        proof = _proof(
            database_path,
            authorization=authorization,
            signing_identity=signing_identity,
        )
        try:
            result = create_or_restore_order(
                database_path,
                device_fingerprint_hash=proof.device_fingerprint_hash,
                product_code=request.product_code,
                provider=payment_provider,
                ttl_minutes=payment_order_ttl_minutes,
                gateway=gateway,
                notify_url=notify_url or "https://mock.invalid/notify",
                expected_appid=expected_appid,
                expected_mchid=expected_mchid,
            )
        except PaymentServiceError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        return _order_payload(result)

    @router.get("/orders/{order_id}")
    def get_order(order_id: str, authorization: str = Header(default="")):
        _require_payment_provider(payment_provider, gateway)
        proof = _proof(
            database_path,
            authorization=authorization,
            signing_identity=signing_identity,
        )
        try:
            result = _read_order_for_device(
                database_path,
                order_id=order_id,
                device_fingerprint_hash=proof.device_fingerprint_hash,
            )
        except PaymentServiceError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        return _order_payload(result)

    if reconciliation_service is not None:

        @router.post("/orders/{order_id}/refresh")
        def refresh_order(
            order_id: str,
            _request: PaymentRefreshRequest | None = Body(default=None),
            _valid_body: None = Depends(_reject_explicit_json_null),
            authorization: str = Header(default=""),
        ):
            proof = _proof(
                database_path,
                authorization=authorization,
                signing_identity=signing_identity,
            )
            try:
                order = _read_order_for_device(
                    database_path,
                    order_id=order_id,
                    device_fingerprint_hash=proof.device_fingerprint_hash,
                )
                immediate = _local_refresh_response(order)
                if immediate is not None:
                    return immediate

                now = utc_now()
                ensured = ensure_ready(database_path, order_id, now, now)
                if ensured.outcome is EnsureReadyOutcome.NOT_FOUND:
                    raise _refresh_unavailable()
                if ensured.outcome is EnsureReadyOutcome.NOT_ELIGIBLE:
                    return _current_refresh_response(
                        database_path,
                        order_id=order_id,
                        device_fingerprint_hash=proof.device_fingerprint_hash,
                    )

                claimed = claim_order(
                    database_path,
                    order_id=order_id,
                    worker_id=_REFRESH_WORKER_ID,
                    now=now,
                    lease_seconds=_REFRESH_CLAIM_LEASE_SECONDS,
                    clock=utc_now,
                )
                if claimed.outcome is ClaimOrderOutcome.NOT_DUE:
                    record = get_reconciliation(database_path, order_id)
                    retry_after = _retry_after(
                        record.next_attempt_at if record is not None else None,
                        utc_now(),
                    )
                    raise HTTPException(
                        status_code=429,
                        detail="PAYMENT_REFRESH_RATE_LIMITED",
                        headers={"Retry-After": str(retry_after)},
                    )
                if claimed.outcome is ClaimOrderOutcome.IN_PROGRESS:
                    record = get_reconciliation(database_path, order_id)
                    retry_after = _retry_after(
                        record.lease_expires_at if record is not None else None,
                        utc_now(),
                    )
                    current = _read_order_for_device(
                        database_path,
                        order_id=order_id,
                        device_fingerprint_hash=proof.device_fingerprint_hash,
                    )
                    return JSONResponse(
                        status_code=202,
                        content=_refresh_payload(
                            current,
                            refresh_result="REFRESH_IN_PROGRESS",
                            retry_after_seconds=retry_after,
                        ),
                    )
                if claimed.outcome is ClaimOrderOutcome.TERMINAL:
                    raise HTTPException(
                        status_code=409,
                        detail="PAYMENT_RECONCILIATION_REQUIRES_REVIEW",
                    )
                if claimed.outcome is ClaimOrderOutcome.NOT_ELIGIBLE:
                    return _current_refresh_response(
                        database_path,
                        order_id=order_id,
                        device_fingerprint_hash=proof.device_fingerprint_hash,
                    )
                if claimed.outcome is ClaimOrderOutcome.NOT_FOUND:
                    raise _refresh_unavailable()
                if claimed.claim is None:
                    raise _refresh_unavailable()

                result = reconciliation_service.reconcile_claim(
                    claimed.claim,
                    now=utc_now(),
                )
                current = _read_order_for_device(
                    database_path,
                    order_id=order_id,
                    device_fingerprint_hash=proof.device_fingerprint_hash,
                )
                return _reconciliation_response(current, result.outcome)
            except PaymentServiceError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
            except (PaymentReconciliationRepositoryError, sqlite3.Error) as exc:
                raise _refresh_unavailable() from exc

    if payment_provider == "mock":

        @router.post("/mock/orders/{order_id}/pay")
        def mock_pay_order(
            order_id: str,
            _request: MockPayRequest = Body(default=MockPayRequest()),
            x_mock_payment_token: str = Header(default=""),
        ):
            if not payment_mock_admin_token or not hmac.compare_digest(
                x_mock_payment_token,
                payment_mock_admin_token,
            ):
                raise HTTPException(status_code=403, detail="invalid_mock_payment_token")
            now = datetime.now(timezone.utc).replace(microsecond=0)
            evidence = PaymentEvidence(
                source=PaymentEvidenceSource.MOCK,
                out_trade_no=order_id,
                provider_transaction_id=f"mock_txn_{order_id}",
                trade_type="NATIVE",
                trade_state="SUCCESS",
                amount_fen=ANNUAL_V1.amount_fen,
                currency=ANNUAL_V1.currency,
                paid_at=now,
                appid=MOCK_APP_ID,
                mchid=MOCK_MCH_ID,
            )
            try:
                result = confirm_paid_order(
                    database_path,
                    evidence,
                    issued_by="mock",
                    now=now,
                )
            except PaymentServiceError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
            return {
                "order_id": result.order_id,
                "status": result.status,
                "license_id": str(result.license_id),
                "grant_id": str(result.grant_id),
                "expires_at": result.expires_at,
                "idempotent": result.idempotent,
            }

    return router


def _reconciliation_service(
    *,
    database_path: Path,
    payment_provider: str | None,
    gateway: PaymentGateway | None,
    expected_appid: str | None,
    expected_mchid: str | None,
) -> PaymentReconciliationService | None:
    if gateway is None:
        return None
    if payment_provider == "mock":
        appid, mchid = MOCK_APP_ID, MOCK_MCH_ID
    elif payment_provider == "wechat_native" and expected_appid and expected_mchid:
        appid, mchid = expected_appid, expected_mchid
    else:
        return None
    return PaymentReconciliationService(
        database_path=database_path,
        gateway=gateway,
        expected_appid=appid,
        expected_mchid=mchid,
        policy=_REFRESH_POLICY,
    )


async def _reject_explicit_json_null(request: Request) -> None:
    if (await request.body()).strip() == b"null":
        raise HTTPException(status_code=422, detail="INVALID_PAYMENT_REFRESH_REQUEST")


def _require_payment_provider(
    payment_provider: str | None,
    gateway: PaymentGateway | None,
) -> None:
    if payment_provider is None or gateway is None:
        raise HTTPException(status_code=503, detail="payment_provider_not_configured")


def _proof(
    database_path: Path,
    *,
    authorization: str,
    signing_identity: LicenseSigningIdentity,
):
    with connect(database_path) as connection:
        return verify_device_proof_token(
            connection,
            signed_license_token=bearer_token(authorization),
            signing_identity=signing_identity,
        )


def _read_order_for_device(
    database_path: Path,
    *,
    order_id: str,
    device_fingerprint_hash: str,
) -> PaymentOrderResult:
    with connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT * FROM payment_orders
            WHERE order_id = ? AND device_fingerprint_hash = ?
            """,
            (order_id, device_fingerprint_hash),
        ).fetchone()
    if row is None:
        raise PaymentServiceError("payment_order_not_found", status_code=404)
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


def _local_refresh_response(order: PaymentOrderResult):
    if order.status == "PAID":
        return _refresh_payload(
            order,
            refresh_result="ALREADY_PAID",
            license_refresh_required=True,
        )
    if order.status == "CLOSED":
        return _refresh_payload(order, refresh_result="ALREADY_CLOSED")
    if order.status == "ABNORMAL":
        raise HTTPException(status_code=409, detail="PAYMENT_ORDER_REQUIRES_REVIEW")
    if order.status == "CREATED":
        raise HTTPException(status_code=409, detail="PAYMENT_ORDER_PROCESSING")
    if order.status != "WAITING_PAYMENT":
        raise _refresh_unavailable()
    return None


def _current_refresh_response(
    database_path: Path,
    *,
    order_id: str,
    device_fingerprint_hash: str,
):
    current = _read_order_for_device(
        database_path,
        order_id=order_id,
        device_fingerprint_hash=device_fingerprint_hash,
    )
    immediate = _local_refresh_response(current)
    if immediate is not None:
        return immediate
    raise _refresh_unavailable()


def _reconciliation_response(
    order: PaymentOrderResult,
    outcome: ReconciliationOutcome,
):
    if outcome is ReconciliationOutcome.LOST_CLAIM:
        return JSONResponse(
            status_code=202,
            content=_refresh_payload(
                order,
                refresh_result="REFRESH_IN_PROGRESS",
                license_refresh_required=order.status == "PAID",
                retry_after_seconds=1,
            ),
        )
    if (
        outcome is ReconciliationOutcome.LOST_CLAIM_AFTER_PAYMENT
        and order.status != "PAID"
    ):
        return JSONResponse(
            status_code=202,
            content=_refresh_payload(
                order,
                refresh_result="REFRESH_IN_PROGRESS",
                retry_after_seconds=1,
            ),
        )
    if order.status == "PAID":
        return _refresh_payload(
            order,
            refresh_result=(
                "ALREADY_PAID"
                if outcome is ReconciliationOutcome.ALREADY_PAID
                else "PAID"
            ),
            license_refresh_required=True,
        )
    if order.status == "CLOSED":
        return _refresh_payload(
            order,
            refresh_result=(
                "ALREADY_CLOSED"
                if outcome is ReconciliationOutcome.ALREADY_CLOSED
                else "CLOSED"
            ),
        )
    if order.status == "ABNORMAL":
        raise HTTPException(status_code=409, detail="PAYMENT_ORDER_REQUIRES_REVIEW")
    if outcome is ReconciliationOutcome.RESCHEDULED and order.status == "WAITING_PAYMENT":
        return _refresh_payload(order, refresh_result="WAITING_PAYMENT")
    if outcome is ReconciliationOutcome.TERMINAL_ABNORMAL:
        raise HTTPException(
            status_code=409,
            detail="PAYMENT_RECONCILIATION_REQUIRES_REVIEW",
        )
    raise _refresh_unavailable()


def _refresh_payload(
    order: PaymentOrderResult,
    *,
    refresh_result: str,
    license_refresh_required: bool = False,
    retry_after_seconds: int | None = None,
) -> dict[str, object]:
    return {
        "order_id": order.order_id,
        "status": order.status,
        "amount_fen": order.amount_fen,
        "currency": order.currency,
        "expires_at": order.expires_at,
        "paid_at": order.paid_at,
        "license_refresh_required": license_refresh_required,
        "refresh_result": refresh_result,
        "retry_after_seconds": retry_after_seconds,
    }


def _retry_after(target: datetime | None, now: datetime) -> int:
    if target is None:
        return 1
    return max(1, math.ceil((target - now).total_seconds()))


def _refresh_unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="PAYMENT_REFRESH_UNAVAILABLE")


def _order_payload(result) -> dict[str, object]:
    return {
        "order_id": result.order_id,
        "product_code": result.product_code,
        "amount_fen": result.amount_fen,
        "currency": result.currency,
        "provider": result.provider,
        "status": result.status,
        "code_url": result.code_url,
        "created_at": result.created_at,
        "expires_at": result.expires_at,
        "paid_at": result.paid_at,
    }
