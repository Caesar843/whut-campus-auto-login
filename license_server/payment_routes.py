from __future__ import annotations

import hmac
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Body, Header, HTTPException
from pydantic import BaseModel, ConfigDict

from license_server.db import connect
from license_server.device_proof import bearer_token, verify_device_proof_token
from license_server.payment import ANNUAL_V1, PaymentEvidence, PaymentEvidenceSource
from license_server.payment_gateway import MOCK_APP_ID, MOCK_MCH_ID, PaymentGateway
from license_server.payment_service import (
    PaymentServiceError,
    confirm_paid_order,
    create_or_restore_order,
    get_order_for_device,
)
from license_server.signer import datetime_text


class PaymentOrderCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_code: str


class MockPayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


def create_payment_router(
    *,
    database_path: Path,
    private_key_b64: str,
    payment_provider: str | None,
    payment_mock_admin_token: str | None,
    gateway: PaymentGateway | None,
    notify_url: str | None,
    expected_appid: str | None,
    expected_mchid: str | None,
    payment_order_ttl_minutes: int,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/payment")

    @router.post("/orders")
    def create_order(
        request: PaymentOrderCreateRequest,
        authorization: str = Header(default=""),
    ):
        _require_payment_provider(payment_provider, gateway)
        proof = _proof(
            database_path,
            authorization=authorization,
            private_key_b64=private_key_b64,
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
            private_key_b64=private_key_b64,
        )
        try:
            result = get_order_for_device(
                database_path,
                order_id=order_id,
                device_fingerprint_hash=proof.device_fingerprint_hash,
            )
        except PaymentServiceError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        return _order_payload(result)

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


def _require_payment_provider(
    payment_provider: str | None,
    gateway: PaymentGateway | None,
) -> None:
    if payment_provider is None or gateway is None:
        raise HTTPException(status_code=503, detail="payment_provider_not_configured")


def _proof(database_path: Path, *, authorization: str, private_key_b64: str):
    with connect(database_path) as connection:
        return verify_device_proof_token(
            connection,
            signed_license_token=bearer_token(authorization),
            private_key_b64=private_key_b64,
        )


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
