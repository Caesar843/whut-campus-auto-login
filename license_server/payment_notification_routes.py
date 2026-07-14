from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.requests import ClientDisconnect

from license_server.payment_notification_repository import (
    IncomingPaymentNotification,
    InsertOutcome,
    PaymentNotificationRepositoryError,
    insert_received_notification,
)
from license_server.wechat_payment import (
    WeChatNativePaymentGateway,
    WechatPaymentError,
)


MAX_NOTIFICATION_BODY_BYTES = 65536
_LOGGER = logging.getLogger(__name__)
_REQUIRED_HEADERS = (
    "Wechatpay-Serial",
    "Wechatpay-Signature",
    "Wechatpay-Timestamp",
    "Wechatpay-Nonce",
)
_VERIFY_ERRORS = {
    "PAYMENT_NOTIFY_SIGNATURE_INVALID": (401, "PAYMENT_NOTIFY_SIGN_INVALID"),
    "PAYMENT_NOTIFY_TIMESTAMP_INVALID": (401, "PAYMENT_NOTIFY_TIMESTAMP_INVALID"),
    "PAYMENT_NOTIFY_DECRYPT_FAILED": (400, "PAYMENT_NOTIFY_DECRYPT_FAILED"),
    "PAYMENT_NOTIFY_PAYLOAD_INVALID": (400, "PAYMENT_NOTIFY_SCHEMA_INVALID"),
}


def create_payment_notification_router(
    *,
    database_path: Path,
    gateway: WeChatNativePaymentGateway,
    expected_appid: str,
    expected_mchid: str,
    signature_key_id: str,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/payment/wechat")

    @router.post("/notify", status_code=204, response_class=Response)
    async def receive_notification(request: Request) -> Response:
        body = await _limited_body(request)
        notification_headers = _unique_notification_headers(request)
        received_at = datetime.now(timezone.utc)
        try:
            verified = gateway.parse_and_verify_notification(
                notification_headers,
                body,
                now=received_at,
            )
        except WechatPaymentError as exc:
            status_code, detail = _VERIFY_ERRORS.get(
                exc.code,
                (400, "PAYMENT_NOTIFY_SCHEMA_INVALID"),
            )
            raise HTTPException(status_code=status_code, detail=detail) from exc
        if verified.appid != expected_appid or verified.mchid != expected_mchid:
            raise HTTPException(
                status_code=400,
                detail="PAYMENT_NOTIFY_MERCHANT_MISMATCH",
            )
        notification = IncomingPaymentNotification(
            provider_notification_id=verified.notification_id,
            provider="wechat_native",
            out_trade_no=verified.out_trade_no,
            provider_transaction_id=verified.transaction_id,
            event_type=verified.event_type,
            signature_key_id=signature_key_id,
            payload_digest_sha256=hashlib.sha256(body).hexdigest(),
            reported_appid=verified.appid,
            reported_mchid=verified.mchid,
            reported_trade_type=verified.trade_type,
            reported_trade_state=verified.trade_state,
            reported_amount_fen=verified.amount_total,
            reported_currency=verified.currency,
            reported_success_at=verified.success_time,
            provider_created_at=verified.provider_created_time,
            received_at=received_at,
        )
        try:
            result = insert_received_notification(database_path, notification)
        except PaymentNotificationRepositoryError as exc:
            raise HTTPException(
                status_code=500,
                detail="PAYMENT_NOTIFICATION_PERSIST_FAILED",
            ) from exc
        if result.outcome is InsertOutcome.DUPLICATE_DIGEST_CONFLICT:
            _LOGGER.warning("payment_notification_digest_conflict")
        return Response(status_code=204)

    return router


async def _limited_body(request: Request) -> bytes:
    _validate_content_length(request)
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_NOTIFICATION_BODY_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="PAYMENT_NOTIFY_BODY_TOO_LARGE",
                )
            chunks.append(chunk)
    except ClientDisconnect as exc:
        raise HTTPException(
            status_code=400,
            detail="PAYMENT_NOTIFY_SCHEMA_INVALID",
        ) from exc
    return b"".join(chunks)


def _unique_notification_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name in _REQUIRED_HEADERS:
        values = request.headers.getlist(name)
        if len(values) != 1:
            raise HTTPException(
                status_code=401,
                detail="PAYMENT_NOTIFY_HEADERS_INVALID",
            )
        value = values[0].strip(" \t")
        if not value:
            raise HTTPException(
                status_code=401,
                detail="PAYMENT_NOTIFY_HEADERS_INVALID",
            )
        headers[name] = value
    return headers


def _validate_content_length(request: Request) -> None:
    values = request.headers.getlist("content-length")
    if len(values) > 1:
        raise HTTPException(
            status_code=400,
            detail="PAYMENT_NOTIFY_SCHEMA_INVALID",
        )
    if not values:
        return
    declared = values[0].strip(" \t")
    if (
        not declared
        or not declared.isascii()
        or any(character < "0" or character > "9" for character in declared)
    ):
        raise HTTPException(
            status_code=400,
            detail="PAYMENT_NOTIFY_SCHEMA_INVALID",
        )
    normalized = declared.lstrip("0") or "0"
    maximum = str(MAX_NOTIFICATION_BODY_BYTES)
    if len(normalized) > len(maximum) or (
        len(normalized) == len(maximum) and normalized > maximum
    ):
        raise HTTPException(
            status_code=413,
            detail="PAYMENT_NOTIFY_BODY_TOO_LARGE",
        )
