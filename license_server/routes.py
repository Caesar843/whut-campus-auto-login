from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, model_validator

from license_client.constants import PRODUCT_ID, TRIAL_DAYS
from license_server.db import connect
from license_server.license_service import (
    create_license,
    latest_license,
    paid_active_license_exists,
)
from license_server.payment import ANNUAL_V1, OrderStatus
from license_server.signer import datetime_text, sign_license_payload, utc_now_text


LEGACY_DEVICE_DESCRIPTION_FIELDS = {"device_name", "os", "app_version"}


class DeviceRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str
    device_fingerprint_hash: str

    @model_validator(mode="before")
    @classmethod
    def ignore_legacy_device_description_fields(cls, data: Any) -> Any:
        return _drop_legacy_device_description_fields(data)


class LicenseRefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str
    device_fingerprint_hash: str

    @model_validator(mode="before")
    @classmethod
    def ignore_legacy_device_description_fields(cls, data: Any) -> Any:
        return _drop_legacy_device_description_fields(data)


class PaymentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str
    device_fingerprint_hash: str
    payment_channel: str
    plan: str = "yearly"


def create_router(
    *,
    database_path: Path,
    private_key_b64: str,
    payment_amount: str,
    payment_currency: str,
    payment_channels: tuple[str, ...],
    payment_order_ttl_minutes: int,
) -> APIRouter:
    router = APIRouter()

    @router.post("/device/register")
    def register_device(request: DeviceRegisterRequest):
        _validate_product(request.product_id)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with connect(database_path) as connection:
            device = connection.execute(
                "SELECT * FROM devices WHERE device_fingerprint_hash = ?",
                (request.device_fingerprint_hash,),
            ).fetchone()
            if device is None:
                cursor = connection.execute(
                    """
                    INSERT INTO devices (
                        product_id, device_fingerprint_hash, first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        request.product_id,
                        request.device_fingerprint_hash,
                        datetime_text(now),
                        datetime_text(now),
                    ),
                )
                device_id = int(cursor.lastrowid)
                license_row = create_license(
                    connection,
                    device_id=device_id,
                    license_type="trial",
                    source="trial",
                    starts_at=now,
                    expires_at=now + timedelta(days=TRIAL_DAYS),
                )
            else:
                device_id = int(device["id"])
                connection.execute(
                    """
                    UPDATE devices
                    SET last_seen_at = ?
                    WHERE id = ?
                    """,
                    (
                        datetime_text(now),
                        device_id,
                    ),
                )
                license_row = latest_license(connection, device_id)
                if license_row is None:
                    license_row = create_license(
                        connection,
                        device_id=device_id,
                        license_type="trial",
                        source="trial",
                        starts_at=now,
                        expires_at=now + timedelta(days=TRIAL_DAYS),
                    )
            connection.commit()
        return _license_response(
            product_id=request.product_id,
            device_fingerprint_hash=request.device_fingerprint_hash,
            license_row=license_row,
            private_key_b64=private_key_b64,
        )

    @router.post("/license/refresh")
    def refresh_license(request: LicenseRefreshRequest):
        _validate_product(request.product_id)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with connect(database_path) as connection:
            device = connection.execute(
                "SELECT * FROM devices WHERE device_fingerprint_hash = ?",
                (request.device_fingerprint_hash,),
            ).fetchone()
            if device is None:
                raise HTTPException(status_code=404, detail="device_not_found")
            connection.execute(
                "UPDATE devices SET last_seen_at = ? WHERE id = ?",
                (datetime_text(now), int(device["id"])),
            )
            license_row = latest_license(connection, int(device["id"]))
            if license_row is None:
                raise HTTPException(status_code=404, detail="license_not_found")
            connection.commit()
        return _license_response(
            product_id=request.product_id,
            device_fingerprint_hash=request.device_fingerprint_hash,
            license_row=license_row,
            private_key_b64=private_key_b64,
        )

    @router.post("/payment/create")
    def create_payment_order(request: PaymentCreateRequest):
        _validate_product(request.product_id)
        _validate_not_blank(request.device_fingerprint_hash, "invalid_device_fingerprint_hash")
        if request.payment_channel not in payment_channels:
            raise HTTPException(status_code=400, detail="invalid_payment_channel")
        if request.plan != "yearly":
            raise HTTPException(status_code=400, detail="invalid_plan")

        now = datetime.now(timezone.utc).replace(microsecond=0)
        with connect(database_path) as connection:
            _expire_open_payment_orders(connection, now=now)
            if paid_active_license_exists(
                connection,
                device_fingerprint_hash=request.device_fingerprint_hash,
                now=now,
            ):
                raise HTTPException(status_code=409, detail="already_paid_active")
            order_row = _latest_open_payment_order(
                connection,
                product_id=request.product_id,
                device_fingerprint_hash=request.device_fingerprint_hash,
                now=now,
            )
            if order_row is None:
                order_row = _create_payment_order(
                    connection,
                    product_id=request.product_id,
                    device_fingerprint_hash=request.device_fingerprint_hash,
                    payment_channel=request.payment_channel,
                    amount=payment_amount,
                    currency=payment_currency,
                    now=now,
                    ttl_minutes=payment_order_ttl_minutes,
                )
            connection.commit()
        return _payment_create_response(order_row)

    @router.get("/payment/status")
    def payment_status(product_id: str, order_id: str, device_fingerprint_hash: str):
        _validate_product(product_id)
        _validate_not_blank(order_id, "invalid_order_id")
        _validate_not_blank(device_fingerprint_hash, "invalid_device_fingerprint_hash")

        now = datetime.now(timezone.utc).replace(microsecond=0)
        with connect(database_path) as connection:
            _expire_open_payment_orders(connection, now=now)
            order_row = connection.execute(
                "SELECT * FROM payment_orders WHERE order_id = ?",
                (order_id,),
            ).fetchone()
            if order_row is None:
                raise HTTPException(status_code=404, detail="order_not_found")
            if str(order_row["device_fingerprint_hash"]) != device_fingerprint_hash:
                raise HTTPException(status_code=403, detail="order_device_mismatch")
            connection.commit()
        return _payment_status_response(order_row)

    return router


def _validate_product(product_id: str) -> None:
    if product_id != PRODUCT_ID:
        raise HTTPException(status_code=400, detail="invalid_product_id")


def _drop_legacy_device_description_fields(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    # ponytail: old clients sent these; remove this shim after clients stop.
    return {
        key: value
        for key, value in data.items()
        if key not in LEGACY_DEVICE_DESCRIPTION_FIELDS
    }


def _validate_not_blank(value: str, detail: str) -> None:
    if not str(value or "").strip():
        raise HTTPException(status_code=400, detail=detail)


def _expire_open_payment_orders(connection, *, now: datetime) -> None:
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


def _latest_open_payment_order(
    connection,
    *,
    product_id: str,
    device_fingerprint_hash: str,
    now: datetime,
):
    return connection.execute(
        """
        SELECT * FROM payment_orders
        WHERE product_code = ?
          AND device_fingerprint_hash = ?
          AND open_slot = 'open'
          AND status IN ('CREATED', 'WAITING_PAYMENT', 'ABNORMAL')
          AND (status = 'ABNORMAL' OR expires_at > ?)
        ORDER BY id DESC
        LIMIT 1
        """,
        (ANNUAL_V1.product_code, device_fingerprint_hash, datetime_text(now)),
    ).fetchone()


def _create_payment_order(
    connection,
    *,
    product_id: str,
    device_fingerprint_hash: str,
    payment_channel: str,
    amount: str,
    currency: str,
    now: datetime,
    ttl_minutes: int,
):
    order_id = f"pay_{uuid4().hex}"
    now_text = datetime_text(now)
    expire_at = datetime_text(now + timedelta(minutes=ttl_minutes))
    cursor = connection.execute(
        """
        INSERT INTO payment_orders (
            order_id, device_fingerprint_hash, product_code, amount_fen,
            currency, provider, status, open_slot, provider_order_id,
            provider_transaction_id, provider_trade_state, created_at,
            updated_at, expires_at, paid_at, closed_at, security_error_code
        ) VALUES (?, ?, ?, ?, ?, ?, 'CREATED', 'open', NULL, NULL,
                  'not_configured', ?, ?, ?, NULL, NULL, NULL)
        """,
        (
            order_id,
            device_fingerprint_hash,
            ANNUAL_V1.product_code,
            ANNUAL_V1.amount_fen,
            ANNUAL_V1.currency,
            payment_channel,
            now_text,
            now_text,
            expire_at,
        ),
    )
    return connection.execute(
        "SELECT * FROM payment_orders WHERE id = ?",
        (int(cursor.lastrowid),),
    ).fetchone()


def _payment_create_response(order_row) -> dict[str, object]:
    return {
        "order_id": str(order_row["order_id"]),
        "amount": _amount_text(int(order_row["amount_fen"])),
        "currency": str(order_row["currency"]),
        "payment_channel": str(order_row["provider"]),
        "order_status": _legacy_order_status(order_row),
        "payment_status": _legacy_payment_status(order_row),
        "provider_status": str(order_row["provider_trade_state"] or "not_configured"),
        "expire_at": str(order_row["expires_at"]),
        "payment_url": None,
        "qr_code_url": None,
        "message": "order_created_payment_provider_not_configured",
    }


def _payment_status_response(order_row) -> dict[str, object]:
    order_status = _legacy_order_status(order_row)
    message = "order_expired" if order_status == "expired" else "order_waiting_for_payment_provider"
    return {
        "order_id": str(order_row["order_id"]),
        "order_status": order_status,
        "payment_status": _legacy_payment_status(order_row),
        "provider_status": str(order_row["provider_trade_state"] or "not_configured"),
        "amount": _amount_text(int(order_row["amount_fen"])),
        "currency": str(order_row["currency"]),
        "payment_channel": str(order_row["provider"]),
        "expire_at": str(order_row["expires_at"]),
        "paid_at": order_row["paid_at"],
        "message": message,
    }


def _legacy_order_status(order_row) -> str:
    status = str(order_row["status"])
    if status == OrderStatus.CLOSED.value and order_row["security_error_code"] == "expired":
        return "expired"
    if status == OrderStatus.WAITING_PAYMENT.value:
        return "pending_payment"
    return status.lower()


def _legacy_payment_status(order_row) -> str:
    return "paid" if str(order_row["status"]) == OrderStatus.PAID.value else "unpaid"


def _amount_text(amount_fen: int) -> str:
    whole, cents = divmod(amount_fen, 100)
    return f"{whole}.{cents:02d}".rstrip("0").rstrip(".")


def _license_response(*, product_id: str, device_fingerprint_hash: str, license_row, private_key_b64: str):
    expires_at = str(license_row["expires_at"])
    payload = {
        "product_id": product_id,
        "device_fingerprint_hash": device_fingerprint_hash,
        "license_id": str(license_row["id"]),
        "license_type": str(license_row["license_type"]),
        "license_status": str(license_row["status"]),
        "issued_at": utc_now_text(),
        "expires_at": expires_at,
        "features": ["auto_login"],
    }
    signed_license_token = sign_license_payload(payload, private_key_b64=private_key_b64)
    return {
        "status": _response_status(str(license_row["license_type"]), str(license_row["status"]), expires_at),
        "product_id": product_id,
        "device_fingerprint_hash": device_fingerprint_hash,
        "license_id": str(license_row["id"]),
        "license_type": str(license_row["license_type"]),
        "license_status": str(license_row["status"]),
        "issued_at": payload["issued_at"],
        "expires_at": expires_at,
        "signed_license_token": signed_license_token,
    }


def _response_status(license_type: str, status: str, expires_at: str) -> str:
    if status == "revoked":
        return "revoked"
    parsed_expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if parsed_expires <= datetime.now(timezone.utc):
        return "paid_expired" if license_type == "paid" else "trial_expired"
    return "paid_active" if license_type == "paid" else "trial_active"
