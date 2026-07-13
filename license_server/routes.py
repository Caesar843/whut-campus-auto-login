from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, model_validator

from license_client.constants import PRODUCT_ID, TRIAL_DAYS
from license_server.db import connect
from license_server.license_service import (
    create_license,
    latest_license,
)
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
