from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from license_client.constants import PAID_LICENSE_DAYS, PRODUCT_ID, TRIAL_DAYS
from license_server.db import connect
from license_server.signer import datetime_text, sign_license_payload, utc_now_text


class DeviceRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    product_id: str
    device_fingerprint_hash: str
    device_name: Optional[str] = None
    os: Optional[str] = None
    app_version: Optional[str] = None


class LicenseRefreshRequest(BaseModel):
    product_id: str
    device_fingerprint_hash: str
    app_version: Optional[str] = None


class AdminGrantRequest(BaseModel):
    device_fingerprint_hash: str
    license_days: int = Field(default=PAID_LICENSE_DAYS, ge=1, le=3660)
    reason: str


def create_router(*, database_path: Path, private_key_b64: str, admin_token: str) -> APIRouter:
    router = APIRouter()

    @router.get("/health")
    def health():
        return {"status": "ok"}

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
                        product_id, device_fingerprint_hash, device_name, os, app_version,
                        first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.product_id,
                        request.device_fingerprint_hash,
                        request.device_name,
                        request.os,
                        request.app_version,
                        datetime_text(now),
                        datetime_text(now),
                    ),
                )
                device_id = int(cursor.lastrowid)
                license_row = _create_license(
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
                    SET last_seen_at = ?, app_version = ?, device_name = ?, os = ?
                    WHERE id = ?
                    """,
                    (
                        datetime_text(now),
                        request.app_version,
                        request.device_name,
                        request.os,
                        device_id,
                    ),
                )
                license_row = _latest_license(connection, device_id)
                if license_row is None:
                    license_row = _create_license(
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
                "UPDATE devices SET last_seen_at = ?, app_version = COALESCE(?, app_version) WHERE id = ?",
                (datetime_text(now), request.app_version, int(device["id"])),
            )
            license_row = _latest_license(connection, int(device["id"]))
            if license_row is None:
                raise HTTPException(status_code=404, detail="license_not_found")
            connection.commit()
        return _license_response(
            product_id=request.product_id,
            device_fingerprint_hash=request.device_fingerprint_hash,
            license_row=license_row,
            private_key_b64=private_key_b64,
        )

    @router.post("/admin/grant")
    def admin_grant(
        request: AdminGrantRequest,
        x_license_admin_token: str = Header(default=""),
    ):
        if x_license_admin_token != admin_token:
            raise HTTPException(status_code=403, detail="invalid_admin_token")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with connect(database_path) as connection:
            device = connection.execute(
                "SELECT * FROM devices WHERE device_fingerprint_hash = ?",
                (request.device_fingerprint_hash,),
            ).fetchone()
            if device is None:
                raise HTTPException(status_code=404, detail="device_not_found")
            license_row = _create_license(
                connection,
                device_id=int(device["id"]),
                license_type="paid",
                source="admin",
                starts_at=now,
                expires_at=now + timedelta(days=request.license_days),
            )
            connection.commit()
        return _license_response(
            product_id=PRODUCT_ID,
            device_fingerprint_hash=request.device_fingerprint_hash,
            license_row=license_row,
            private_key_b64=private_key_b64,
        )

    return router


def _validate_product(product_id: str) -> None:
    if product_id != PRODUCT_ID:
        raise HTTPException(status_code=400, detail="invalid_product_id")


def _create_license(connection, *, device_id: int, license_type: str, source: str, starts_at: datetime, expires_at: datetime):
    cursor = connection.execute(
        """
        INSERT INTO licenses (
            device_id, license_type, status, starts_at, expires_at, source, order_id,
            created_at, revoked_at, revoked_reason
        ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL)
        """,
        (
            device_id,
            license_type,
            "active",
            datetime_text(starts_at),
            datetime_text(expires_at),
            source,
            datetime_text(starts_at),
        ),
    )
    return connection.execute(
        "SELECT * FROM licenses WHERE id = ?",
        (int(cursor.lastrowid),),
    ).fetchone()


def _latest_license(connection, device_id: int):
    paid = connection.execute(
        """
        SELECT * FROM licenses
        WHERE device_id = ? AND license_type = 'paid'
        ORDER BY id DESC LIMIT 1
        """,
        (device_id,),
    ).fetchone()
    if paid is not None:
        return paid
    return connection.execute(
        """
        SELECT * FROM licenses
        WHERE device_id = ?
        ORDER BY id DESC LIMIT 1
        """,
        (device_id,),
    ).fetchone()


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
