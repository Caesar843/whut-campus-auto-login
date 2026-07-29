from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException

from license_client.constants import PRODUCT_ID
from license_server.signer import (
    LicenseSigningIdentity,
    verify_license_token_payload,
)


@dataclass(frozen=True)
class DeviceProof:
    device_fingerprint_hash: str
    license_id: int


REQUIRED_CLAIMS = {
    "product_id",
    "device_fingerprint_hash",
    "license_id",
    "license_type",
    "license_status",
    "issued_at",
    "expires_at",
    "features",
}


def bearer_token(authorization: str) -> str:
    scheme, _, token = str(authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="invalid_device_proof")
    return token.strip()


def verify_device_proof_token(
    connection,
    *,
    signed_license_token: str,
    signing_identity: LicenseSigningIdentity,
    expected_product_id: str = PRODUCT_ID,
) -> DeviceProof:
    try:
        payload = verify_license_token_payload(
            signed_license_token,
            identity=signing_identity,
        )
        _validate_payload_shape(payload)
        device_hash = _required_claim(payload, "device_fingerprint_hash")
        license_id = int(_required_claim(payload, "license_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="invalid_device_proof") from None

    if payload.get("product_id") != expected_product_id:
        raise HTTPException(status_code=401, detail="invalid_device_proof")
    if payload.get("license_status") == "revoked":
        raise HTTPException(status_code=403, detail="device_proof_revoked")

    row = connection.execute(
        """
        SELECT licenses.id AS license_id,
               licenses.license_type AS license_type,
               licenses.status AS license_status,
               devices.device_fingerprint_hash AS device_fingerprint_hash
        FROM licenses
        JOIN devices ON devices.id = licenses.device_id
        WHERE licenses.id = ?
        """,
        (license_id,),
    ).fetchone()
    if row is None or str(row["device_fingerprint_hash"]) != device_hash:
        raise HTTPException(status_code=401, detail="invalid_device_proof")
    if str(row["license_type"]) != payload.get("license_type"):
        raise HTTPException(status_code=401, detail="invalid_device_proof")
    if str(row["license_status"]) == "revoked":
        raise HTTPException(status_code=403, detail="device_proof_revoked")
    return DeviceProof(device_fingerprint_hash=device_hash, license_id=license_id)


def _validate_payload_shape(payload: Mapping[str, Any]) -> None:
    if any(key not in payload for key in REQUIRED_CLAIMS):
        raise ValueError("missing_claim")
    if payload.get("license_type") not in {"trial", "paid"}:
        raise ValueError("invalid_license_type")
    if payload.get("license_status") not in {"active", "revoked"}:
        raise ValueError("invalid_license_status")
    if not isinstance(payload.get("features"), list):
        raise ValueError("invalid_features")
    _parse_time(_required_claim(payload, "issued_at"))
    _parse_time(_required_claim(payload, "expires_at"))


def _required_claim(payload: Mapping[str, Any], key: str) -> str:
    raw_value = payload.get(key)
    value = "" if raw_value is None else str(raw_value).strip()
    if not value:
        raise ValueError(key)
    return value


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
