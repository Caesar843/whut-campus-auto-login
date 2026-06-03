from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from license_client.constants import PRODUCT_ID


@dataclass(frozen=True)
class LicenseTokenVerification:
    valid: bool
    payload: Optional[dict[str, Any]] = None
    error: Optional[str] = None


def verify_signed_license_token(
    signed_license_token: str,
    *,
    public_key_b64: str,
    current_device_fingerprint_hash: str,
    expected_product_id: str = PRODUCT_ID,
    now: Optional[datetime] = None,
) -> LicenseTokenVerification:
    try:
        payload_segment, signature_segment = signed_license_token.split(".", 1)
    except ValueError:
        return LicenseTokenVerification(False, error="invalid_format")

    try:
        signature = _b64url_decode(signature_segment)
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        public_key.verify(signature, payload_segment.encode("ascii"))
    except (ValueError, InvalidSignature, base64.binascii.Error):
        return LicenseTokenVerification(False, error="signature_invalid")

    try:
        payload = json.loads(_b64url_decode(payload_segment).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return LicenseTokenVerification(False, error="invalid_payload")
    if not isinstance(payload, dict):
        return LicenseTokenVerification(False, error="invalid_payload")

    error = _payload_error(
        payload,
        current_device_fingerprint_hash=current_device_fingerprint_hash,
        expected_product_id=expected_product_id,
        now=now,
    )
    if error:
        return LicenseTokenVerification(False, payload=payload, error=error)
    return LicenseTokenVerification(True, payload=payload)


def _payload_error(
    payload: Mapping[str, Any],
    *,
    current_device_fingerprint_hash: str,
    expected_product_id: str,
    now: Optional[datetime],
) -> Optional[str]:
    required = {
        "product_id",
        "device_fingerprint_hash",
        "license_id",
        "license_type",
        "license_status",
        "issued_at",
        "expires_at",
        "features",
    }
    if any(key not in payload for key in required):
        return "missing_claim"
    if payload.get("product_id") != expected_product_id:
        return "product_mismatch"
    if payload.get("device_fingerprint_hash") != current_device_fingerprint_hash:
        return "device_mismatch"
    if payload.get("license_status") == "revoked":
        return "revoked"
    expires_at = parse_utc_datetime(str(payload.get("expires_at") or ""))
    if expires_at is None:
        return "invalid_expires_at"
    current_time = now or datetime.now(timezone.utc)
    if expires_at <= current_time:
        return "expired"
    return None


def parse_utc_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
