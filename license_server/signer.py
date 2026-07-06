from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sign_license_payload(payload: Mapping[str, Any], *, private_key_b64: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    payload_json = json.dumps(
        dict(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload_segment = _b64url(payload_json)
    signature_segment = _b64url(private_key.sign(payload_segment.encode("ascii")))
    return f"{payload_segment}.{signature_segment}"


def verify_license_token_payload(
    signed_license_token: str,
    *,
    private_key_b64: str,
) -> dict[str, Any]:
    try:
        payload_segment, signature_segment = signed_license_token.split(".", 1)
        signature = _b64url_decode(signature_segment)
        private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
        private_key.public_key().verify(signature, payload_segment.encode("ascii"))
        payload = json.loads(_b64url_decode(payload_segment).decode("utf-8"))
    except (
        ValueError,
        InvalidSignature,
        binascii.Error,
        json.JSONDecodeError,
        UnicodeEncodeError,
        UnicodeDecodeError,
    ) as exc:
        raise ValueError("invalid_signed_license_token") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid_signed_license_token")
    return payload


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def datetime_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
