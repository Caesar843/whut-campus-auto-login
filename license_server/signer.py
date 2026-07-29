from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature

from license_server.ed25519_keys import (
    derive_public_key_raw_bytes,
    load_private_key_b64,
    public_key_sha256,
)


RUNTIME_ATTESTATION_SIGNING_DOMAIN = (
    b"whut-campus-auto-login:runtime-attestation:v1\x00"
)


class LicenseSigningIdentity:
    __slots__ = ("__private_key", "__public_key_sha256")

    def __init__(
        self,
        private_key_b64: str,
        *,
        source: str = "private_key_b64",
    ) -> None:
        private_key = load_private_key_b64(private_key_b64, source=source)
        self.__private_key = private_key
        self.__public_key_sha256 = public_key_sha256(
            derive_public_key_raw_bytes(private_key)
        )

    @property
    def public_key_sha256(self) -> str:
        return self.__public_key_sha256

    def sign_license_payload(self, payload: Mapping[str, Any]) -> str:
        payload_json = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        payload_segment = _b64url(payload_json)
        signature_segment = _b64url(
            self.__private_key.sign(payload_segment.encode("ascii"))
        )
        return f"{payload_segment}.{signature_segment}"

    def verify_license_token_payload(
        self,
        signed_license_token: str,
    ) -> dict[str, Any]:
        try:
            payload_segment, signature_segment = signed_license_token.split(".", 1)
            signature = _b64url_decode(signature_segment)
            self.__private_key.public_key().verify(
                signature,
                payload_segment.encode("ascii"),
            )
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

    def sign_runtime_attestation(self, canonical_payload_json: bytes) -> bytes:
        return self.__private_key.sign(
            RUNTIME_ATTESTATION_SIGNING_DOMAIN + canonical_payload_json
        )

    def __repr__(self) -> str:
        return (
            "LicenseSigningIdentity("
            f"public_key_sha256={self.public_key_sha256!r})"
        )


def sign_license_payload(
    payload: Mapping[str, Any],
    *,
    identity: LicenseSigningIdentity,
) -> str:
    return identity.sign_license_payload(payload)


def verify_license_token_payload(
    signed_license_token: str,
    *,
    identity: LicenseSigningIdentity,
) -> dict[str, Any]:
    return identity.verify_license_token_payload(signed_license_token)


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def datetime_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
