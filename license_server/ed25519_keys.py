from __future__ import annotations

import base64
import binascii
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class Ed25519KeyFormatError(ValueError):
    pass


def _decode_canonical_key_b64(value: str, *, source: str, key_type: str) -> bytes:
    try:
        text = str(value or "")
        text.encode("ascii")
        raw = base64.b64decode(text, validate=True)
        if base64.b64encode(raw).decode("ascii") != text:
            raise ValueError("non-canonical base64")
        return raw
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise Ed25519KeyFormatError(
            f"{source} must be a base64-encoded 32-byte Ed25519 {key_type} key."
        ) from exc


def load_private_key_b64(
    value: str,
    *,
    source: str = "LICENSE_PRIVATE_KEY",
) -> Ed25519PrivateKey:
    try:
        raw = validate_private_key_b64_text(value, source=source)
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise Ed25519KeyFormatError(
            f"{source} must be a base64-encoded 32-byte Ed25519 private key."
        ) from exc


def validate_private_key_b64_text(
    value: str,
    *,
    source: str = "LICENSE_PRIVATE_KEY",
) -> bytes:
    raw = _decode_canonical_key_b64(
        value,
        source=source,
        key_type="private",
    )
    if len(raw) != 32:
        raise Ed25519KeyFormatError(
            f"{source} must be a base64-encoded 32-byte Ed25519 private key."
        )
    return raw


def load_public_key_b64(
    value: str,
    *,
    source: str = "LICENSE_PUBLIC_KEY",
) -> Ed25519PublicKey:
    try:
        raw = _decode_canonical_key_b64(
            value,
            source=source,
            key_type="public",
        )
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise Ed25519KeyFormatError(
            f"{source} must be a base64-encoded 32-byte Ed25519 public key."
        ) from exc


def public_key_raw_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_public_key_raw_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return public_key_raw_bytes(private_key.public_key())


def public_key_sha256(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes.")
    return hashlib.sha256(raw_public_key).hexdigest()
