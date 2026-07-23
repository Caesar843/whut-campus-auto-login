import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from license_server.ed25519_keys import (
    Ed25519KeyFormatError,
    derive_public_key_raw_bytes,
    load_private_key_b64,
    load_public_key_b64,
    public_key_raw_bytes,
    public_key_sha256,
)


def _keypair_b64() -> tuple[str, str, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
        public_raw,
    )


def test_loaders_and_derivation_share_raw_key_format():
    private_b64, public_b64, public_raw = _keypair_b64()
    private_key = load_private_key_b64(private_b64)
    public_key = load_public_key_b64(public_b64)
    assert derive_public_key_raw_bytes(private_key) == public_raw
    assert public_key_raw_bytes(public_key) == public_raw


def test_public_key_fingerprint_hashes_raw_bytes_not_base64_text():
    _private_b64, public_b64, public_raw = _keypair_b64()
    assert public_key_sha256(public_raw) == hashlib.sha256(public_raw).hexdigest()
    assert public_key_sha256(public_raw) != hashlib.sha256(
        public_b64.encode("ascii")
    ).hexdigest()


@pytest.mark.parametrize(
    "value",
    ["not-base64", base64.b64encode(b"short").decode("ascii")],
)
def test_private_key_loader_rejects_invalid_values_without_echo(value):
    with pytest.raises(Ed25519KeyFormatError) as exc_info:
        load_private_key_b64(value, source="LICENSE_PRIVATE_KEY")
    message = str(exc_info.value)
    assert "base64-encoded 32-byte Ed25519 private key" in message
    assert value not in message


@pytest.mark.parametrize(
    "value",
    ["not-base64", base64.b64encode(b"short").decode("ascii")],
)
def test_public_key_loader_rejects_invalid_values_without_echo(value):
    with pytest.raises(Ed25519KeyFormatError) as exc_info:
        load_public_key_b64(value, source="LICENSE_PUBLIC_KEY")
    message = str(exc_info.value)
    assert "base64-encoded 32-byte Ed25519 public key" in message
    assert value not in message
