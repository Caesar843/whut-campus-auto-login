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


def _noncanonical_pad_bits_b64(value: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert value.endswith("=")
    pad_bits_index = len(value) - 2
    canonical_index = alphabet.index(value[pad_bits_index])
    noncanonical_index = canonical_index | 0b01
    assert noncanonical_index != canonical_index
    return value[:pad_bits_index] + alphabet[noncanonical_index] + value[pad_bits_index + 1 :]


def test_loaders_and_derivation_share_raw_key_format():
    private_b64, public_b64, public_raw = _keypair_b64()
    private_key = load_private_key_b64(private_b64)
    public_key = load_public_key_b64(public_b64)
    assert derive_public_key_raw_bytes(private_key) == public_raw
    assert public_key_raw_bytes(public_key) == public_raw


def test_private_key_loader_accepts_canonical_base64():
    private_b64, _public_b64, _public_raw = _keypair_b64()

    assert derive_public_key_raw_bytes(load_private_key_b64(private_b64))


def test_public_key_loader_accepts_canonical_base64():
    _private_b64, public_b64, public_raw = _keypair_b64()

    assert public_key_raw_bytes(load_public_key_b64(public_b64)) == public_raw


def test_private_key_loader_rejects_noncanonical_pad_bits_without_echo():
    private_b64, _public_b64, _public_raw = _keypair_b64()
    noncanonical = _noncanonical_pad_bits_b64(private_b64)
    assert noncanonical != private_b64
    assert base64.b64decode(noncanonical, validate=True) == base64.b64decode(
        private_b64,
        validate=True,
    )

    with pytest.raises(Ed25519KeyFormatError) as exc_info:
        load_private_key_b64(noncanonical)

    assert noncanonical not in str(exc_info.value)
    assert noncanonical not in repr(exc_info.value)


def test_public_key_loader_rejects_noncanonical_pad_bits_without_echo():
    _private_b64, public_b64, _public_raw = _keypair_b64()
    noncanonical = _noncanonical_pad_bits_b64(public_b64)
    assert noncanonical != public_b64
    assert base64.b64decode(noncanonical, validate=True) == base64.b64decode(
        public_b64,
        validate=True,
    )

    with pytest.raises(Ed25519KeyFormatError) as exc_info:
        load_public_key_b64(noncanonical)

    assert noncanonical not in str(exc_info.value)
    assert noncanonical not in repr(exc_info.value)


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
