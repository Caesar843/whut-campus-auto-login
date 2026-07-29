import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import license_server.signer as signer
import license_server.config as server_config
from license_server.app import create_app


PRIVATE_KEY_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
PAYLOAD = {
    "product_id": "whut-campus-auto-login",
    "device_fingerprint_hash": "device-a",
    "license_id": "1",
    "license_type": "trial",
    "license_status": "active",
    "issued_at": "2026-07-26T00:00:00Z",
    "expires_at": "2026-08-09T00:00:00Z",
    "features": ["auto_login"],
}
EXPECTED_TOKEN = (
    "eyJkZXZpY2VfZmluZ2VycHJpbnRfaGFzaCI6ImRldmljZS1hIiwiZXhwaXJlc19hdCI6"
    "IjIwMjYtMDgtMDlUMDA6MDA6MDBaIiwiZmVhdHVyZXMiOlsiYXV0b19sb2dpbiJdLCJp"
    "c3N1ZWRfYXQiOiIyMDI2LTA3LTI2VDAwOjAwOjAwWiIsImxpY2Vuc2VfaWQiOiIxIiwi"
    "bGljZW5zZV9zdGF0dXMiOiJhY3RpdmUiLCJsaWNlbnNlX3R5cGUiOiJ0cmlhbCIsInBy"
    "b2R1Y3RfaWQiOiJ3aHV0LWNhbXB1cy1hdXRvLWxvZ2luIn0."
    "u17i8UHaVEwU2smH1rbWPSSQYJRW7VN2Iegb5lMS1m2GGjtmexkcrHqpxHJx6n4ZE3NI"
    "eT_7v6xxGQVkJTQ2Bg"
)


def test_identity_loads_private_key_once_and_preserves_token_wire_format(monkeypatch):
    calls = 0
    original = signer.load_private_key_b64

    def counting_loader(value, *, source="LICENSE_PRIVATE_KEY"):
        nonlocal calls
        calls += 1
        return original(value, source=source)

    monkeypatch.setattr(signer, "load_private_key_b64", counting_loader)

    identity = signer.LicenseSigningIdentity(PRIVATE_KEY_B64)
    first = identity.sign_license_payload(PAYLOAD)
    second = identity.sign_license_payload(PAYLOAD)

    assert first == EXPECTED_TOKEN
    assert second == EXPECTED_TOKEN
    assert identity.verify_license_token_payload(first) == PAYLOAD
    assert calls == 1


def test_identity_repr_and_errors_do_not_expose_key_material():
    identity = signer.LicenseSigningIdentity(PRIVATE_KEY_B64)
    public_key_b64 = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(PRIVATE_KEY_B64)
        ).public_key().public_bytes_raw()
    ).decode("ascii")

    text = repr(identity)

    assert PRIVATE_KEY_B64 not in text
    assert public_key_b64 not in text

    try:
        identity.verify_license_token_payload("invalid")
    except ValueError as exc:
        assert str(exc) == "invalid_signed_license_token"
        assert PRIVATE_KEY_B64 not in str(exc)
    else:
        raise AssertionError("invalid token must be rejected")


def test_runtime_attestation_signature_uses_an_independent_domain():
    identity = signer.LicenseSigningIdentity(PRIVATE_KEY_B64)
    payload = b'{"protocol":"whut-license-runtime-attestation-v1"}'
    signature = identity.sign_runtime_attestation(payload)
    public_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(PRIVATE_KEY_B64)
    ).public_key()

    public_key.verify(
        signature,
        signer.RUNTIME_ATTESTATION_SIGNING_DOMAIN + payload,
    )


def test_application_constructs_the_only_private_key_object_at_startup(
    tmp_path,
    monkeypatch,
):
    config_validations = 0
    identity_loads = 0
    original_config_validator = server_config.validate_private_key_b64_text
    original_identity_loader = signer.load_private_key_b64

    def config_validator(value, *, source="LICENSE_PRIVATE_KEY"):
        nonlocal config_validations
        config_validations += 1
        return original_config_validator(value, source=source)

    def identity_loader(value, *, source="LICENSE_PRIVATE_KEY"):
        nonlocal identity_loads
        identity_loads += 1
        return original_identity_loader(value, source=source)

    monkeypatch.setattr(
        server_config,
        "validate_private_key_b64_text",
        config_validator,
    )
    monkeypatch.setattr(signer, "load_private_key_b64", identity_loader)
    monkeypatch.setenv("LICENSE_SERVER_ENV", "test")
    monkeypatch.setenv(
        "DATABASE_URL",
        "sqlite:///" + (tmp_path / "license.sqlite3").as_posix(),
    )
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", PRIVATE_KEY_B64)

    create_app()

    assert config_validations == 1
    assert identity_loads == 1
