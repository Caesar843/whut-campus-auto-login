import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from license_client.license_guard import get_current_license_state
from license_client.license_state import LicenseStatus
from license_client.public_key import (
    EMBEDDED_CONFIG_FILENAME,
    EMBEDDED_CONFIG_MODULE_NAME,
    resolve_build_environment,
    resolve_license_public_key,
    write_embedded_build_config,
)
from license_client.token_store import save_signed_license_token


PRODUCT_ID = "whut-campus-auto-login"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _key_pair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_b64 = base64.b64encode(
        public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    ).decode("ascii")
    return private_key, public_key_b64


def _signed_license_token(private_key, **overrides):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "product_id": PRODUCT_ID,
        "device_fingerprint_hash": "device-a",
        "license_id": "lic-1",
        "license_type": "paid",
        "license_status": "active",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=365)).isoformat().replace("+00:00", "Z"),
        "features": ["auto_login"],
    }
    payload.update(overrides)
    payload_segment = _b64url(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature_segment = _b64url(private_key.sign(payload_segment.encode("ascii")))
    return f"{payload_segment}.{signature_segment}"


def test_development_build_allows_environment_public_key_override(monkeypatch):
    monkeypatch.setenv("LICENSE_PUBLIC_KEY", "env-key")

    assert (
        resolve_license_public_key(
            explicit_public_key=" explicit-key ",
            embedded_config_loader=lambda: ("production", "packaged-key"),
        )
        == "explicit-key"
    )
    assert (
        resolve_license_public_key(
            embedded_config_loader=lambda: ("development", "packaged-key"),
        )
        == "env-key"
    )

    monkeypatch.delenv("LICENSE_PUBLIC_KEY", raising=False)

    assert (
        resolve_license_public_key(
            embedded_config_loader=lambda: ("development", " packaged-key "),
        )
        == "packaged-key"
    )
    assert (
        resolve_build_environment(embedded_config_loader=lambda: None)
        == "development"
    )
    assert (
        resolve_build_environment(embedded_config_loader=lambda: (" production ", "packaged-key"))
        == "production"
    )
    assert (
        resolve_license_public_key(
            env={"LICENSE_PUBLIC_KEY": "env-key"},
            embedded_config_loader=lambda: ("staging", "packaged-key"),
        )
        == ""
    )
    assert (
        resolve_license_public_key(
            embedded_config_loader=lambda: ("development", ""),
        )
        == ""
    )


def test_frozen_app_missing_build_environment_fails_closed(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    assert resolve_build_environment(embedded_config_loader=lambda: None) == ""
    assert (
        resolve_license_public_key(
            env={"LICENSE_PUBLIC_KEY": "env-key"},
            embedded_config_loader=lambda: None,
        )
        == ""
    )


@pytest.mark.parametrize("build_environment", ["production", "preproduction"])
def test_release_builds_ignore_runtime_public_key_env(build_environment):
    assert (
        resolve_license_public_key(
            env={"LICENSE_PUBLIC_KEY": "malicious-key"},
            embedded_config_loader=lambda: (build_environment, "packaged-key"),
        )
        == "packaged-key"
    )


def test_production_packaged_public_key_verifies_token_when_env_is_malicious(
    tmp_path,
    monkeypatch,
):
    private_key, public_key_b64 = _key_pair()
    _malicious_private, malicious_public_key_b64 = _key_pair()
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(_signed_license_token(private_key), token_path=token_path)
    monkeypatch.setenv("LICENSE_PUBLIC_KEY", malicious_public_key_b64)
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", public_key_b64),
    )

    decision = get_current_license_state(
        token_path=token_path,
        device_fingerprint_hash="device-a",
    )

    assert decision.status == LicenseStatus.PAID_ACTIVE
    assert decision.allowed is True


def test_production_missing_packaged_public_key_fails_closed_even_with_env(
    tmp_path,
    monkeypatch,
):
    attacker_private_key, attacker_public_key_b64 = _key_pair()
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(_signed_license_token(attacker_private_key), token_path=token_path)
    monkeypatch.setenv("LICENSE_PUBLIC_KEY", attacker_public_key_b64)
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", ""),
    )

    decision = get_current_license_state(
        token_path=token_path,
        device_fingerprint_hash="device-a",
    )

    assert decision.status == LicenseStatus.TOKEN_INVALID
    assert decision.reason == "missing_public_key"


def test_explicit_public_key_parameter_remains_test_injection(tmp_path, monkeypatch):
    private_key, public_key_b64 = _key_pair()
    _wrong_private_key, wrong_public_key_b64 = _key_pair()
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(_signed_license_token(private_key), token_path=token_path)
    monkeypatch.setenv("LICENSE_PUBLIC_KEY", wrong_public_key_b64)
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", wrong_public_key_b64),
    )

    decision = get_current_license_state(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
    )

    assert decision.status == LicenseStatus.PAID_ACTIVE
    assert decision.allowed is True


def test_guard_uses_packaged_public_key_when_env_missing(tmp_path, monkeypatch):
    private_key, public_key_b64 = _key_pair()
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(_signed_license_token(private_key), token_path=token_path)
    monkeypatch.delenv("LICENSE_PUBLIC_KEY", raising=False)
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", public_key_b64),
    )

    decision = get_current_license_state(
        token_path=token_path,
        device_fingerprint_hash="device-a",
    )

    assert decision.status == LicenseStatus.PAID_ACTIVE
    assert decision.allowed is True


def test_missing_public_key_fails_closed(tmp_path, monkeypatch):
    private_key, _public_key_b64 = _key_pair()
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(_signed_license_token(private_key), token_path=token_path)
    monkeypatch.delenv("LICENSE_PUBLIC_KEY", raising=False)
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", ""),
    )

    decision = get_current_license_state(
        token_path=token_path,
        device_fingerprint_hash="device-a",
    )

    assert decision.status == LicenseStatus.TOKEN_INVALID
    assert decision.reason == "missing_public_key"


def test_wrong_or_invalid_public_key_does_not_verify_token(tmp_path, monkeypatch):
    private_key, _public_key_b64 = _key_pair()
    _wrong_private, wrong_public_key_b64 = _key_pair()
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(_signed_license_token(private_key), token_path=token_path)

    monkeypatch.delenv("LICENSE_PUBLIC_KEY", raising=False)
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", wrong_public_key_b64),
    )

    wrong_key = get_current_license_state(
        token_path=token_path,
        device_fingerprint_hash="device-a",
    )

    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", "not-a-public-key"),
    )

    invalid_key = get_current_license_state(
        token_path=token_path,
        device_fingerprint_hash="device-a",
    )

    assert wrong_key.status == LicenseStatus.TOKEN_INVALID
    assert wrong_key.reason == "signature_invalid"
    assert invalid_key.status == LicenseStatus.TOKEN_INVALID
    assert invalid_key.reason == "signature_invalid"


def test_write_embedded_build_config_writes_only_allowed_constants(tmp_path):
    _private_key, public_key_b64 = _key_pair()
    output_path = tmp_path / "generated" / EMBEDDED_CONFIG_FILENAME

    write_embedded_build_config(
        public_key_b64=public_key_b64,
        build_environment=" production ",
        output_path=output_path,
    )

    content = output_path.read_text(encoding="utf-8")
    assert content == (
        'BUILD_ENVIRONMENT = "production"\n'
        f'LICENSE_PUBLIC_KEY_B64 = "{public_key_b64}"\n'
    )
    assert "PRIVATE" not in content
    assert "TOKEN" not in content
    with pytest.raises(ValueError):
        write_embedded_build_config(
            public_key_b64=public_key_b64,
            build_environment="staging",
            output_path=output_path,
        )
    with pytest.raises(ValueError):
        write_embedded_build_config(
            public_key_b64="not-a-public-key",
            build_environment="production",
            output_path=output_path,
        )


def test_pyinstaller_config_freezes_embedded_config_module_not_external_txt():
    root = Path(__file__).resolve().parents[2]
    spec = (root / "WHUTCampusAutoLogin.spec").read_text(encoding="utf-8")
    build_script = (root / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    gitignore = (root / ".gitignore").read_text(encoding="utf-8")

    assert EMBEDDED_CONFIG_FILENAME in spec
    assert EMBEDDED_CONFIG_FILENAME in build_script
    assert EMBEDDED_CONFIG_MODULE_NAME in spec
    assert "license_public_key.txt" not in spec
    assert "build_environment.txt" not in spec
    assert "datas=[]" in spec.replace(" ", "")
    assert "license_public_key.txt" not in build_script
    assert "build_environment.txt" not in build_script
    assert "BuildEnvironment" in build_script
    assert '[string]$BuildEnvironment = "production"' not in build_script
    assert "build/generated/" in gitignore
    for forbidden in (
        "LICENSE_PRIVATE_KEY",
        "LICENSE_ADMIN_TOKEN",
        "PAYMENT_MOCK_ADMIN_TOKEN",
        "MOCK_PAYMENT_ADMIN_TOKEN",
        "WECHAT_PAY_MERCHANT_PRIVATE_KEY",
        "WECHAT_PAY_API_V3_KEY",
    ):
        assert forbidden not in spec
        assert forbidden not in build_script
