import base64
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from license_client.license_api import LicenseApiClient, LicenseApiResult
from license_client.constants import DEFAULT_LICENSE_SERVER_URL
from license_client.license_guard import (
    check_license_before_login,
    initialize_license,
    try_initialize_license_after_bootstrap_login,
)
from license_client.license_state import LicenseDecision, LicenseStatus, evaluate_local_license
from license_client.token_store import (
    delete_signed_license_token,
    load_signed_license_token,
    save_signed_license_token,
)
import license_client.license_guard as license_guard
from license_client.token_verify import verify_signed_license_token


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
        "license_type": "trial",
        "license_status": "active",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "features": ["auto_login"],
    }
    payload.update(overrides)
    payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_segment = _b64url(payload_json)
    signature_segment = _b64url(private_key.sign(payload_segment.encode("ascii")))
    return f"{payload_segment}.{signature_segment}"


def test_license_api_client_uses_default_local_server_when_env_missing(monkeypatch):
    monkeypatch.delenv("LICENSE_SERVER_URL", raising=False)

    client = LicenseApiClient()

    assert client.base_url == DEFAULT_LICENSE_SERVER_URL


def test_license_api_client_uses_license_server_url_env(monkeypatch):
    monkeypatch.setenv("LICENSE_SERVER_URL", "https://license.example.test/")

    client = LicenseApiClient()

    assert client.base_url == "https://license.example.test"


def test_license_api_client_explicit_base_url_overrides_env(monkeypatch):
    monkeypatch.setenv("LICENSE_SERVER_URL", "https://license.example.test")

    client = LicenseApiClient(base_url="http://license.local/")

    assert client.base_url == "http://license.local"


def test_register_device_payload_excludes_campus_account_fields(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200
        content = b"{}"

        def json(self):
            return {
                "status": "trial_active",
                "signed_license_token": "signed-token",
            }

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["payload"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("license_client.license_api.requests.post", fake_post)

    result = LicenseApiClient(base_url="http://license.local").register_device(
        device_fingerprint_hash="device-a",
    )

    assert result.signed_license_token == "signed-token"
    forbidden_keys = {
        "campus_account",
        "campus_account_hash",
        "campus_account_masked",
        "account_hash",
        "account_masked",
        "username",
        "password",
    }
    assert forbidden_keys.isdisjoint(set(captured["payload"]))


def test_license_api_client_classifies_timeout_and_invalid_response(monkeypatch):
    monkeypatch.setattr(
        "license_client.license_api.requests.post",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.Timeout("slow")),
    )

    timeout = LicenseApiClient(base_url="http://license.local").register_device(
        device_fingerprint_hash="device-a",
    )

    assert timeout.reachable is False
    assert timeout.status == "request_timeout"
    assert timeout.error == "request_timeout"

    class InvalidJsonResponse:
        status_code = 200
        content = b"not-json"

        def json(self):
            raise ValueError("not-json")

    monkeypatch.setattr(
        "license_client.license_api.requests.post",
        lambda *args, **kwargs: InvalidJsonResponse(),
    )

    invalid = LicenseApiClient(base_url="http://license.local").register_device(
        device_fingerprint_hash="device-a",
    )

    assert invalid.reachable is True
    assert invalid.status == "invalid_response"
    assert invalid.error == "invalid_response"


def test_token_store_round_trips_signed_license_token(tmp_path):
    path = tmp_path / "license_token.json"

    save_signed_license_token("signed-value", token_path=path)
    loaded = load_signed_license_token(token_path=path)

    assert loaded.status == "loaded"
    assert loaded.signed_license_token == "signed-value"
    assert path.name == "license_token.json"

    deleted = delete_signed_license_token(token_path=path)

    assert deleted is True
    assert load_signed_license_token(token_path=path).status == "missing"


def test_token_store_replaces_existing_token(tmp_path):
    path = tmp_path / "license_token.json"

    save_signed_license_token("old-signed-value", token_path=path)
    save_signed_license_token("new-signed-value", token_path=path)

    assert load_signed_license_token(token_path=path).signed_license_token == "new-signed-value"


def test_token_store_preserves_json_format_and_utf8_encoding(tmp_path):
    path = tmp_path / "license_token.json"

    save_signed_license_token("signed-value", token_path=path)

    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    assert json.loads(raw.decode("utf-8")) == {"signed_license_token": "signed-value"}


def test_token_store_replace_failure_keeps_existing_token_and_cleans_temp_file(tmp_path, monkeypatch):
    path = tmp_path / "license_token.json"
    save_signed_license_token("old-signed-value", token_path=path)

    def fail_replace(src, dst):
        raise OSError("replace failed C:/Users/example/license_token.json")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError):
        save_signed_license_token("new-signed-value", token_path=path)

    assert load_signed_license_token(token_path=path).signed_license_token == "old-signed-value"
    assert [item.name for item in path.parent.iterdir()] == ["license_token.json"]


def test_token_store_temp_write_failure_keeps_existing_token_and_cleans_temp_file(tmp_path, monkeypatch):
    path = tmp_path / "license_token.json"
    temp_path = tmp_path / ".license-token-temp"
    save_signed_license_token("old-signed-value", token_path=path)

    class FailingTempFile:
        name = str(temp_path)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def write(self, value):
            temp_path.write_text("partial", encoding="utf-8")
            raise OSError("write failed C:/Users/example/license_token.json")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", lambda *args, **kwargs: FailingTempFile())

    with pytest.raises(OSError):
        save_signed_license_token("new-signed-value", token_path=path)

    assert load_signed_license_token(token_path=path).signed_license_token == "old-signed-value"
    assert [item.name for item in path.parent.iterdir()] == ["license_token.json"]


def test_token_store_reports_corrupt_file_without_crashing(tmp_path):
    path = tmp_path / "license_token.json"
    path.write_text("{not-json", encoding="utf-8")

    loaded = load_signed_license_token(token_path=path)

    assert loaded.status == "corrupt"
    assert loaded.signed_license_token is None


def test_valid_unexpired_trial_token_allows_use():
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)

    verification = verify_signed_license_token(
        signed_license_token,
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash="device-a",
        expected_product_id=PRODUCT_ID,
    )
    decision = evaluate_local_license(verification)

    assert verification.valid is True
    assert decision.status == LicenseStatus.TRIAL_ACTIVE
    assert decision.allowed is True
    assert decision.days_remaining >= 1
    assert "试用中" in decision.message_for_ui


def test_expired_trial_token_blocks_use():
    private_key, public_key_b64 = _key_pair()
    expired_at = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0)
    signed_license_token = _signed_license_token(
        private_key,
        expires_at=expired_at.isoformat().replace("+00:00", "Z"),
    )

    verification = verify_signed_license_token(
        signed_license_token,
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash="device-a",
        expected_product_id=PRODUCT_ID,
    )
    decision = evaluate_local_license(verification)

    assert verification.valid is False
    assert verification.error == "expired"
    assert decision.status == LicenseStatus.TRIAL_EXPIRED
    assert decision.allowed is False


def test_tampered_token_blocks_use():
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)
    payload_segment, signature_segment = signed_license_token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_segment + "==").decode("utf-8"))
    payload["license_type"] = "paid"
    tampered_payload_segment = _b64url(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )

    verification = verify_signed_license_token(
        f"{tampered_payload_segment}.{signature_segment}",
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash="device-a",
        expected_product_id=PRODUCT_ID,
    )
    decision = evaluate_local_license(verification)

    assert verification.valid is False
    assert verification.error == "signature_invalid"
    assert decision.status == LicenseStatus.TOKEN_INVALID
    assert decision.allowed is False


def test_device_mismatch_blocks_use():
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)

    verification = verify_signed_license_token(
        signed_license_token,
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash="device-b",
        expected_product_id=PRODUCT_ID,
    )

    assert verification.valid is False
    assert verification.error == "device_mismatch"
    decision = evaluate_local_license(verification)
    assert decision.allowed is False
    assert decision.reason == "device_mismatch"
    assert decision.retryable is False


def test_revoked_token_blocks_use():
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key, license_status="revoked")

    verification = verify_signed_license_token(
        signed_license_token,
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash="device-a",
        expected_product_id=PRODUCT_ID,
    )
    decision = evaluate_local_license(verification)

    assert verification.valid is False
    assert verification.error == "revoked"
    assert decision.status == LicenseStatus.REVOKED
    assert decision.allowed is False


def test_guard_allows_valid_local_token_when_server_unreachable(tmp_path):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(signed_license_token, token_path=token_path)

    decision = check_license_before_login(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.TRIAL_ACTIVE


def test_guard_blocks_when_server_unreachable_and_token_missing(tmp_path):
    decision = check_license_before_login(
        token_path=tmp_path / "missing-license.json",
        public_key_b64="unused",
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
        saved_login_available_func=lambda: False,
        campus_network_probe_func=lambda: True,
    )

    assert decision.allowed is False
    assert decision.status == LicenseStatus.SERVER_UNREACHABLE


def test_guard_registers_device_and_saves_trial_token_when_missing(tmp_path):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)
    token_path = tmp_path / "license_token.json"

    decision = check_license_before_login(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(
            reachable=True,
            status="trial_active",
            signed_license_token=signed_license_token,
        ),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.TRIAL_ACTIVE
    assert load_signed_license_token(token_path=token_path).signed_license_token == signed_license_token


def test_initialize_license_registers_device_verifies_and_saves_token(tmp_path):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)
    token_path = tmp_path / "license_token.json"
    calls = []

    decision = initialize_license(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: calls.append("register")
        or LicenseApiResult(
            reachable=True,
            status="trial_active",
            signed_license_token=signed_license_token,
        ),
    )

    assert calls == ["register"]
    assert decision.status == LicenseStatus.TRIAL_ACTIVE
    assert load_signed_license_token(token_path=token_path).signed_license_token == signed_license_token


def test_initialize_license_timeout_is_retryable_without_saving_token(tmp_path):
    token_path = tmp_path / "license_token.json"

    decision = initialize_license(
        token_path=token_path,
        public_key_b64="unused",
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(
            reachable=False,
            status="request_timeout",
            error="request_timeout",
        ),
    )

    assert decision.status == LicenseStatus.SERVER_UNREACHABLE
    assert decision.reason == "request_timeout"
    assert decision.retryable is True
    assert load_signed_license_token(token_path=token_path).status == "missing"


def test_initialize_license_rejects_bad_signature_without_saving(tmp_path):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)
    payload_segment, signature_segment = signed_license_token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_segment + "==").decode("utf-8"))
    payload["license_type"] = "paid"
    tampered = _b64url(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    token_path = tmp_path / "license_token.json"

    decision = initialize_license(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(
            reachable=True,
            status="trial_active",
            signed_license_token=f"{tampered}.{signature_segment}",
        ),
    )

    assert decision.status == LicenseStatus.TOKEN_INVALID
    assert decision.reason == "signature_invalid"
    assert load_signed_license_token(token_path=token_path).status == "missing"


def test_initialize_license_rejects_device_mismatch_without_saving(tmp_path):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key, device_fingerprint_hash="device-b")
    token_path = tmp_path / "license_token.json"

    decision = initialize_license(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(
            reachable=True,
            status="trial_active",
            signed_license_token=signed_license_token,
        ),
    )

    assert decision.status == LicenseStatus.TOKEN_INVALID
    assert decision.reason == "device_mismatch"
    assert load_signed_license_token(token_path=token_path).status == "missing"


def test_guard_keeps_allowed_decision_when_token_persist_fails(tmp_path, monkeypatch):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)

    def fail_save(token, *, token_path=None):
        raise OSError(f"persist failed C:/Users/example/{token}")

    monkeypatch.setattr(license_guard, "save_signed_license_token", fail_save)

    decision = check_license_before_login(
        token_path=tmp_path / "license_token.json",
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(
            reachable=True,
            status="trial_active",
            signed_license_token=signed_license_token,
        ),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.TRIAL_ACTIVE
    assert decision.warning_code == "token_persist_failed"
    assert signed_license_token not in decision.message_for_ui
    assert "C:/Users/example" not in decision.message_for_ui
    assert "persist failed" not in decision.message_for_ui


def test_guard_does_not_convert_invalid_token_to_allowed_persistence_warning(tmp_path, monkeypatch):
    _, public_key_b64 = _key_pair()
    save_calls = []
    monkeypatch.setattr(
        license_guard,
        "save_signed_license_token",
        lambda *args, **kwargs: save_calls.append(args),
    )

    decision = check_license_before_login(
        token_path=tmp_path / "license_token.json",
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(
            reachable=True,
            status="trial_active",
            signed_license_token="invalid-token",
        ),
    )

    assert decision.allowed is False
    assert decision.status == LicenseStatus.TOKEN_INVALID
    assert decision.warning_code is None
    assert save_calls == []


def test_guard_allows_bootstrap_when_token_missing_server_unreachable_saved_config_and_campus_network(tmp_path):
    decision = check_license_before_login(
        token_path=tmp_path / "missing-license.json",
        public_key_b64="unused",
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
        saved_login_available_func=lambda: True,
        campus_network_probe_func=lambda: True,
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.BOOTSTRAP_ALLOWED
    assert decision.bootstrap_required is True
    assert "首次使用" in decision.message_for_ui


def test_guard_blocks_bootstrap_when_saved_config_missing(tmp_path):
    decision = check_license_before_login(
        token_path=tmp_path / "missing-license.json",
        public_key_b64="unused",
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
        saved_login_available_func=lambda: False,
        campus_network_probe_func=lambda: True,
    )

    assert decision.allowed is False
    assert decision.status == LicenseStatus.SERVER_UNREACHABLE
    assert decision.reason == "missing_saved_login_config"
    assert decision.retryable is False
    assert decision.bootstrap_required is False


def test_guard_marks_bootstrap_portal_not_ready_as_retryable(tmp_path):
    decision = check_license_before_login(
        token_path=tmp_path / "missing-license.json",
        public_key_b64="unused",
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
        saved_login_available_func=lambda: True,
        campus_network_probe_func=lambda: False,
    )

    assert decision.allowed is False
    assert decision.status == LicenseStatus.SERVER_UNREACHABLE
    assert decision.reason == "bootstrap_portal_not_ready"
    assert decision.retryable is True
    assert decision.bootstrap_required is False


def test_paid_active_local_token_allows_use_when_server_unreachable(tmp_path):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key, license_type="paid")
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(signed_license_token, token_path=token_path)

    decision = check_license_before_login(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.PAID_ACTIVE


def test_expired_token_blocks_without_bootstrap_even_when_campus_network_available(tmp_path):
    private_key, public_key_b64 = _key_pair()
    expired_at = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0)
    signed_license_token = _signed_license_token(
        private_key,
        expires_at=expired_at.isoformat().replace("+00:00", "Z"),
    )
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(signed_license_token, token_path=token_path)

    decision = check_license_before_login(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
        saved_login_available_func=lambda: True,
        campus_network_probe_func=lambda: True,
    )

    assert decision.allowed is False
    assert decision.status == LicenseStatus.TRIAL_EXPIRED
    assert decision.retryable is False
    assert decision.bootstrap_required is False
    assert "试用期已结束" in decision.message_for_ui


def test_paid_expired_token_blocks_without_bootstrap(tmp_path):
    private_key, public_key_b64 = _key_pair()
    expired_at = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0)
    signed_license_token = _signed_license_token(
        private_key,
        license_type="paid",
        expires_at=expired_at.isoformat().replace("+00:00", "Z"),
    )
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(signed_license_token, token_path=token_path)

    decision = check_license_before_login(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
        saved_login_available_func=lambda: True,
        campus_network_probe_func=lambda: True,
    )

    assert decision.allowed is False
    assert decision.status == LicenseStatus.PAID_EXPIRED
    assert decision.retryable is False
    assert decision.bootstrap_required is False


def test_invalid_token_blocks_without_bootstrap(tmp_path):
    token_path = tmp_path / "license_token.json"
    save_signed_license_token("invalid-token", token_path=token_path)

    decision = check_license_before_login(
        token_path=token_path,
        public_key_b64="not-a-real-key",
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
        saved_login_available_func=lambda: True,
        campus_network_probe_func=lambda: True,
    )

    assert decision.allowed is False
    assert decision.status == LicenseStatus.TOKEN_INVALID
    assert decision.retryable is False
    assert decision.bootstrap_required is False
    assert "本地授权凭证无效" in decision.message_for_ui


def test_revoked_token_blocks_without_bootstrap(tmp_path):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key, license_status="revoked")
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(signed_license_token, token_path=token_path)

    decision = check_license_before_login(
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
        saved_login_available_func=lambda: True,
        campus_network_probe_func=lambda: True,
    )

    assert decision.allowed is False
    assert decision.status == LicenseStatus.REVOKED
    assert decision.retryable is False
    assert decision.bootstrap_required is False


def test_bootstrap_success_initializes_and_saves_license_token(tmp_path):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)
    token_path = tmp_path / "license_token.json"
    bootstrap_decision = LicenseDecision(
        status=LicenseStatus.BOOTSTRAP_ALLOWED,
        allowed=True,
        reason="bootstrap_allowed",
        bootstrap_required=True,
    )

    decision = try_initialize_license_after_bootstrap_login(
        bootstrap_decision=bootstrap_decision,
        token_path=token_path,
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(
            reachable=True,
            status="trial_active",
            signed_license_token=signed_license_token,
        ),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.TRIAL_ACTIVE
    assert load_signed_license_token(token_path=token_path).signed_license_token == signed_license_token


def test_bootstrap_initialize_keeps_allowed_decision_when_token_persist_fails(tmp_path, monkeypatch):
    private_key, public_key_b64 = _key_pair()
    signed_license_token = _signed_license_token(private_key)
    bootstrap_decision = LicenseDecision(
        status=LicenseStatus.BOOTSTRAP_ALLOWED,
        allowed=True,
        reason="bootstrap_allowed",
        bootstrap_required=True,
    )

    def fail_save(token, *, token_path=None):
        raise OSError(f"persist failed C:/Users/example/{token}")

    monkeypatch.setattr(license_guard, "save_signed_license_token", fail_save)

    decision = try_initialize_license_after_bootstrap_login(
        bootstrap_decision=bootstrap_decision,
        token_path=tmp_path / "license_token.json",
        public_key_b64=public_key_b64,
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(
            reachable=True,
            status="trial_active",
            signed_license_token=signed_license_token,
        ),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.TRIAL_ACTIVE
    assert decision.warning_code == "token_persist_failed"
    assert signed_license_token not in decision.message_for_ui
    assert "C:/Users/example" not in decision.message_for_ui
    assert "persist failed" not in decision.message_for_ui


def test_bootstrap_failed_login_does_not_create_token(tmp_path):
    token_path = tmp_path / "license_token.json"
    non_bootstrap_decision = LicenseDecision(
        status=LicenseStatus.TRIAL_ACTIVE,
        allowed=True,
        reason="trial_active",
        bootstrap_required=False,
    )

    decision = try_initialize_license_after_bootstrap_login(
        bootstrap_decision=non_bootstrap_decision,
        token_path=token_path,
        public_key_b64="unused",
        device_fingerprint_hash="device-a",
        api_client=lambda: pytest.fail("post-bootstrap init should not run"),
    )

    assert decision is non_bootstrap_decision
    assert load_signed_license_token(token_path=token_path).status == "missing"
