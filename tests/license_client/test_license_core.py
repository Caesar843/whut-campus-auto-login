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
    get_current_license_state,
    initialize_license,
    report_device_usage,
    try_initialize_license_after_bootstrap_login,
)
from license_client.license_state import (
    FREE_LICENSE_MESSAGE,
    LicenseDecision,
    LicenseStatus,
    evaluate_local_license,
    free_decision,
)
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
                "status": "free_active",
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
    assert "免费版" in decision.message_for_ui


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


# ---------------------------------------------------------------------------
# 免费版授权入口：任何本地凭证状态都不能阻断功能
# ---------------------------------------------------------------------------


def test_free_decision_is_allowed_and_marked_free():
    decision = free_decision()

    assert decision.status == LicenseStatus.FREE
    assert decision.allowed is True
    assert decision.license_type == "free"
    assert decision.reason == "free_mode"
    assert decision.message_for_ui == FREE_LICENSE_MESSAGE


def test_check_license_before_login_allows_without_network_or_token(monkeypatch):
    monkeypatch.setattr(
        "license_client.license_api.requests.post",
        lambda *args, **kwargs: pytest.fail("login-time check must not call the server"),
    )
    monkeypatch.setattr(
        "license_client.license_guard.generate_device_fingerprint_hash",
        lambda *args, **kwargs: pytest.fail("login-time check must not touch the device"),
    )

    decision = check_license_before_login()

    assert decision.allowed is True
    assert decision.status == LicenseStatus.FREE
    # 登录成功后仍需补一次设备使用上报
    assert decision.usage_sync_required is True


def test_guard_public_api_no_longer_accepts_blocking_inputs():
    import inspect

    assert set(inspect.signature(check_license_before_login).parameters) == set()
    assert set(inspect.signature(initialize_license).parameters) == {
        "device_fingerprint_hash",
        "api_client",
    }
    assert set(
        inspect.signature(try_initialize_license_after_bootstrap_login).parameters
    ) == {"bootstrap_decision", "device_fingerprint_hash", "api_client"}


def test_initialize_license_reports_device_usage_and_allows():
    calls = []

    def fake_api_client():
        calls.append("called")
        return LicenseApiResult(reachable=True, status="free_active")

    decision = initialize_license(
        device_fingerprint_hash="device-a",
        api_client=fake_api_client,
    )

    assert calls == ["called"]
    assert decision.allowed is True
    assert decision.status == LicenseStatus.FREE
    assert decision.usage_sync_required is False


def test_initialize_license_allows_when_server_unreachable():
    decision = initialize_license(
        device_fingerprint_hash="device-a",
        api_client=lambda: LicenseApiResult(reachable=False, status="server_unreachable"),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.FREE


def test_initialize_license_allows_when_api_client_raises():
    def broken_api_client():
        raise RuntimeError("boom")

    decision = initialize_license(
        device_fingerprint_hash="device-a",
        api_client=broken_api_client,
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.FREE


def test_initialize_license_allows_when_fingerprint_generation_fails(monkeypatch):
    def broken_fingerprint(*args, **kwargs):
        raise OSError("no device identity")

    monkeypatch.setattr(
        "license_client.license_guard.generate_device_fingerprint_hash",
        broken_fingerprint,
    )

    decision = initialize_license(
        api_client=lambda: pytest.fail("no fingerprint, no report"),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.FREE


def test_get_current_license_state_is_always_free():
    first = get_current_license_state()
    second = get_current_license_state()

    assert first.allowed is True
    assert second.allowed is True
    assert first.status == LicenseStatus.FREE
    assert second.usage_sync_required is True


def test_bootstrap_sync_reports_usage_when_required():
    calls = []

    def fake_api_client():
        calls.append("called")
        return LicenseApiResult(reachable=True, status="free_active")

    decision = try_initialize_license_after_bootstrap_login(
        bootstrap_decision=free_decision(usage_sync_required=True),
        device_fingerprint_hash="device-a",
        api_client=fake_api_client,
    )

    assert calls == ["called"]
    assert decision.allowed is True
    assert decision.status == LicenseStatus.FREE


def test_bootstrap_sync_skips_report_when_not_required():
    bootstrap_decision = free_decision(usage_sync_required=False)

    decision = try_initialize_license_after_bootstrap_login(
        bootstrap_decision=bootstrap_decision,
        device_fingerprint_hash="device-a",
        api_client=lambda: pytest.fail("sync not required, no report expected"),
    )

    assert decision is bootstrap_decision


def test_bootstrap_sync_allows_when_report_fails():
    decision = try_initialize_license_after_bootstrap_login(
        bootstrap_decision=free_decision(usage_sync_required=True),
        device_fingerprint_hash="device-a",
        api_client=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    assert decision.allowed is True
    assert decision.status == LicenseStatus.FREE


def test_report_device_usage_returns_none_instead_of_raising(monkeypatch):
    monkeypatch.setattr(
        "license_client.license_guard.generate_device_fingerprint_hash",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("broken")),
    )

    assert report_device_usage(api_client=lambda: pytest.fail("must not report")) is None


def test_report_device_usage_surfaces_api_result_for_logging():
    expected = LicenseApiResult(reachable=False, status="server_unreachable")

    assert report_device_usage(
        device_fingerprint_hash="device-a",
        api_client=lambda: expected,
    ) is expected


def test_license_guard_module_keeps_no_payment_surface():
    assert not hasattr(license_guard, "PaymentApiClient")
    assert not hasattr(license_guard, "default_campus_network_probe")
    source = Path(license_guard.__file__).read_text(encoding="utf-8")
    for forbidden in ("payment", "Payment", "PAYMENT", "wechat", "order"):
        assert forbidden not in source