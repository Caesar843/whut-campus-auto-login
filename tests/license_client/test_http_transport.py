import os

from license_client.http_transport import is_loopback_url, request
from license_client.license_api import LicenseApiClient


class FakeResponse:
    status_code = 200
    content = b"{}"

    def __init__(self, payload=None):
        self._payload = payload or {"status": "ok"}

    def json(self):
        return self._payload


def test_loopback_url_detection():
    assert is_loopback_url("http://127.0.0.1:8787")
    assert is_loopback_url("http://127.42.1.9:8787")
    assert is_loopback_url("http://localhost:8787")
    assert is_loopback_url("http://LOCALHOST:8787")
    assert is_loopback_url("http://[::1]:8787")
    assert not is_loopback_url("https://license.example.com")
    assert not is_loopback_url("not a url")


def test_loopback_request_uses_session_without_environment_proxy(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:7993")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7993")
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:7993")
    original_no_proxy = os.environ.get("NO_PROXY")
    calls = []

    class FakeSession:
        trust_env = True

        def request(self, method, url, **kwargs):
            calls.append(
                {
                    "method": method,
                    "url": url,
                    "trust_env": self.trust_env,
                    "kwargs": kwargs,
                }
            )
            return FakeResponse()

    monkeypatch.setattr("license_client.http_transport.requests.Session", FakeSession)

    request("post", "http://127.0.0.1:8787/device/register", json={"x": 1}, timeout=2.0)

    assert calls == [
        {
            "method": "post",
            "url": "http://127.0.0.1:8787/device/register",
            "trust_env": False,
            "kwargs": {"json": {"x": 1}, "timeout": 2.0},
        }
    ]
    assert os.environ.get("NO_PROXY") == original_no_proxy


def test_remote_request_keeps_requests_default_environment_behavior(monkeypatch):
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr(
        "license_client.http_transport.requests.Session",
        lambda: (_ for _ in ()).throw(AssertionError("remote request should not disable trust_env")),
    )
    monkeypatch.setattr("license_client.http_transport.requests.post", fake_post)

    request("post", "https://license.example.com/device/register", json={"x": 1}, timeout=2.0)

    assert calls == [("https://license.example.com/device/register", {"json": {"x": 1}, "timeout": 2.0})]


def test_license_client_bypasses_proxy_for_loopback(monkeypatch):
    calls = []

    class FakeSession:
        trust_env = True

        def request(self, method, url, **kwargs):
            calls.append((method, url, self.trust_env, kwargs))
            return FakeResponse({"status": "free_active", "signed_license_token": "signed-token"})

    monkeypatch.setattr("license_client.http_transport.requests.Session", FakeSession)

    license_result = LicenseApiClient(base_url="http://localhost:8787").register_device(
        device_fingerprint_hash="device-a",
    )

    assert license_result.signed_license_token == "signed-token"
    assert [call[2] for call in calls] == [False]
    assert calls[0][3]["timeout"] == 2.0
