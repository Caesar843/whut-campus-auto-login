import base64
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from fastapi.testclient import TestClient

from license_server.app import create_app


def _private_key_b64() -> str:
    private_key = Ed25519PrivateKey.generate()
    return base64.b64encode(
        private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
    ).decode("ascii")


def _public_key_b64(private_key_b64: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    return base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    ).decode("ascii")


def _client(tmp_path):
    private_key_b64 = _private_key_b64()
    app = create_app(
        database_path=tmp_path / "license.sqlite3",
        private_key_b64=private_key_b64,
        admin_token="admin-token",
    )
    return TestClient(app), _public_key_b64(private_key_b64)


def _register_payload(device_hash="device-a"):
    return {
        "product_id": "whut-campus-auto-login",
        "device_fingerprint_hash": device_hash,
        "device_name": "dev pc",
        "os": "Windows",
        "app_version": "0.1.0",
        "campus_account_hash": "account-hash",
        "campus_account_masked": "2024****1234",
    }


def test_health_endpoint_returns_service_status(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_register_new_device_issues_14_day_trial(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    response = client.post("/device/register", json=_register_payload())

    assert response.status_code == 200
    payload = response.json()
    assert payload["license_type"] == "trial"
    assert payload["license_status"] == "active"
    assert payload["signed_license_token"]
    expires_at = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
    assert 13 <= (expires_at - datetime.now(timezone.utc)).days <= 14


def test_register_existing_device_does_not_duplicate_trial(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    first = client.post("/device/register", json=_register_payload()).json()
    second = client.post("/device/register", json=_register_payload()).json()

    assert second["license_id"] == first["license_id"]
    assert second["license_type"] == "trial"


def test_refresh_returns_latest_license(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)
    registered = client.post("/device/register", json=_register_payload()).json()

    response = client.post(
        "/license/refresh",
        json={
            "product_id": "whut-campus-auto-login",
            "device_fingerprint_hash": "device-a",
            "app_version": "0.1.0",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["license_id"] == registered["license_id"]
    assert payload["signed_license_token"]


def test_admin_grant_issues_365_day_paid_license(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)
    client.post("/device/register", json=_register_payload())

    response = client.post(
        "/admin/grant",
        headers={"X-License-Admin-Token": "admin-token"},
        json={
            "device_fingerprint_hash": "device-a",
            "license_days": 365,
            "reason": "dev grant",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["license_type"] == "paid"
    assert payload["license_status"] == "active"
    expires_at = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
    assert 364 <= (expires_at - datetime.now(timezone.utc)).days <= 365


def test_admin_grant_requires_admin_token(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)
    client.post("/device/register", json=_register_payload())

    response = client.post(
        "/admin/grant",
        headers={"X-License-Admin-Token": "wrong"},
        json={
            "device_fingerprint_hash": "device-a",
            "license_days": 365,
            "reason": "dev grant",
        },
    )

    assert response.status_code == 403
