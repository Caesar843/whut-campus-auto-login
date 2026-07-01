import base64
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from fastapi.testclient import TestClient

from license_server.db import initialize_database
from license_server.app import _default_app, create_app
from license_server.config import load_config


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
    }


def test_health_endpoint_returns_service_status(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "license_server"}


def test_default_app_health_works_without_sensitive_env(monkeypatch):
    monkeypatch.delenv("LICENSE_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("LICENSE_PRIVATE_KEY_FILE", raising=False)
    monkeypatch.delenv("LICENSE_ADMIN_TOKEN", raising=False)

    client = TestClient(_default_app())
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "license_server"}


def test_load_config_uses_relative_sqlite_database_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./license_server_dev.sqlite3")
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", "private-placeholder")
    monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "admin-placeholder")
    monkeypatch.delenv("LICENSE_DB_PATH", raising=False)

    config = load_config()

    assert config.database_path == Path("license_server_dev.sqlite3")


def test_load_config_uses_absolute_sqlite_database_url(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        "sqlite:////var/lib/whut-campus-auto-login/license.sqlite3",
    )
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", "private-placeholder")
    monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "admin-placeholder")
    monkeypatch.delenv("LICENSE_DB_PATH", raising=False)

    config = load_config()

    assert config.database_path.as_posix().endswith(
        "/var/lib/whut-campus-auto-login/license.sqlite3"
    )


def test_load_config_keeps_license_db_path_fallback(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("LICENSE_DB_PATH", "legacy-license.sqlite3")
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", "private-placeholder")
    monkeypatch.setenv("LICENSE_ADMIN_TOKEN", "admin-placeholder")

    config = load_config()

    assert config.database_path == Path("legacy-license.sqlite3")


def test_devices_schema_excludes_campus_account_columns(tmp_path):
    database_path = tmp_path / "license.sqlite3"

    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(devices)").fetchall()
        }
    assert "campus_account_hash" not in columns
    assert "campus_account_masked" not in columns
    assert "device_name" not in columns
    assert "os" not in columns
    assert "app_version" not in columns


def test_licenses_schema_excludes_revoked_reason(tmp_path):
    database_path = tmp_path / "license.sqlite3"

    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(licenses)").fetchall()
        }
    assert "revoked_reason" not in columns


def test_initialize_database_removes_legacy_sensitive_columns(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id TEXT NOT NULL,
                device_fingerprint_hash TEXT NOT NULL UNIQUE,
                device_name TEXT,
                os TEXT,
                app_version TEXT,
                campus_account_hash TEXT,
                campus_account_masked TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO devices (
                product_id, device_fingerprint_hash, device_name, os, app_version,
                campus_account_hash, campus_account_masked, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "whut-campus-auto-login",
                "device-a",
                "dev pc",
                "Windows",
                "0.1.0",
                "account-hash",
                "2024****1234",
                "2026-06-04T00:00:00Z",
                "2026-06-04T00:00:00Z",
            ),
        )

    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(devices)").fetchall()
        }
        device = connection.execute(
            "SELECT device_fingerprint_hash FROM devices"
        ).fetchone()
    assert "campus_account_hash" not in columns
    assert "campus_account_masked" not in columns
    assert "device_name" not in columns
    assert "os" not in columns
    assert "app_version" not in columns
    assert device == ("device-a",)


def test_initialize_database_removes_legacy_license_revoked_reason(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                license_type TEXT NOT NULL,
                status TEXT NOT NULL,
                starts_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                source TEXT NOT NULL,
                order_id TEXT,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                revoked_reason TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO licenses (
                device_id, license_type, status, starts_at, expires_at, source,
                order_id, created_at, revoked_at, revoked_reason
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?)
            """,
            (
                1,
                "trial",
                "active",
                "2026-06-04T00:00:00Z",
                "2026-06-11T00:00:00Z",
                "trial",
                "2026-06-04T00:00:00Z",
                "legacy reason",
            ),
        )

    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(licenses)").fetchall()
        }
        license_row = connection.execute(
            "SELECT license_type, status FROM licenses"
        ).fetchone()
    assert "revoked_reason" not in columns
    assert license_row == ("trial", "active")


def test_register_device_ignores_device_description_fields(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)
    payload = _register_payload()
    payload.update(
        {
            "device_name": "dev pc",
            "os": "Windows",
            "app_version": "0.1.0",
        }
    )

    response = client.post("/device/register", json=payload)

    assert response.status_code == 200
    assert "device_name" not in response.json()
    assert "os" not in response.json()
    assert "app_version" not in response.json()


def test_register_device_rejects_campus_account_fields(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)
    payload = _register_payload()
    payload["campus_account_hash"] = "account-hash"
    payload["campus_account_masked"] = "2024****1234"

    response = client.post("/device/register", json=payload)

    assert response.status_code == 422


def test_refresh_license_rejects_campus_account_fields(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)
    client.post("/device/register", json=_register_payload())

    response = client.post(
        "/license/refresh",
        json={
            "product_id": "whut-campus-auto-login",
            "device_fingerprint_hash": "device-a",
            "app_version": "0.1.0",
            "campus_account_hash": "account-hash",
            "campus_account_masked": "2024****1234",
            "password": "secret",
        },
    )

    assert response.status_code == 422


def test_refresh_license_ignores_device_description_fields(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)
    client.post("/device/register", json=_register_payload())

    response = client.post(
        "/license/refresh",
        json={
            "product_id": "whut-campus-auto-login",
            "device_fingerprint_hash": "device-a",
            "app_version": "0.1.0",
        },
    )

    assert response.status_code == 200


def test_register_new_device_issues_14_day_trial(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    response = client.post("/device/register", json=_register_payload())

    assert response.status_code == 200
    payload = response.json()
    assert payload["license_type"] == "trial"
    assert payload["license_status"] == "active"
    assert payload["signed_license_token"]
    assert "device_name" not in payload
    assert "os" not in payload
    assert "app_version" not in payload
    expires_at = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
    assert 13 <= (expires_at - datetime.now(timezone.utc)).days <= 14


def test_register_device_stores_only_minimal_device_fields(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    response = client.post("/device/register", json=_register_payload())

    assert response.status_code == 200
    with sqlite3.connect(tmp_path / "license.sqlite3") as connection:
        columns = [
            row[1]
            for row in connection.execute("PRAGMA table_info(devices)").fetchall()
        ]
        row = connection.execute("SELECT * FROM devices").fetchone()

    assert columns == [
        "id",
        "product_id",
        "device_fingerprint_hash",
        "first_seen_at",
        "last_seen_at",
    ]
    assert row[1] == "whut-campus-auto-login"
    assert row[2] == "device-a"


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


def test_env_example_contains_only_placeholders():
    content = Path("license_server/.env.example").read_text(encoding="utf-8")

    assert "LICENSE_SERVER_URL=http://127.0.0.1:8787" in content
    assert "LICENSE_PRIVATE_KEY=replace_with_base64_or_configured_private_key" in content
    assert "LICENSE_PUBLIC_KEY=replace_with_public_key" in content
    assert "LICENSE_ADMIN_TOKEN=replace_with_strong_admin_token" in content
    assert "DATABASE_URL=sqlite:///./license_server_dev.sqlite3" in content
    assert "SERVER_ENV=development" in content
    assert "LICENSE_DB_PATH" not in content
    forbidden_fragments = [
        "124.223.7.147",
        "license.whutlogin.cn",
        "BEGIN " + "PRIVATE KEY",
        "signed_license_token",
        "license_token.json",
        "sk_",
        "wxpay",
        "alipay_" + "secret",
    ]
    for fragment in forbidden_fragments:
        assert fragment not in content


def test_deploy_examples_exist_and_include_required_settings():
    service = Path("deploy/systemd/whut-license-server.service.example")
    nginx = Path("deploy/nginx/license.whutlogin.cn.conf.example")

    service_content = service.read_text(encoding="utf-8")
    nginx_content = nginx.read_text(encoding="utf-8")

    assert "WorkingDirectory=/opt/whut-campus-auto-login" in service_content
    assert "EnvironmentFile=/etc/whut-campus-auto-login/license-server.env" in service_content
    assert "/opt/whut-campus-auto-login/.venv/bin/uvicorn" in service_content
    assert "--host 127.0.0.1 --port 8787" in service_content
    assert "Restart=always" in service_content

    assert "server_name license.whutlogin.cn;" in nginx_content
    assert "listen 80;" in nginx_content
    assert "proxy_pass http://127.0.0.1:8787;" in nginx_content
    assert "/path/to/fullchain.pem" in nginx_content
    assert "/path/to/privkey.pem" in nginx_content
