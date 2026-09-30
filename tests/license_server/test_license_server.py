import base64
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from fastapi.testclient import TestClient
import pytest

from license_server.db import connect, initialize_database
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


def _client(tmp_path, **app_kwargs):
    private_key_b64 = _private_key_b64()
    app = create_app(
        database_path=tmp_path / "license.sqlite3",
        private_key_b64=private_key_b64,
        **app_kwargs,
    )
    return TestClient(app), _public_key_b64(private_key_b64)


def _register_payload(device_hash="device-a"):
    return {
        "product_id": "whut-campus-auto-login",
        "device_fingerprint_hash": device_hash,
    }


def _sqlite_url(path: Path) -> str:
    return "sqlite:///" + path.as_posix()


def _production_env(tmp_path, **overrides):
    env = {
        "LICENSE_SERVER_ENV": "production",
        "DATABASE_URL": _sqlite_url(tmp_path / "license.sqlite3"),
        "LICENSE_PRIVATE_KEY": _private_key_b64(),
    }
    env.update(overrides)
    return env


def test_health_endpoint_returns_service_status(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "license_server"}


def test_healthz_endpoint_returns_minimal_status(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    response_text = response.text
    assert "admin-token" not in response_text
    assert str(tmp_path) not in response_text


def test_default_app_health_works_without_sensitive_env(monkeypatch):
    monkeypatch.delenv("LICENSE_SERVER_ENV", raising=False)
    monkeypatch.delenv("SERVER_ENV", raising=False)
    monkeypatch.delenv("LICENSE_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("LICENSE_PRIVATE_KEY_FILE", raising=False)

    client = TestClient(_default_app())
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "license_server"}


def test_default_app_refuses_invalid_production_config(monkeypatch):
    monkeypatch.setenv("LICENSE_SERVER_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("LICENSE_DB_PATH", raising=False)
    monkeypatch.delenv("LICENSE_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("LICENSE_PRIVATE_KEY_FILE", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        _default_app()

    assert "DATABASE_URL or LICENSE_DB_PATH is required in production" in str(exc_info.value)


def test_load_config_accepts_development_mode(monkeypatch):
    monkeypatch.setenv("LICENSE_SERVER_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./license_server_dev.sqlite3")
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", _private_key_b64())

    config = load_config()

    assert config.environment == "development"
    assert config.database_path == Path("license_server_dev.sqlite3")


def test_load_config_accepts_test_mode_with_temporary_config(tmp_path):
    config = load_config(
        {
            "LICENSE_SERVER_ENV": "test",
            "DATABASE_URL": _sqlite_url(tmp_path / "license.sqlite3"),
            "LICENSE_PRIVATE_KEY": _private_key_b64(),
        }
    )

    assert config.environment == "test"
    assert config.database_path == tmp_path / "license.sqlite3"


def test_free_version_config_has_no_payment_settings(tmp_path):
    """免费版：服务端配置里不再有任何支付相关项。"""
    config = load_config(_production_env(tmp_path))

    for forbidden in (
        "payment_provider",
        "payment_mock_admin_token",
        "wechat_pay",
        "payment_price_fen",
        "payment_amount",
        "payment_currency",
        "payment_channels",
        "payment_order_ttl_minutes",
        "payment_notification_worker_enabled",
        "payment_reconciliation_worker_enabled",
    ):
        assert not hasattr(config, forbidden), forbidden


def test_load_config_ignores_legacy_payment_env(tmp_path):
    """历史 env 里残留的支付变量不再影响免费版启动。"""
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="wechat_native",
        PAYMENT_PRICE_FEN="991",
        PAYMENT_CURRENCY="USD",
        WECHAT_PAY_APP_ID="legacy-app-id",
    )

    config = load_config(env)

    assert config.environment == "production"
    assert config.database_path == tmp_path / "license.sqlite3"


def test_load_config_rejects_invalid_environment():
    with pytest.raises(RuntimeError) as exc_info:
        load_config({"LICENSE_SERVER_ENV": "staging"})

    assert "LICENSE_SERVER_ENV must be one of" in str(exc_info.value)


def test_production_requires_explicit_database(tmp_path):
    env = _production_env(tmp_path)
    env.pop("DATABASE_URL")
    env.pop("LICENSE_DB_PATH", None)

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    assert "DATABASE_URL or LICENSE_DB_PATH is required in production" in str(exc_info.value)


def test_production_database_path_must_be_absolute(tmp_path):
    env = _production_env(tmp_path, DATABASE_URL="sqlite:///relative-license.sqlite3")

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    assert "must be an absolute path in production" in str(exc_info.value)


def test_production_accepts_absolute_database_path(tmp_path):
    config = load_config(_production_env(tmp_path))

    assert config.environment == "production"
    assert config.database_path == tmp_path / "license.sqlite3"


def test_production_requires_private_key(tmp_path):
    env = _production_env(tmp_path)
    env.pop("LICENSE_PRIVATE_KEY")

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    assert "LICENSE_PRIVATE_KEY or LICENSE_PRIVATE_KEY_FILE is required" in str(exc_info.value)


def test_production_private_key_file_must_exist(tmp_path):
    missing_key_file = tmp_path / "missing-private-key.txt"
    env = _production_env(
        tmp_path,
        LICENSE_PRIVATE_KEY="",
        LICENSE_PRIVATE_KEY_FILE=str(missing_key_file),
    )

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    assert "Failed to read LICENSE_PRIVATE_KEY_FILE" in str(exc_info.value)
    assert str(missing_key_file) in str(exc_info.value)
    assert not missing_key_file.exists()


def test_production_private_key_file_must_be_valid(tmp_path):
    private_key_file = tmp_path / "private-key.txt"
    private_key_file.write_text("not-a-private-key", encoding="utf-8")
    env = _production_env(
        tmp_path,
        LICENSE_PRIVATE_KEY="",
        LICENSE_PRIVATE_KEY_FILE=str(private_key_file),
    )

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    message = str(exc_info.value)
    assert "LICENSE_PRIVATE_KEY_FILE must be a base64-encoded 32-byte Ed25519 private key" in message
    assert "not-a-private-key" not in message


def test_production_loads_valid_private_key_file(tmp_path):
    private_key_b64 = _private_key_b64()
    private_key_file = tmp_path / "private-key.txt"
    private_key_file.write_text(private_key_b64, encoding="utf-8")

    config = load_config(
        _production_env(
            tmp_path,
            LICENSE_PRIVATE_KEY="",
            LICENSE_PRIVATE_KEY_FILE=str(private_key_file),
        )
    )

    assert config.private_key_b64 == private_key_b64


def test_production_no_longer_requires_legacy_license_admin_token(tmp_path):
    config = load_config(_production_env(tmp_path))

    assert not hasattr(config, "admin_token")


def test_load_config_uses_relative_sqlite_database_url(monkeypatch):
    monkeypatch.setenv("LICENSE_SERVER_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./license_server_dev.sqlite3")
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", _private_key_b64())
    monkeypatch.delenv("LICENSE_DB_PATH", raising=False)

    config = load_config()

    assert config.database_path == Path("license_server_dev.sqlite3")


def test_load_config_uses_absolute_sqlite_database_url(monkeypatch):
    monkeypatch.setenv("LICENSE_SERVER_ENV", "development")
    monkeypatch.setenv(
        "DATABASE_URL",
        "sqlite:////var/lib/whut-campus-auto-login/license.sqlite3",
    )
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", _private_key_b64())
    monkeypatch.delenv("LICENSE_DB_PATH", raising=False)

    config = load_config()

    assert config.database_path.as_posix().endswith(
        "/var/lib/whut-campus-auto-login/license.sqlite3"
    )


def test_load_config_keeps_license_db_path_fallback(monkeypatch):
    monkeypatch.setenv("LICENSE_SERVER_ENV", "development")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("LICENSE_DB_PATH", "legacy-license.sqlite3")
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", _private_key_b64())

    config = load_config()

    assert config.database_path == Path("legacy-license.sqlite3")


def test_load_config_wraps_unreadable_private_key_file(monkeypatch, tmp_path):
    monkeypatch.setenv("LICENSE_SERVER_ENV", "development")
    missing_key_file = tmp_path / "missing-private-key.txt"
    monkeypatch.delenv("LICENSE_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("LICENSE_PRIVATE_KEY_FILE", str(missing_key_file))

    with pytest.raises(RuntimeError) as exc_info:
        load_config()

    assert "Failed to read LICENSE_PRIVATE_KEY_FILE" in str(exc_info.value)
    assert str(missing_key_file) in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, OSError)


def test_database_connection_enforces_license_device_foreign_key(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO licenses (
                    device_id, license_type, status, starts_at, expires_at,
                    source, order_id, created_at, revoked_at
                ) VALUES (999, 'free', 'active', ?, ?, 'free', NULL, ?, NULL)
                """,
                (
                    "2026-06-04T00:00:00Z",
                    "2026-06-18T00:00:00Z",
                    "2026-06-04T00:00:00Z",
                ),
            )


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
            "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')"
        )
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


def test_invalid_v1_orphan_license_fails_closed_without_changes(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')"
        )
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
    with sqlite3.connect(database_path) as connection:
        before_schema = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        before_licenses = connection.execute("SELECT * FROM licenses").fetchall()

    with pytest.raises(RuntimeError) as exc_info:
        initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0] == "1"
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'devices'"
        ).fetchone() is None
        assert connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall() == before_schema
        assert connection.execute("SELECT * FROM licenses").fetchall() == before_licenses
    assert str(exc_info.value) == "database schema does not match the free-version core schema"


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


def test_register_new_device_issues_free_license(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    response = client.post("/device/register", json=_register_payload())

    assert response.status_code == 200
    payload = response.json()
    assert payload["license_type"] == "free"
    assert payload["license_status"] == "active"
    assert payload["status"] == "free_active"
    assert payload["signed_license_token"]
    assert "device_name" not in payload
    assert "os" not in payload
    assert "app_version" not in payload
    # 免费版：永久免费，不再是 14 天试用
    assert payload["expires_at"] == "9999-12-31T00:00:00Z"


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


def test_register_existing_device_does_not_duplicate_license(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    first = client.post("/device/register", json=_register_payload()).json()
    second = client.post("/device/register", json=_register_payload()).json()

    assert second["license_id"] == first["license_id"]
    assert second["license_type"] == "free"


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


def test_legacy_admin_grant_route_is_removed(tmp_path):
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

    assert response.status_code == 404


def test_openapi_excludes_legacy_admin_grant_route(tmp_path):
    client, _public_key_b64_value = _client(tmp_path)

    schema = client.get("/openapi.json").json()

    assert "/admin/grant" not in schema["paths"]


def test_env_example_contains_only_placeholders():
    content = Path("license_server/.env.example").read_text(encoding="utf-8")

    assert "LICENSE_SERVER_ENV=development" in content
    assert "DATABASE_URL=sqlite:///ABSOLUTE_PATH_TO_LICENSE_SERVER_DB.sqlite3" in content
    assert "LICENSE_PRIVATE_KEY_FILE=ABSOLUTE_PATH_TO_ED25519_PRIVATE_KEY_B64_FILE" in content
    assert "LICENSE_SERVER_URL=http://127.0.0.1:8787" in content
    assert "LICENSE_PUBLIC_KEY=REPLACE_WITH_ED25519_PUBLIC_KEY_B64" in content
    assert "LICENSE_ADMIN_TOKEN" not in content
    assert "\nSERVER_ENV=" not in content
    assert "LICENSE_DB_PATH" not in content
    # 免费版：示例环境文件里不再有任何支付配置
    for payment_key in ("PAYMENT_PROVIDER", "WECHAT_PAY", "PAYMENT_PRICE_FEN", "PAYMENT_CURRENCY"):
        assert payment_key not in content
    forbidden_fragments = [
        "124.223.7.147",
        "license.whutlogin.cn",
        "BEGIN " + "PRIVATE KEY",
        "LICENSE_PRIVATE_KEY=",
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
    assert "/usr/local/libexec/whut-license-startup-gate" in service_content
    assert "/opt/whut-campus-auto-login/.venv/bin/python -I -m uvicorn" in service_content
    assert "--app-dir /opt/whut-campus-auto-login" in service_content
    assert "--host 127.0.0.1 --port 8787" in service_content
    assert "Restart=always" in service_content

    assert "server_name REPLACE_WITH_LICENSE_DOMAIN;" in nginx_content
    assert "listen 80;" in nginx_content
    assert "listen 443 ssl http2;" in nginx_content
    assert "location ^~ /internal/admin {" in nginx_content
    assert "return 404;" in nginx_content
    assert "proxy_pass http://127.0.0.1:8787;" in nginx_content
    assert "REPLACE_WITH_FULLCHAIN_PEM_PATH" in nginx_content
    assert "REPLACE_WITH_PRIVKEY_PEM_PATH" in nginx_content


def test_production_config_doc_exists_without_secrets():
    content = Path("docs/deploy/LICENSE_SERVER_PRODUCTION_CONFIG.md").read_text(
        encoding="utf-8"
    )

    assert "LICENSE_SERVER_ENV" in content
    assert "DATABASE_URL" in content
    assert "LICENSE_PRIVATE_KEY_FILE" in content
    assert "LICENSE_ADMIN_TOKEN" not in content
    assert "GET /healthz" in content
    assert "Nginx" in content
    forbidden_fragments = [
        "BEGIN " + "PRIVATE KEY",
        "replace_with_real",
        "license.whutlogin.cn",
        "124.223.7.147",
        "sk_",
    ]
    for fragment in forbidden_fragments:
        assert fragment not in content
