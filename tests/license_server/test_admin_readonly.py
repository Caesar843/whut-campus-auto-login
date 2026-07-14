import hashlib
from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

import license_server.admin_routes as admin_routes
from license_server.app import create_app
from license_server.db import connect
from tests.license_server.test_license_server import (
    _client,
    _private_key_b64,
    _sqlite_url,
)


ADMIN_TOKEN = "p4-admin-token-with-randomish-value"
ADMIN_HASH = hashlib.sha256(ADMIN_TOKEN.encode("utf-8")).hexdigest()
FORBIDDEN_TEXT = (
    "provider_code_url",
    "raw_payload",
    "body_raw",
    "body_decrypted",
    "openid",
    "bank_type",
    "signed_token",
    "token",
    "campus_account",
    "campus_password",
    "password",
)
ADMIN_HEADERS = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
}


def test_admin_is_disabled_by_default_and_public_api_still_works(tmp_path):
    client, _public_key = _client(tmp_path)

    assert client.get("/internal/admin/").status_code == 404
    assert client.get("/internal/admin/assets/admin.js").status_code == 404
    assert client.get("/internal/admin/api/summary").status_code == 404
    assert client.get("/health").status_code == 200


def test_admin_enabled_requires_valid_access_token_hash(tmp_path, monkeypatch):
    _set_admin_env(tmp_path, monkeypatch, access_hash="")
    with pytest.raises(RuntimeError, match="ADMIN_ACCESS_TOKEN_SHA256"):
        create_app()

    _set_admin_env(tmp_path, monkeypatch, access_hash="not-a-sha256")
    with pytest.raises(RuntimeError, match="ADMIN_ACCESS_TOKEN_SHA256"):
        create_app()


def test_admin_enabled_rejects_invalid_flag_value(tmp_path, monkeypatch):
    _set_admin_env(tmp_path, monkeypatch)
    monkeypatch.setenv("ADMIN_ENABLED", "maybe")

    with pytest.raises(RuntimeError, match="ADMIN_ENABLED"):
        create_app()


def test_admin_page_and_script_load_without_bearer_but_api_does_not(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    page = client.get("/internal/admin/")
    script = client.get("/internal/admin/assets/admin.js")
    api = client.get("/internal/admin/api/summary")

    assert page.status_code == 200
    assert script.status_code == 200
    assert api.status_code == 401
    assert "/internal/admin/assets/admin.js" in page.text
    assert ADMIN_TOKEN not in page.text
    assert ADMIN_HASH not in page.text
    assert ADMIN_TOKEN not in script.text
    assert ADMIN_HASH not in script.text
    for response in (page, script, api):
        _assert_security_headers(response)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer    "},
        {"Authorization": "Bearer alpha beta"},
        {"Authorization": "Bearer wrong-admin-token"},
    ],
)
def test_admin_auth_rejects_missing_malformed_and_wrong_tokens(tmp_path, monkeypatch, headers):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    response = client.get("/internal/admin/api/summary", headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] in {"ADMIN_AUTH_REQUIRED", "ADMIN_AUTH_INVALID"}
    _assert_security_headers(response)
    _assert_no_sensitive_text(response.text)


def test_admin_auth_accepts_bearer_token_and_routes_are_hidden_from_openapi(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    response = client.get("/internal/admin/api/summary", headers=_auth())
    schema = client.get("/openapi.json").json()

    assert response.status_code == 200
    assert not any(path.startswith("/internal/admin") for path in schema["paths"])
    assert "/docs" not in response.text
    _assert_security_headers(response)


def test_all_admin_api_routes_require_bearer_token(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    for path in (
        "/internal/admin/api/summary",
        "/internal/admin/api/orders",
        "/internal/admin/api/orders/missing",
        "/internal/admin/api/notifications",
        "/internal/admin/api/notifications/missing",
        "/internal/admin/api/grants",
        "/internal/admin/api/licenses",
    ):
        response = client.get(path)
        assert response.status_code == 401
        _assert_security_headers(response)


def test_admin_queries_filter_page_and_exclude_sensitive_fields(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    orders = client.get(
        "/internal/admin/api/orders",
        headers=_auth(),
        params={"status": "PAID", "created_from": "2026-07-06T00:00:00Z", "limit": 200},
    )
    order_detail = client.get("/internal/admin/api/orders/order-paid", headers=_auth())
    notifications = client.get(
        "/internal/admin/api/notifications",
        headers=_auth(),
        params={"process_status": "ABNORMAL", "signature_valid": "false"},
    )
    notification_detail = client.get("/internal/admin/api/notifications/notice-b", headers=_auth())
    grants = client.get(
        "/internal/admin/api/grants",
        headers=_auth(),
        params={"source_order_id": "order-paid"},
    )
    licenses = client.get(
        "/internal/admin/api/licenses",
        headers=_auth(),
        params={"device_id_hash": "device-a", "status": "active"},
    )

    assert orders.status_code == 200
    assert orders.json()["limit"] == 100
    assert [row["order_id"] for row in orders.json()["items"]] == ["order-paid"]
    assert order_detail.status_code == 200
    assert order_detail.json()["order_id"] == "order-paid"
    assert notifications.status_code == 200
    assert [row["provider_notification_id"] for row in notifications.json()["items"]] == ["notice-b"]
    assert notification_detail.status_code == 200
    assert notification_detail.json()["process_status"] == "ABNORMAL"
    assert grants.status_code == 200
    assert grants.json()["items"][0]["new_expire_at"] == "2027-07-06T00:00:00Z"
    assert licenses.status_code == 200
    assert licenses.json()["items"][0]["device_id_hash"] == "device-a"
    for response in (orders, order_detail, notifications, notification_detail, grants, licenses):
        _assert_security_headers(response)
        _assert_no_sensitive_text(response.text)


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/internal/admin/api/orders", {"status": "SUCCESS"}),
        ("/internal/admin/api/orders", {"created_from": "not-a-date"}),
        ("/internal/admin/api/notifications", {"process_status": "DONE"}),
        ("/internal/admin/api/notifications", {"signature_valid": "maybe"}),
        ("/internal/admin/api/licenses", {"status": "deleted"}),
        ("/internal/admin/api/grants", {"created_to": "not-a-date"}),
        ("/internal/admin/api/orders", {"offset": -1}),
        ("/internal/admin/api/notifications", {"offset": -1}),
        ("/internal/admin/api/grants", {"offset": -1}),
        ("/internal/admin/api/licenses", {"offset": -1}),
    ],
)
def test_admin_queries_reject_invalid_filters(tmp_path, monkeypatch, path, params):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    response = client.get(path, headers=_auth(), params=params)

    assert response.status_code == 400
    assert response.json()["detail"] == "ADMIN_QUERY_INVALID"
    _assert_security_headers(response)


def test_admin_details_return_404_for_missing_resources(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    for path in (
        "/internal/admin/api/orders/missing",
        "/internal/admin/api/notifications/999",
    ):
        response = client.get(path, headers=_auth())
        assert response.status_code == 404
        assert response.json()["detail"] == "ADMIN_RESOURCE_NOT_FOUND"
        _assert_security_headers(response)


def test_admin_summary_and_page_have_security_headers(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    summary = client.get("/internal/admin/api/summary", headers=_auth())
    page = client.get("/internal/admin/")
    script = client.get("/internal/admin/assets/admin.js")

    assert summary.status_code == 200
    assert summary.json()["orders_by_status"]["PAID"] == 1
    assert summary.json()["license_grants_total"] == 1
    assert page.status_code == 200
    assert script.status_code == 200
    assert "sessionStorage" in page.text
    assert "localStorage" not in page.text
    assert "unsafe-inline" not in page.headers["content-security-policy"]
    assert "unsafe-inline" not in script.headers["content-security-policy"]
    assert "http://" not in page.text
    assert "https://" not in page.text
    assert "http://" not in script.text
    assert "https://" not in script.text
    for response in (summary, page, script):
        _assert_security_headers(response)


@pytest.mark.parametrize("helper", ["_count_by", "_count"])
def test_admin_summary_maps_stats_helper_sqlite_errors(tmp_path, monkeypatch, helper):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    def fail_stats_query(*_args):
        raise sqlite3.OperationalError("summary query failed")

    monkeypatch.setattr(admin_routes, helper, fail_stats_query)
    response = client.get("/internal/admin/api/summary", headers=_auth())

    assert response.status_code == 500
    assert response.json() == {"detail": "ADMIN_INTERNAL_ERROR"}
    _assert_security_headers(response)


def test_admin_summary_maps_direct_sqlite_query_error(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    class FailingConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, *_args):
            raise sqlite3.OperationalError("summary query failed")

    monkeypatch.setattr(admin_routes, "_connection", lambda _database_path: FailingConnection())
    monkeypatch.setattr(admin_routes, "_count_by", lambda *_args: {})
    monkeypatch.setattr(admin_routes, "_count", lambda *_args: 0)
    response = client.get("/internal/admin/api/summary", headers=_auth())

    assert response.status_code == 500
    assert response.json() == {"detail": "ADMIN_INTERNAL_ERROR"}
    _assert_security_headers(response)


def test_admin_script_uses_session_storage_and_authorized_same_origin_api_only(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    script = client.get("/internal/admin/assets/admin.js").text

    assert "sessionStorage.setItem" in script
    assert "sessionStorage.getItem" in script
    assert "sessionStorage.removeItem" in script
    assert "localStorage" not in script
    assert "document.cookie" not in script
    assert "window.location" not in script
    assert "console.log" not in script
    assert "Authorization" in script
    assert '"Bearer "' in script
    assert 'const API_BASE = "/internal/admin/api/"' in script
    assert "path.startsWith(API_BASE)" in script
    assert "fetch(path" in script
    assert "管理员令牌无效或已失效。" in script


def test_admin_script_avoids_unsafe_dom_injection_and_has_basic_controls(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    page = client.get("/internal/admin/").text
    script = client.get("/internal/admin/assets/admin.js").text

    for forbidden in ("innerHTML", "insertAdjacentHTML", "document.write"):
        assert forbidden not in page
        assert forbidden not in script
    assert "textContent" in script
    assert "document.createElement" in script
    for expected in (
        'id="admin-secret"',
        'id="save-secret"',
        'id="clear-secret"',
        'id="load-summary"',
        'id="orders-load"',
        'id="notifications-load"',
        'id="grants-load"',
        'id="licenses-load"',
        'id="orders-next"',
        'id="notifications-next"',
        'id="grants-next"',
        'id="licenses-next"',
    ):
        assert expected in page
    assert "rows.length === 0 && direction > 0" in script


def test_admin_router_only_exposes_note_post_and_queries_do_not_modify_database(
    tmp_path,
    monkeypatch,
):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)
    before = _table_counts(database_path)
    before_paid = _paid_license_expires(database_path)

    write_routes = {
        (route.path, method)
        for route in client.app.routes
        if getattr(route, "path", "").startswith("/internal/admin")
        for method in getattr(route, "methods", set())
        if method not in {"GET", "HEAD"}
    }
    client.get("/internal/admin/api/orders", headers=_auth())
    client.get("/internal/admin/api/notifications", headers=_auth())
    client.get("/internal/admin/api/grants", headers=_auth())
    client.get("/internal/admin/api/licenses", headers=_auth())
    client.get("/internal/admin/api/audit-logs", headers=_auth())

    assert write_routes == {
        ("/internal/admin/api/orders/{order_id}/notes", "POST"),
    }
    assert _table_counts(database_path) == before
    assert _paid_license_expires(database_path) == before_paid


def test_nginx_example_blocks_internal_admin_before_public_proxy():
    config = Path("deploy/nginx/license.whutlogin.cn.conf.example").read_text(encoding="utf-8")

    assert "location ^~ /internal/admin" in config
    assert config.index("location ^~ /internal/admin") < config.index("location /")


def _admin_client(tmp_path, monkeypatch):
    _set_admin_env(tmp_path, monkeypatch)
    app = create_app()
    return TestClient(app), tmp_path / "license.sqlite3"


def _set_admin_env(tmp_path, monkeypatch, *, access_hash=ADMIN_HASH):
    monkeypatch.setenv("LICENSE_SERVER_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", _sqlite_url(tmp_path / "license.sqlite3"))
    monkeypatch.setenv("LICENSE_PRIVATE_KEY", _private_key_b64())
    monkeypatch.setenv("ADMIN_ENABLED", "true")
    monkeypatch.setenv("ADMIN_OPERATOR_NAME", "tester")
    if access_hash is None:
        monkeypatch.delenv("ADMIN_ACCESS_TOKEN_SHA256", raising=False)
    else:
        monkeypatch.setenv("ADMIN_ACCESS_TOKEN_SHA256", access_hash)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _seed_admin_rows(database_path):
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (
                product_id, device_fingerprint_hash, first_seen_at, last_seen_at
            ) VALUES
                ('whut-campus-auto-login', 'device-a', '2026-07-06T00:00:00Z', '2026-07-06T00:10:00Z'),
                ('whut-campus-auto-login', 'device-b', '2026-07-06T00:00:00Z', '2026-07-06T00:10:00Z')
            """
        )
        connection.execute(
            """
            INSERT INTO licenses (
                device_id, license_type, status, starts_at, expires_at, source,
                order_id, created_at, revoked_at
            ) VALUES
                (1, 'paid', 'active', '2026-07-06T00:00:00Z', '2027-07-06T00:00:00Z',
                 'payment', 'order-paid', '2026-07-06T00:00:00Z', NULL),
                (2, 'trial', 'active', '2026-07-06T00:00:00Z', '2026-07-20T00:00:00Z',
                 'trial', NULL, '2026-07-06T00:00:00Z', NULL)
            """
        )
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, provider_order_id,
                provider_transaction_id, provider_trade_state, created_at,
                updated_at, expires_at, paid_at, closed_at, security_error_code
            ) VALUES
                ('order-waiting', 'device-a', 'annual_v1', 990, 'CNY', 'mock',
                 'WAITING_PAYMENT', 'open', 'provider-waiting', NULL,
                 'MOCK_WAITING_PAYMENT', '2026-07-06T00:00:00Z',
                 '2026-07-06T00:00:00Z', '2026-07-06T00:15:00Z', NULL, NULL, NULL),
                ('order-paid', 'device-a', 'annual_v1', 990, 'CNY', 'mock',
                 'PAID', NULL, 'provider-paid', 'txn-paid', 'SUCCESS',
                 '2026-07-06T00:05:00Z', '2026-07-06T00:06:00Z',
                 '2026-07-06T00:20:00Z', '2026-07-06T00:06:00Z', NULL, NULL),
                ('order-abnormal', 'device-b', 'annual_v1', 990, 'CNY', 'mock',
                 'ABNORMAL', 'open', 'provider-abnormal', NULL, 'FAIL',
                 '2026-07-06T00:03:00Z', '2026-07-06T00:04:00Z',
                 '2026-07-06T00:18:00Z', NULL, NULL, 'amount_mismatch')
            """
        )
        connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, order_id, out_trade_no, provider,
                provider_transaction_id, event_type, signature_key_id,
                signature_valid, payload_digest_sha256, reported_trade_type,
                reported_trade_state, reported_amount_fen, reported_currency,
                merchant_identity_valid, process_status, security_error_code,
                failure_code, provider_created_at, received_at, processed_at,
                attempt_count
            ) VALUES
                ('notice-a', 'order-paid', 'order-paid', 'mock', 'txn-paid',
                 'TRANSACTION.SUCCESS', 'serial-a', 1, 'digest-a', 'NATIVE',
                 'SUCCESS', 990, 'CNY', 1, 'PROCESSED', NULL, NULL,
                 '2026-07-06T00:06:00Z', '2026-07-06T00:06:01Z',
                 '2026-07-06T00:06:02Z', 1),
                ('notice-b', 'order-abnormal', 'order-abnormal', 'mock', 'txn-b',
                 'TRANSACTION.SUCCESS', 'serial-b', 0, 'digest-b', 'NATIVE',
                 'SUCCESS', 1, 'CNY', 1, 'ABNORMAL', 'amount_mismatch',
                 'amount_mismatch', '2026-07-06T00:07:00Z',
                 '2026-07-06T00:07:01Z', '2026-07-06T00:07:02Z', 2)
            """
        )
        connection.execute(
            """
            INSERT INTO license_grants (
                source_order_id, device_fingerprint_hash, license_id,
                product_code, grant_days, previous_expire_at, new_expire_at,
                granted_at, issued_by
            ) VALUES (
                'order-paid', 'device-a', 1, 'annual_v1', 365, NULL,
                '2027-07-06T00:00:00Z', '2026-07-06T00:06:00Z', 'mock'
            )
            """
        )
        connection.commit()


def _table_counts(database_path):
    with connect(database_path) as connection:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "devices",
                "licenses",
                "payment_orders",
                "payment_notifications",
                "license_grants",
            )
        }


def _paid_license_expires(database_path):
    with connect(database_path) as connection:
        return connection.execute(
            "SELECT expires_at FROM licenses WHERE license_type = 'paid' ORDER BY id"
        ).fetchall()


def _assert_security_headers(response):
    for name, value in ADMIN_HEADERS.items():
        assert response.headers[name] == value


def _assert_no_sensitive_text(text: str):
    lowered = text.lower()
    for forbidden in FORBIDDEN_TEXT:
        assert forbidden not in lowered
