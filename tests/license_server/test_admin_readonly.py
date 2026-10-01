"""免费版后台只读接口测试。

旧版商业模块移除后，后台只保留 summary / devices / licenses / audit-logs 的只读
查询与设备、授权备注端点；旧版的 orders / notifications / grants 端点应
返回 404。本文件保持原有安全性质：认证明缺失或错误 401、缺少资源 404、非法
参数 400、分页边界、安全头、敏感字段不返回、只读查询不改库。

本文件的断言以 `license_server/admin_routes.py` 的真实响应结构为准。
"""

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

import license_server.admin_routes as admin_routes
from license_server.app import create_app
from license_server.db import connect
from license_server.signer import datetime_text
from tests.license_server.test_license_server import (
    _private_key_b64,
    _sqlite_url,
)


ADMIN_TOKEN = "p4-admin-token-with-randomish-value"
ADMIN_HASH = hashlib.sha256(ADMIN_TOKEN.encode("utf-8")).hexdigest()
ADMIN_PAGE = "/internal/admin/"
ADMIN_SCRIPT = "/internal/admin/assets/admin.js"
ADMIN_API = "/internal/admin/api/"
ADMIN_PAGE_TITLE = "管理后台"
FORBIDDEN_TEXT = (
    "provider_code_url",
    "raw_payload",
    "body_raw",
    "body_decrypted",
    "signed_token",
    "token",
    "campus_account",
    "campus_password",
    "password",
    "order_id",
    "out_trade_no",
)
ADMIN_HEADERS = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
}
EXPECTED_ADMIN_PATHS = {
    "/internal/admin/",
    "/internal/admin/assets/admin.js",
    "/internal/admin/api/summary",
    "/internal/admin/api/devices",
    "/internal/admin/api/devices/{device_fingerprint_hash}",
    "/internal/admin/api/devices/{device_fingerprint_hash}/notes",
    "/internal/admin/api/licenses",
    "/internal/admin/api/licenses/{license_id}/notes",
    "/internal/admin/api/audit-logs",
    "/internal/admin/api/audit-logs/{audit_id}",
}
REMOVED_PAYMENT_ENDPOINTS = (
    "/internal/admin/api/orders",
    "/internal/admin/api/orders/order-paid",
    "/internal/admin/api/orders/order-paid/notes",
    "/internal/admin/api/notifications",
    "/internal/admin/api/notifications/notice-b",
    "/internal/admin/api/notifications/notice-b/notes",
    "/internal/admin/api/grants",
    "/internal/admin/api/grants/1",
    "/internal/admin/api/grants/1/notes",
)
SUMMARY_FIELDS = {
    "devices_total",
    "devices_active_24h",
    "devices_active_7d",
    "devices_active_30d",
    "licenses_by_type",
    "licenses_by_status",
    "licenses_active_unexpired",
}
DEVICE_FIELDS = {
    "device_id_hash",
    "product_id",
    "first_seen_at",
    "last_seen_at",
    "license_id",
    "license_type",
    "license_status",
    "license_expires_at",
}
DEVICE_DETAIL_FIELDS = {
    "device_id_hash",
    "product_id",
    "first_seen_at",
    "last_seen_at",
    "licenses",
}
LICENSE_FIELDS = {
    "license_id",
    "license_type",
    "status",
    "starts_at",
    "expires_at",
    "source",
    "created_at",
    "revoked_at",
}
AUDIT_FIELDS = {
    "id",
    "actor",
    "source_ip",
    "request_id",
    "action",
    "target_type",
    "target_id",
    "result",
    "before_state",
    "after_state",
    "reason",
    "failure_code",
    "created_at",
}
FREE_EXPIRES_AT = "9999-12-31T00:00:00Z"


def _iter_effective_routes(routes):
    for route in routes:
        effective_route_contexts = getattr(
            route,
            "effective_route_contexts",
            None,
        )
        if callable(effective_route_contexts):
            yield from effective_route_contexts()
        else:
            yield route


def test_iter_effective_routes_expands_nested_route_contexts():
    class NestedRoutes:
        def effective_route_contexts(self):
            yield "nested-route"

    flat_route = object()

    assert list(_iter_effective_routes((flat_route, NestedRoutes()))) == [
        flat_route,
        "nested-route",
    ]


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

    page = client.get(ADMIN_PAGE)
    script = client.get(ADMIN_SCRIPT)
    api = client.get(ADMIN_API + "summary")

    assert page.status_code == 200
    assert script.status_code == 200
    assert api.status_code == 401
    assert ADMIN_PAGE_TITLE in page.text
    assert ADMIN_SCRIPT in page.text
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

    response = client.get(ADMIN_API + "summary", headers=headers)

    assert response.status_code == 401
    assert response.json()["detail"] in {"ADMIN_AUTH_REQUIRED", "ADMIN_AUTH_INVALID"}
    _assert_security_headers(response)
    _assert_no_sensitive_text(response.text)


def test_admin_auth_accepts_bearer_token_and_routes_are_hidden_from_openapi(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    response = client.get(ADMIN_API + "summary", headers=_auth())
    schema = client.get("/openapi.json").json()

    assert response.status_code == 200
    assert not any(path.startswith("/internal/admin") for path in schema["paths"])
    assert "/docs" not in response.text
    _assert_security_headers(response)


def test_all_admin_api_routes_require_bearer_token(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    for path in (
        ADMIN_API + "summary",
        ADMIN_API + "devices",
        ADMIN_API + "devices/device-a",
        ADMIN_API + "licenses",
        ADMIN_API + "audit-logs",
        ADMIN_API + "audit-logs/1",
    ):
        response = client.get(path)
        assert response.status_code == 401
        _assert_security_headers(response)

    for path in (
        ADMIN_API + "devices/device-a/notes",
        ADMIN_API + "licenses/1/notes",
    ):
        response = client.post(path, json={"note": "ok"})
        assert response.status_code == 401
        _assert_security_headers(response)


def test_admin_router_exposes_only_free_version_paths(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    admin_paths = {
        route.path
        for route in _iter_effective_routes(client.app.routes)
        if getattr(route, "path", "").startswith("/internal/admin")
    }

    assert admin_paths == EXPECTED_ADMIN_PATHS


def test_removed_payment_endpoints_are_gone(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    for path in REMOVED_PAYMENT_ENDPOINTS:
        with_token = client.get(path, headers=_auth())
        without_token = client.get(path)
        posted = client.post(path, headers=_auth(), json={"note": "ok"})
        for response in (with_token, without_token, posted):
            assert response.status_code == 404
            _assert_security_headers(response)


def test_admin_devices_and_licenses_filter_and_exclude_sensitive_fields(
    tmp_path,
    monkeypatch,
):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    devices = client.get(ADMIN_API + "devices", headers=_auth(), params={"limit": 200})
    device_detail = client.get(ADMIN_API + "devices/device-a", headers=_auth())
    licenses = client.get(
        ADMIN_API + "licenses",
        headers=_auth(),
        params={"device_id_hash": "device-a", "status": "active"},
    )
    revoked = client.get(
        ADMIN_API + "licenses",
        headers=_auth(),
        params={"device_id_hash": "device-b", "status": "revoked"},
    )
    by_product = client.get(
        ADMIN_API + "devices",
        headers=_auth(),
        params={"product_id": "whut-campus-auto-login"},
    )
    other_product = client.get(
        ADMIN_API + "devices",
        headers=_auth(),
        params={"product_id": "other-product"},
    )

    assert devices.status_code == 200
    assert devices.json()["limit"] == 100
    assert devices.json()["offset"] == 0
    items = devices.json()["items"]
    # 设备按 last_seen_at 倒序
    assert [row["device_id_hash"] for row in items] == [
        "device-fresh",
        "device-a",
        "device-b",
    ]
    for row in items:
        assert set(row) == DEVICE_FIELDS
        assert row["license_type"] == "free"
    assert items[0]["license_status"] == "active"
    assert items[0]["license_expires_at"] == FREE_EXPIRES_AT
    assert items[2]["license_status"] == "revoked"
    assert items[2]["license_id"] is not None

    assert [row["device_id_hash"] for row in by_product.json()["items"]] == [
        "device-fresh",
        "device-a",
        "device-b",
    ]
    assert other_product.json()["items"] == []

    assert device_detail.status_code == 200
    detail = device_detail.json()
    assert set(detail) == DEVICE_DETAIL_FIELDS
    assert detail["device_id_hash"] == "device-a"
    assert detail["product_id"] == "whut-campus-auto-login"
    assert [row["license_type"] for row in detail["licenses"]] == ["free"]
    assert detail["licenses"][0]["status"] == "active"
    assert set(detail["licenses"][0]) == LICENSE_FIELDS

    assert licenses.status_code == 200
    license_items = licenses.json()["items"]
    assert [row["status"] for row in license_items] == ["active"]
    assert license_items[0]["expires_at"] == FREE_EXPIRES_AT
    assert license_items[0]["license_type"] == "free"

    assert revoked.status_code == 200
    revoked_items = revoked.json()["items"]
    assert [row["status"] for row in revoked_items] == ["revoked"]
    assert revoked_items[0]["revoked_at"] is not None

    for response in (
        devices,
        device_detail,
        licenses,
        revoked,
        by_product,
        other_product,
    ):
        assert "order_id" not in response.text
        _assert_security_headers(response)
        _assert_no_sensitive_text(response.text)


def test_admin_devices_pagination_boundaries(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    first_page = client.get(
        ADMIN_API + "devices", headers=_auth(), params={"limit": 2, "offset": 0}
    )
    second_page = client.get(
        ADMIN_API + "devices", headers=_auth(), params={"limit": 2, "offset": 2}
    )
    beyond = client.get(
        ADMIN_API + "devices", headers=_auth(), params={"limit": 2, "offset": 4}
    )

    assert first_page.status_code == 200
    assert [row["device_id_hash"] for row in first_page.json()["items"]] == [
        "device-fresh",
        "device-a",
    ]
    assert second_page.status_code == 200
    assert [row["device_id_hash"] for row in second_page.json()["items"]] == ["device-b"]
    assert beyond.status_code == 200
    assert beyond.json()["items"] == []
    assert beyond.json()["offset"] == 4
    for response in (first_page, second_page, beyond):
        _assert_security_headers(response)


def test_admin_devices_seen_range_filters(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)

    recent = client.get(
        ADMIN_API + "devices",
        headers=_auth(),
        params={"seen_from": datetime_text(now - timedelta(days=61))},
    )
    older = client.get(
        ADMIN_API + "devices",
        headers=_auth(),
        params={"seen_to": datetime_text(now - timedelta(days=65))},
    )
    contradictory = client.get(
        ADMIN_API + "devices",
        headers=_auth(),
        params={
            "seen_from": datetime_text(now - timedelta(days=61)),
            "seen_to": datetime_text(now - timedelta(days=65)),
        },
    )
    both_bounds = client.get(
        ADMIN_API + "devices",
        headers=_auth(),
        params={
            "seen_from": datetime_text(now - timedelta(days=71)),
            "seen_to": datetime_text(now - timedelta(days=59)),
        },
    )

    assert [row["device_id_hash"] for row in recent.json()["items"]] == [
        "device-fresh",
        "device-a",
    ]
    assert [row["device_id_hash"] for row in older.json()["items"]] == ["device-b"]
    assert contradictory.json()["items"] == []
    assert [row["device_id_hash"] for row in both_bounds.json()["items"]] == [
        "device-a",
        "device-b",
    ]
    for response in (recent, older, contradictory, both_bounds):
        _assert_security_headers(response)


def test_unknown_device_query_parameter_is_ignored(tmp_path, monkeypatch):
    """支付时代才有的 active_within_hours 已不是过滤条件，参数被忽略。"""
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    response = client.get(
        ADMIN_API + "devices",
        headers=_auth(),
        params={"active_within_hours": "24"},
    )

    assert response.status_code == 200
    assert [row["device_id_hash"] for row in response.json()["items"]] == [
        "device-fresh",
        "device-a",
        "device-b",
    ]


def test_admin_summary_reports_free_version_stats(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    response = client.get(ADMIN_API + "summary", headers=_auth())

    assert response.status_code == 200
    body = response.json()
    assert set(body) == SUMMARY_FIELDS
    assert body["devices_total"] == 3
    assert body["devices_active_24h"] == 1
    assert body["devices_active_7d"] == 1
    assert body["devices_active_30d"] == 1
    assert body["licenses_by_type"] == {"free": 3}
    assert body["licenses_by_status"] == {"active": 2, "revoked": 1}
    assert body["licenses_active_unexpired"] == 2
    assert "orders_by_status" not in body
    assert "license_grants_total" not in body
    _assert_no_sensitive_text(response.text)
    _assert_security_headers(response)


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/internal/admin/api/devices", {"seen_from": "not-a-date"}),
        ("/internal/admin/api/devices", {"seen_to": "2026-07-06T00:00:00"}),
        ("/internal/admin/api/devices", {"limit": 0}),
        ("/internal/admin/api/devices", {"offset": -1}),
        ("/internal/admin/api/licenses", {"status": "deleted"}),
        ("/internal/admin/api/licenses", {"expires_from": "not-a-date"}),
        ("/internal/admin/api/licenses", {"limit": 0}),
        ("/internal/admin/api/licenses", {"offset": -1}),
        ("/internal/admin/api/audit-logs", {"result": "BOGUS"}),
        ("/internal/admin/api/audit-logs", {"created_to": "not-a-date"}),
        ("/internal/admin/api/audit-logs", {"limit": 0}),
        ("/internal/admin/api/audit-logs", {"offset": -1}),
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
        ADMIN_API + "devices/missing-device-hash",
        ADMIN_API + "audit-logs/999",
    ):
        response = client.get(path, headers=_auth())
        assert response.status_code == 404
        assert response.json()["detail"] == "ADMIN_RESOURCE_NOT_FOUND"
        _assert_security_headers(response)


def test_admin_note_post_endpoints_append_audit_rows(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    device_note = client.post(
        ADMIN_API + "devices/device-a/notes",
        headers=_auth(),
        json={"note": "复核设备活跃记录"},
    )
    license_note = client.post(
        ADMIN_API + "licenses/1/notes",
        headers=_auth(),
        json={"note": "复核免费授权状态"},
    )

    assert device_note.status_code == 201
    device_body = device_note.json()
    assert set(device_body) == AUDIT_FIELDS
    assert device_body["actor"] == "tester"
    assert device_body["action"] == "DEVICE_NOTE_ADDED"
    assert device_body["target_type"] == "DEVICE"
    assert device_body["target_id"] == "device-a"
    assert device_body["result"] == "SUCCESS"
    assert device_body["before_state"] is None
    assert device_body["after_state"] is None
    assert license_note.status_code == 201
    assert license_note.json()["action"] == "LICENSE_NOTE_ADDED"
    assert license_note.json()["target_type"] == "LICENSE"

    audit = client.get(ADMIN_API + "audit-logs", headers=_auth())
    items = audit.json()["items"]
    assert [row["action"] for row in items] == ["LICENSE_NOTE_ADDED", "DEVICE_NOTE_ADDED"]

    device_only = client.get(
        ADMIN_API + "audit-logs", headers=_auth(), params={"target_type": "DEVICE"}
    )
    assert [row["target_id"] for row in device_only.json()["items"]] == ["device-a"]

    audit_page = client.get(
        ADMIN_API + "audit-logs", headers=_auth(), params={"limit": 1, "offset": 1}
    )
    assert [row["action"] for row in audit_page.json()["items"]] == ["DEVICE_NOTE_ADDED"]

    detail = client.get(ADMIN_API + f"audit-logs/{items[0]['id']}", headers=_auth())
    assert detail.status_code == 200
    assert detail.json()["reason"] == "复核免费授权状态"

    for response in (device_note, license_note, audit, device_only, audit_page, detail):
        _assert_no_sensitive_text(response.text)
        _assert_security_headers(response)


def test_admin_summary_and_page_have_security_headers(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    summary = client.get(ADMIN_API + "summary", headers=_auth())
    page = client.get(ADMIN_PAGE)
    script = client.get(ADMIN_SCRIPT)

    assert summary.status_code == 200
    assert "orders_by_status" not in summary.text
    assert "license_grants_total" not in summary.text
    assert page.status_code == 200
    assert script.status_code == 200
    assert ADMIN_PAGE_TITLE in page.text
    assert "sessionStorage" in page.text
    assert "localStorage" not in page.text
    combined = page.text + script.text
    assert "订单" not in combined
    assert "支付" not in combined
    for response in (summary, page, script):
        _assert_security_headers(response)
    for response in (page, script):
        assert "unsafe-inline" not in response.headers["content-security-policy"]
    assert "http://" not in combined
    assert "https://" not in combined


@pytest.mark.parametrize(
    "helper",
    ["_count", "_count_by", "_count_devices_seen_since"],
)
def test_admin_summary_maps_stats_helper_sqlite_errors(tmp_path, monkeypatch, helper):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    def fail_stats_query(*_args, **_kwargs):
        raise sqlite3.OperationalError("summary query failed")

    monkeypatch.setattr(admin_routes, helper, fail_stats_query)
    response = client.get(ADMIN_API + "summary", headers=_auth())

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
    response = client.get(ADMIN_API + "summary", headers=_auth())

    assert response.status_code == 500
    assert response.json() == {"detail": "ADMIN_INTERNAL_ERROR"}
    _assert_security_headers(response)


def test_admin_script_uses_session_storage_and_authorized_same_origin_api_only(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    script = client.get(ADMIN_SCRIPT).text

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
    assert 'credentials: "omit"' in script
    assert "管理员令牌无效或已失效。" in script


def test_admin_script_avoids_unsafe_dom_injection_and_has_basic_controls(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    page = client.get(ADMIN_PAGE).text
    script = client.get(ADMIN_SCRIPT).text

    for forbidden in (
        "innerHTML",
        "insertAdjacentHTML",
        "document.write",
        "response.text",
        "response.body",
    ):
        assert forbidden not in page
        assert forbidden not in script
    assert "textContent" in script
    assert "document.createElement" in script
    for expected in (
        'id="admin-secret"',
        'id="save-secret"',
        'id="clear-secret"',
        'id="load-summary"',
        'id="summary-output"',
        'id="devices-device-id"',
        'id="devices-product-id"',
        'id="devices-load"',
        'id="devices-prev"',
        'id="devices-next"',
        'id="devices-page"',
        'id="devices-output"',
        'id="licenses-device-id"',
        'id="licenses-status"',
        'id="licenses-load"',
        'id="licenses-prev"',
        'id="licenses-next"',
        'id="licenses-page"',
        'id="licenses-output"',
        'id="audit-target-type"',
        'id="audit-target-id"',
        'id="audit-action"',
        'id="audit-result"',
        'id="audit-request-id"',
        'id="audit-created-from"',
        'id="audit-created-to"',
        'id="audit-load"',
        'id="audit-prev"',
        'id="audit-next"',
        'id="audit-page"',
        'id="audit-output"',
        'id="audit-detail-output"',
        'id="device-detail-hash"',
        'id="device-detail-load"',
        'id="device-detail-output"',
        'id="device-note-device-id"',
        'id="device-note-text"',
        'id="device-note-submit"',
        'id="device-note-status"',
        'id="license-note-license-id"',
        'id="license-note-text"',
        'id="license-note-submit"',
        'id="license-note-status"',
    ):
        assert expected in page
    for removed_prefix in ("orders-", "notifications-", "grants-", "order-note-", "payment-"):
        assert f'id="{removed_prefix}' not in page
    assert "rows.length === 0 && direction > 0" in script


def test_admin_router_only_exposes_note_post_and_queries_do_not_modify_database(
    tmp_path,
    monkeypatch,
):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)
    before_bytes = database_path.read_bytes()
    before_counts = _table_counts(database_path)

    write_routes = {
        (route.path, method)
        for route in _iter_effective_routes(client.app.routes)
        if getattr(route, "path", "").startswith("/internal/admin")
        for method in getattr(route, "methods", set())
        if method not in {"GET", "HEAD"}
    }
    for path in (
        ADMIN_API + "summary",
        ADMIN_API + "devices",
        ADMIN_API + "devices/device-a",
        ADMIN_API + "devices/missing-device-hash",
        ADMIN_API + "licenses",
        ADMIN_API + "audit-logs",
        ADMIN_API + "audit-logs/1",
        ADMIN_API + "audit-logs/999",
        ADMIN_API + "orders",
        ADMIN_API + "notifications",
        ADMIN_API + "grants",
    ):
        response = client.get(path, headers=_auth())
        assert response.status_code in {200, 404}

    assert write_routes == {
        ("/internal/admin/api/devices/{device_fingerprint_hash}/notes", "POST"),
        ("/internal/admin/api/licenses/{license_id}/notes", "POST"),
    }
    assert database_path.read_bytes() == before_bytes
    assert _table_counts(database_path) == before_counts


def test_nginx_example_blocks_internal_admin_before_public_proxy():
    config = Path("deploy/nginx/license.whutlogin.cn.conf.example").read_text(encoding="utf-8")

    assert "location ^~ /internal/admin" in config
    assert config.index("location ^~ /internal/admin") < config.index("location /")


def _client(tmp_path, **app_kwargs):
    from tests.license_server.test_license_server import _client as _license_server_client

    return _license_server_client(tmp_path, **app_kwargs)


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
    """免费版夹具：3 台设备 + free 授权（1 条 revoked），不触碰支付遗留表。"""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    stamps = {
        "a_first": datetime_text(now - timedelta(days=90)),
        "a_seen": datetime_text(now - timedelta(days=60)),
        "b_first": datetime_text(now - timedelta(days=95)),
        "b_seen": datetime_text(now - timedelta(days=70)),
        "fresh_first": datetime_text(now - timedelta(hours=2)),
        "fresh_seen": datetime_text(now - timedelta(hours=1)),
    }
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (
                product_id, device_fingerprint_hash, first_seen_at, last_seen_at
            ) VALUES
                ('whut-campus-auto-login', 'device-a', ?, ?),
                ('whut-campus-auto-login', 'device-b', ?, ?),
                ('whut-campus-auto-login', 'device-fresh', ?, ?)
            """,
            (
                stamps["a_first"],
                stamps["a_seen"],
                stamps["b_first"],
                stamps["b_seen"],
                stamps["fresh_first"],
                stamps["fresh_seen"],
            ),
        )
        connection.execute(
            """
            INSERT INTO licenses (
                device_id, license_type, status, starts_at, expires_at, source,
                order_id, created_at, revoked_at
            ) VALUES
                (1, 'free', 'active', ?, ?, 'free', NULL, ?, NULL),
                (2, 'free', 'revoked', ?, ?, 'free', NULL, ?, ?),
                (3, 'free', 'active', ?, ?, 'free', NULL, ?, NULL)
            """,
            (
                stamps["a_first"],
                FREE_EXPIRES_AT,
                stamps["a_first"],
                stamps["b_first"],
                FREE_EXPIRES_AT,
                stamps["b_first"],
                stamps["b_seen"],
                stamps["fresh_first"],
                FREE_EXPIRES_AT,
                stamps["fresh_first"],
            ),
        )
    return stamps


def _table_counts(database_path):
    with connect(database_path) as connection:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("devices", "licenses", "admin_audit_logs", "schema_meta")
        }


def _assert_security_headers(response):
    for name, value in ADMIN_HEADERS.items():
        assert response.headers[name] == value


def _assert_no_sensitive_text(text: str):
    lowered = text.lower()
    for forbidden in FORBIDDEN_TEXT:
        assert forbidden not in lowered