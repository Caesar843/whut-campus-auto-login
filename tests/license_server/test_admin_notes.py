from datetime import datetime
import sqlite3

import pytest
from fastapi.testclient import TestClient

import license_server.admin_routes as admin_routes
from license_server.admin_audit import AdminAuditEntry, AuditResult, record_admin_audit
from license_server.app import create_app
from license_server.db import connect
from tests.license_server.test_admin_readonly import (
    _admin_client,
    _assert_no_sensitive_text,
    _assert_security_headers,
    _auth,
    _seed_admin_rows,
    _set_admin_env,
)


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


def test_new_admin_routes_require_bearer_and_stay_out_of_openapi(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    for method, path, kwargs in (
        (client.get, "/internal/admin/api/audit-logs", {}),
        (client.get, "/internal/admin/api/audit-logs/1", {}),
        (client.post, "/internal/admin/api/devices/device-a/notes", {"json": {"note": "check"}}),
    ):
        response = method(path, **kwargs)
        assert response.status_code == 401
        _assert_security_headers(response)

    assert not any(
        path.startswith("/internal/admin")
        for path in client.get("/openapi.json").json()["paths"]
    )
    assert client.post("/admin/grant", json={}).status_code == 404


def test_audit_list_filters_sorts_pages_and_detail_uses_safe_fields(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)
    first_id = _record(
        database_path,
        request_id="request-a",
        target_id="device-a",
        action="DEVICE_REVIEWED",
        result=AuditResult.SUCCESS,
        created_at="2026-07-10T08:00:00Z",
    )
    second_id = _record(
        database_path,
        request_id="request-b",
        target_id="device-a",
        action="DEVICE_NOTE_ADDED",
        result=AuditResult.SUCCESS,
        created_at="2026-07-10T09:00:00Z",
    )
    third_id = _record(
        database_path,
        request_id="request-c",
        target_type="LICENSE",
        target_id="1",
        action="DEVICE_NOTE_ADDED",
        result=AuditResult.REJECTED,
        created_at="2026-07-10T10:00:00Z",
    )

    response = client.get(
        "/internal/admin/api/audit-logs",
        headers=_auth(),
        params={
            "target_type": "DEVICE",
            "target_id": "device-a",
            "action": "DEVICE_NOTE_ADDED",
            "result": "SUCCESS",
            "request_id": "request-b",
            "created_from": "2026-07-10T08:30:00Z",
            "created_to": "2026-07-10T09:30:00Z",
            "limit": 200,
            "offset": 0,
        },
    )

    assert response.status_code == 200
    assert response.json()["limit"] == 100
    assert [item["id"] for item in response.json()["items"]] == [second_id]
    assert set(response.json()["items"][0]) == AUDIT_FIELDS
    _assert_no_sensitive_text(response.text)
    _assert_security_headers(response)

    page = client.get(
        "/internal/admin/api/audit-logs",
        headers=_auth(),
        params={"limit": 1, "offset": 1},
    )
    assert page.status_code == 200
    assert [item["id"] for item in page.json()["items"]] == [second_id]

    detail = client.get(f"/internal/admin/api/audit-logs/{first_id}", headers=_auth())
    assert detail.status_code == 200
    assert detail.json()["id"] == first_id
    assert detail.json()["before_state"] == {"license_status": "active"}
    assert set(detail.json()) == AUDIT_FIELDS
    _assert_security_headers(detail)

    assert client.get("/internal/admin/api/audit-logs/99999", headers=_auth()).status_code == 404
    assert client.get(
        "/internal/admin/api/audit-logs", headers=_auth(), params={"offset": -1}
    ).status_code == 400

    expected_filters = (
        ({"target_type": "DEVICE"}, [second_id, first_id]),
        ({"target_id": "device-a"}, [second_id, first_id]),
        ({"action": "DEVICE_REVIEWED"}, [first_id]),
        ({"result": "REJECTED"}, [third_id]),
        ({"request_id": "request-b"}, [second_id]),
        ({"created_from": "2026-07-10T09:30:00Z"}, [third_id]),
        ({"created_to": "2026-07-10T08:30:00Z"}, [first_id]),
    )
    for params, expected_ids in expected_filters:
        filtered = client.get(
            "/internal/admin/api/audit-logs",
            headers=_auth(),
            params=params,
        )
        assert [item["id"] for item in filtered.json()["items"]] == expected_ids


def test_equal_created_at_sorts_by_id_desc(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    first = _record(database_path, request_id="same-time-a")
    second = _record(database_path, request_id="same-time-b")

    response = client.get("/internal/admin/api/audit-logs", headers=_auth())

    assert [item["id"] for item in response.json()["items"]] == [second, first]


def test_add_device_note_appends_one_audit_without_changing_device_or_license_data(
    tmp_path,
    monkeypatch,
):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)
    before = _business_rows(database_path)

    response = client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers={**_auth(), "X-Forwarded-For": "203.0.113.9"},
        json={"note": "  设备已重装系统，麻烦核对使用状态。  "},
    )

    assert response.status_code == 201
    body = response.json()
    assert set(body) == AUDIT_FIELDS
    assert body["actor"] == "tester"
    assert body["source_ip"] == "testclient"
    assert body["source_ip"] != "203.0.113.9"
    assert body["action"] == "DEVICE_NOTE_ADDED"
    assert body["target_type"] == "DEVICE"
    assert body["target_id"] == "device-a"
    assert body["result"] == "SUCCESS"
    assert body["reason"] == "设备已重装系统，麻烦核对使用状态。"
    assert body["before_state"] is None
    assert body["after_state"] is None
    assert body["failure_code"] is None
    assert len(body["request_id"]) == 36
    assert _business_rows(database_path) == before
    assert _audit_count(database_path) == 1
    _assert_no_sensitive_text(response.text)
    _assert_security_headers(response)


def test_add_license_note_appends_one_audit(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)
    before = _business_rows(database_path)

    response = client.post(
        "/internal/admin/api/licenses/1/notes",
        headers=_auth(),
        json={"note": "授权到期时间已人工核对。"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["action"] == "LICENSE_NOTE_ADDED"
    assert body["target_type"] == "LICENSE"
    assert body["target_id"] == "1"
    assert body["reason"] == "授权到期时间已人工核对。"
    assert _business_rows(database_path) == before
    assert _audit_count(database_path) == 1
    _assert_security_headers(response)

    missing = client.post(
        "/internal/admin/api/licenses/99999/notes",
        headers=_auth(),
        json={"note": "check"},
    )
    assert missing.status_code == 404
    assert missing.json() == {"detail": "ADMIN_RESOURCE_NOT_FOUND"}
    assert _audit_count(database_path) == 1
    _assert_security_headers(missing)


@pytest.mark.parametrize("length", [1, 500])
def test_note_length_boundaries_are_accepted(tmp_path, monkeypatch, length):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    response = client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers=_auth(),
        json={"note": "界" * length},
    )

    assert response.status_code == 201
    assert len(response.json()["reason"]) == length


@pytest.mark.parametrize("note", ["", "   ", "x" * 501, "ok\nnext", "ok\rnext", "ok\x00next"])
def test_invalid_note_shape_is_rejected_without_writing(tmp_path, monkeypatch, note):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    response = client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers=_auth(),
        json={"note": note},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "ADMIN_NOTE_INVALID"}
    assert _audit_count(database_path) == 0
    if note:
        assert note not in response.text
    _assert_security_headers(response)


@pytest.mark.parametrize(
    "note",
    [
        "Token abc123",
        "to-ken abc123",
        "to ken abc123",
        "ｔｏｋｅｎ abc123",
        "Authorization: Bearer abc123",
        "PASS-WORD=abc123",
        "-----BEGIN PRIVATE KEY-----",
        "private_key material",
        "weixin://wxpay/bizpayurl?pr=secret",
        '{"event_type":"TRANSACTION.SUCCESS","resource":{}}',
    ],
)
def test_sensitive_note_is_rejected_without_echo_or_write(tmp_path, monkeypatch, note):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    response = client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers=_auth(),
        json={"note": note},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "ADMIN_NOTE_SENSITIVE"}
    assert note not in response.text
    assert _audit_count(database_path) == 0
    _assert_security_headers(response)


def test_punctuated_chinese_note_remains_allowed(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    response = client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers=_auth(),
        json={"note": "设备已重装系统，麻烦核对。"},
    )

    assert response.status_code == 201
    assert response.json()["reason"] == "设备已重装系统，麻烦核对。"
    assert _audit_count(database_path) == 1


def test_client_cannot_supply_request_id(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    response = client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers=_auth(),
        json={"note": "check", "request_id": "client-chosen"},
    )

    assert response.status_code == 422
    assert _audit_count(database_path) == 0
    _assert_security_headers(response)


def test_other_admin_validation_errors_have_security_headers_and_public_api_is_unchanged(
    tmp_path,
    monkeypatch,
):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)

    response = client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers=_auth(),
        json={"note": 123},
    )
    public = client.get("/health")

    assert response.status_code == 422
    _assert_security_headers(response)
    assert _audit_count(database_path) == 0
    for header in (
        "cache-control",
        "x-content-type-options",
        "referrer-policy",
        "content-security-policy",
    ):
        assert header not in public.headers


def test_audit_queries_redact_sensitive_historical_reasons(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    sensitive_id = _record(
        database_path,
        request_id="sensitive-history",
        reason="Token secret-value",
    )
    safe_id = _record(
        database_path,
        request_id="safe-history",
        reason="正常售后备注",
    )

    listed = client.get("/internal/admin/api/audit-logs", headers=_auth())
    sensitive_detail = client.get(
        f"/internal/admin/api/audit-logs/{sensitive_id}",
        headers=_auth(),
    )
    safe_detail = client.get(
        f"/internal/admin/api/audit-logs/{safe_id}",
        headers=_auth(),
    )

    reasons = {item["id"]: item["reason"] for item in listed.json()["items"]}
    assert reasons[sensitive_id] == "[REDACTED]"
    assert reasons[safe_id] == "正常售后备注"
    assert sensitive_detail.json()["reason"] == "[REDACTED]"
    assert safe_detail.json()["reason"] == "正常售后备注"
    assert "secret-value" not in listed.text
    assert "secret-value" not in sensitive_detail.text


def test_missing_device_and_empty_operator_fail_closed_without_writing(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    missing = client.post(
        "/internal/admin/api/devices/missing/notes",
        headers=_auth(),
        json={"note": "check"},
    )
    assert missing.status_code == 404
    assert missing.json() == {"detail": "ADMIN_RESOURCE_NOT_FOUND"}
    assert _audit_count(database_path) == 0
    _assert_security_headers(missing)

    _set_admin_env(tmp_path, monkeypatch)
    monkeypatch.setenv("ADMIN_OPERATOR_NAME", "   ")
    empty_operator_client = TestClient(create_app())
    rejected = empty_operator_client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers=_auth(),
        json={"note": "check"},
    )
    assert rejected.status_code == 503
    assert rejected.json() == {"detail": "ADMIN_OPERATOR_REQUIRED"}
    assert _audit_count(database_path) == 0
    _assert_security_headers(rejected)


def test_audit_insert_failure_rolls_back_and_leaves_business_data_unchanged(
    tmp_path,
    monkeypatch,
):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    _seed_admin_rows(database_path)
    before = _business_rows(database_path)
    original = admin_routes.insert_admin_audit

    def fail_after_insert(connection, entry):
        original(connection, entry)
        raise RuntimeError("audit failed")

    monkeypatch.setattr(admin_routes, "insert_admin_audit", fail_after_insert)
    response = client.post(
        "/internal/admin/api/devices/device-a/notes",
        headers=_auth(),
        json={"note": "check"},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "ADMIN_INTERNAL_ERROR"}
    assert _audit_count(database_path) == 0
    assert _business_rows(database_path) == before
    _assert_security_headers(response)


def test_admin_read_helpers_close_database_connections(tmp_path, monkeypatch):
    client, database_path = _admin_client(tmp_path, monkeypatch)
    client.get("/internal/admin/api/audit-logs", headers=_auth())

    selected_connection = connect(database_path)
    monkeypatch.setattr(admin_routes, "connect", lambda _path: selected_connection)
    admin_routes._select(database_path, "SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        selected_connection.execute("SELECT 1")

    context_connection = connect(database_path)
    monkeypatch.setattr(admin_routes, "connect", lambda _path: context_connection)
    with admin_routes._connection(database_path) as connection:
        connection.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        context_connection.execute("SELECT 1")


def _record(
    database_path,
    *,
    request_id="request-1",
    target_type="DEVICE",
    target_id="device-a",
    action="DEVICE_NOTE_ADDED",
    result=AuditResult.SUCCESS,
    reason="safe note",
    created_at="2026-07-10T09:00:00Z",
):
    return record_admin_audit(
        database_path,
        AdminAuditEntry(
            actor="tester",
            source_ip="127.0.0.1",
            request_id=request_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            result=result,
            before_state={"license_status": "active"},
            after_state={"license_status": "active"},
            reason=reason,
            failure_code=None,
            created_at=datetime.fromisoformat(created_at.replace("Z", "+00:00")),
        ),
    )


def _audit_count(database_path):
    with connect(database_path) as connection:
        return connection.execute("SELECT COUNT(*) FROM admin_audit_logs").fetchone()[0]


def _business_rows(database_path):
    with connect(database_path) as connection:
        return {
            table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY id")]
            for table in ("devices", "licenses")
        }
