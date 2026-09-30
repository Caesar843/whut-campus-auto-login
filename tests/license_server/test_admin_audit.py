import json
import sqlite3
from datetime import datetime, timezone

import pytest

import license_server.admin_audit as admin_audit
import license_server.db as db
from license_server.admin_audit import (
    AdminAuditEntry,
    AuditResult,
    insert_admin_audit,
    record_admin_audit,
    serialize_audit_snapshot,
)
from license_server.db import connect, initialize_database, write_transaction


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)


def test_empty_database_initializes_admin_audit_latest_schema_and_indexes(tmp_path):
    database_path = tmp_path / "license.sqlite3"

    initialize_database(database_path)

    with connect(database_path) as connection:
        version = connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(admin_audit_logs)").fetchall()
        }
        indexes = {
            row["name"]
            for row in connection.execute("PRAGMA index_list(admin_audit_logs)").fetchall()
        }

    assert version == "6"
    assert columns == {
        "id",
        "actor",
        "source_ip",
        "request_id",
        "action",
        "target_type",
        "target_id",
        "result",
        "before_state_json",
        "after_state_json",
        "reason",
        "failure_code",
        "created_at",
    }
    assert {
        "idx_admin_audit_logs_target_created",
        "idx_admin_audit_logs_created_at",
        "idx_admin_audit_logs_request_id",
        "idx_admin_audit_logs_result",
    } <= indexes


def test_admin_audit_result_check_constraint_rejects_invalid_value(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO admin_audit_logs (
                    actor, source_ip, request_id, action, target_type, target_id,
                    result, reason, created_at
                ) VALUES ('operator', '127.0.0.1', 'request-1', 'DEVICE_NOTE_ADDED',
                          'DEVICE', 'device-1', 'INVALID', 'test', '2026-07-10T12:00:00Z')
                """
            )


def test_initialize_database_is_idempotent_and_keeps_existing_rows(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    with write_transaction(database_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (
                product_id, device_fingerprint_hash, first_seen_at, last_seen_at
            ) VALUES (
                'whut-campus-auto-login', 'device-a',
                '2026-07-10T12:00:00Z', '2026-07-10T12:00:00Z'
            )
            """
        )
        connection.execute(
            """
            INSERT INTO licenses (
                device_id, license_type, status, starts_at, expires_at, source,
                created_at
            ) VALUES (
                1, 'free', 'active', '2026-07-10T12:00:00Z',
                '2027-07-10T12:00:00Z', 'free', '2026-07-10T12:00:00Z'
            )
            """
        )
    record_admin_audit(database_path, _entry(target_id="device-a"))

    initialize_database(database_path)

    with connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert tables == {"devices", "licenses", "admin_audit_logs", "schema_meta"}
        assert connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0] == "6"
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM admin_audit_logs").fetchone()[0] == 1


def test_admin_audit_schema_setup_rolls_back_with_the_rest_of_initialization(tmp_path, monkeypatch):
    database_path = tmp_path / "license.sqlite3"
    original = db._execute_script

    def fail_admin_audit_schema(connection, script):
        if script == db.ADMIN_AUDIT_SCHEMA:
            raise RuntimeError("audit schema failure")
        original(connection, script)

    monkeypatch.setattr(db, "_execute_script", fail_admin_audit_schema)

    with pytest.raises(RuntimeError, match="audit schema failure"):
        initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }

    assert "devices" not in tables
    assert "admin_audit_logs" not in tables


def test_initialize_database_keeps_delete_journal_mode(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


@pytest.mark.parametrize("result", list(AuditResult))
def test_record_admin_audit_appends_each_supported_result(tmp_path, result):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    audit_id = record_admin_audit(database_path, _entry(result=result))

    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT result, created_at FROM admin_audit_logs WHERE id = ?",
            (audit_id,),
        ).fetchone()

    assert audit_id.isdigit()
    assert tuple(row) == (result.value, "2026-07-10T12:00:00Z")


def test_snapshots_are_stable_compact_json_and_none_stays_null(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    entry = _entry(
        before_state={"license_status": "active", "license_expire_at": NOW},
        after_state=None,
    )

    record_admin_audit(database_path, entry)

    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT before_state_json, after_state_json FROM admin_audit_logs"
        ).fetchone()

    assert serialize_audit_snapshot(entry.before_state) == (
        '{"license_expire_at":"2026-07-10T12:00:00Z","license_status":"active"}'
    )
    assert tuple(row) == (serialize_audit_snapshot(entry.before_state), None)


@pytest.mark.parametrize(
    ("snapshot", "message"),
    [
        ({"unknown": "value"}, "unknown_field"),
        ({"token": "value"}, "forbidden_field"),
        ({"status": {"nested": "value"}}, "value_invalid"),
        ({"status": b"bytes"}, "value_invalid"),
    ],
)
def test_snapshot_rejects_unknown_sensitive_and_unsupported_values(snapshot, message):
    with pytest.raises(ValueError, match=message):
        serialize_audit_snapshot(snapshot)


def test_snapshot_json_contains_no_forbidden_keys():
    snapshot_json = serialize_audit_snapshot(
        {"device_id_hash": "device-1", "status": "active"}
    )

    for forbidden in (
        "signed_token",
        "token",
        "password",
        "campus_account",
        "campus_password",
        "private_key",
        "authorization",
    ):
        assert forbidden not in snapshot_json


def test_snapshot_string_at_limit_serializes_and_persists(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    value = "x" * admin_audit.MAX_AUDIT_SNAPSHOT_STRING_LENGTH

    audit_id = record_admin_audit(database_path, _entry(before_state={"status": value}))

    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT before_state_json FROM admin_audit_logs WHERE id = ?",
            (audit_id,),
        ).fetchone()

    assert json.loads(row[0])["status"] == value


def test_snapshot_string_over_limit_is_rejected_before_insert(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    value = "x" * (admin_audit.MAX_AUDIT_SNAPSHOT_STRING_LENGTH + 1)

    with pytest.raises(ValueError, match="snapshot_value_invalid") as excinfo:
        record_admin_audit(database_path, _entry(before_state={"status": value}))

    assert value not in str(excinfo.value)
    assert _audit_count(database_path) == 0


def test_snapshot_string_limit_counts_unicode_characters(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    value = "汉" * admin_audit.MAX_AUDIT_SNAPSHOT_STRING_LENGTH

    audit_id = record_admin_audit(database_path, _entry(before_state={"status": value}))

    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT before_state_json FROM admin_audit_logs WHERE id = ?",
            (audit_id,),
        ).fetchone()

    assert len(value) == admin_audit.MAX_AUDIT_SNAPSHOT_STRING_LENGTH
    assert len(row[0].encode("utf-8")) > len(row[0])
    assert len(row[0].encode("utf-8")) <= admin_audit.MAX_AUDIT_SNAPSHOT_JSON_BYTES
    assert json.loads(row[0])["status"] == value


def test_snapshot_json_under_limit_with_multiple_fields_persists(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    snapshot = {
        "device_id_hash": "x" * 1000,
        "status": "x" * 1000,
        "license_id": "x" * 1000,
        "license_status": "x" * 1000,
        "license_expire_at": "x" * 1000,
        "failure_code": "x" * 1000,
        "created_at": "x" * 1000,
        "updated_at": "x" * 1000,
    }
    snapshot_json = serialize_audit_snapshot(snapshot)

    assert len(snapshot_json.encode("utf-8")) <= admin_audit.MAX_AUDIT_SNAPSHOT_JSON_BYTES

    audit_id = record_admin_audit(database_path, _entry(before_state=snapshot))

    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT before_state_json FROM admin_audit_logs WHERE id = ?",
            (audit_id,),
        ).fetchone()

    assert json.loads(row[0]) == snapshot


def test_snapshot_json_over_limit_is_rejected_before_insert(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    snapshot = {
        "device_id_hash": "x" * 1024,
        "status": "x" * 1024,
        "license_id": "x" * 1024,
        "license_status": "x" * 1024,
        "license_expire_at": "x" * 1024,
        "failure_code": "x" * 1024,
        "created_at": "x" * 1024,
        "updated_at": "x" * 1024,
    }

    with pytest.raises(ValueError, match="snapshot_json_too_large") as excinfo:
        record_admin_audit(database_path, _entry(before_state=snapshot))

    assert json.dumps(snapshot, ensure_ascii=False, sort_keys=True) not in str(excinfo.value)
    assert _audit_count(database_path) == 0


def test_over_limit_snapshot_rolls_back_callers_transaction(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    value = "x" * (admin_audit.MAX_AUDIT_SNAPSHOT_STRING_LENGTH + 1)

    with pytest.raises(ValueError, match="snapshot_value_invalid"):
        with write_transaction(database_path) as connection:
            insert_admin_audit(connection, _entry(request_id="request-ok"))
            insert_admin_audit(
                connection,
                _entry(request_id="request-bad", after_state={"status": value}),
            )

    assert _audit_count(database_path) == 0


def test_entry_snapshot_is_isolated_from_original_dict_mutation():
    before_state = {"license_status": "active"}
    after_state = {"license_status": "revoked"}

    entry = _entry(before_state=before_state, after_state=after_state)
    before_state["license_status"] = "MUTATED"
    after_state["license_status"] = "MUTATED"

    assert entry.before_state["license_status"] == "active"
    assert entry.after_state["license_status"] == "revoked"


def test_same_request_id_appends_distinct_audit_rows(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    first = record_admin_audit(database_path, _entry(request_id="request-1", target_id="device-1"))
    second = record_admin_audit(database_path, _entry(request_id="request-1", target_id="device-2"))

    with connect(database_path) as connection:
        rows = connection.execute(
            "SELECT id, request_id, target_id FROM admin_audit_logs ORDER BY id"
        ).fetchall()

    assert first != second
    assert [(row["request_id"], row["target_id"]) for row in rows] == [
        ("request-1", "device-1"),
        ("request-1", "device-2"),
    ]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("actor", "   ", "actor_invalid"),
        ("source_ip", "", "source_ip_invalid"),
        ("request_id", "request\n1", "request_id_invalid"),
        ("action", "device note", "action_invalid"),
        ("target_type", "DEVICE!", "target_type_invalid"),
        ("target_id", "target\x00", "target_id_invalid"),
        ("reason", "   ", "reason_invalid"),
        ("reason", "x" * 501, "reason_invalid"),
        ("failure_code", "failure code", "failure_code_invalid"),
        ("result", "INVALID", "result_invalid"),
    ],
)
def test_entry_rejects_invalid_input(field, value, message):
    with pytest.raises(ValueError, match=message):
        _entry(**{field: value})


def test_entry_rejects_overlong_actor():
    with pytest.raises(ValueError, match="actor_invalid"):
        _entry(actor="a" * 129)


def test_entry_rejects_naive_created_at():
    with pytest.raises(ValueError, match="created_at_invalid"):
        _entry(created_at=datetime(2026, 7, 10, 12, 0))


def test_insert_admin_audit_uses_callers_transaction_without_committing(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with pytest.raises(RuntimeError, match="rollback"):
        with write_transaction(database_path) as connection:
            insert_admin_audit(connection, _entry())
            assert connection.in_transaction
            raise RuntimeError("rollback")

    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM admin_audit_logs").fetchone()[0] == 0


def test_insert_admin_audit_persists_when_callers_transaction_commits(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with write_transaction(database_path) as connection:
        audit_id = insert_admin_audit(connection, _entry())

    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT request_id FROM admin_audit_logs WHERE id = ?", (audit_id,)
        ).fetchone()[0] == "request-1"


def test_record_admin_audit_rolls_back_if_insert_fails_after_writing(tmp_path, monkeypatch):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    original = admin_audit.insert_admin_audit

    def fail_after_insert(connection, entry):
        original(connection, entry)
        raise RuntimeError("insert failure")

    monkeypatch.setattr(admin_audit, "insert_admin_audit", fail_after_insert)

    with pytest.raises(RuntimeError, match="insert failure"):
        admin_audit.record_admin_audit(database_path, _entry())

    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM admin_audit_logs").fetchone()[0] == 0


def test_different_request_ids_append_separate_immutable_rows(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    first = record_admin_audit(database_path, _entry(request_id="request-1"))
    second = record_admin_audit(database_path, _entry(request_id="request-2"))

    assert first != second
    assert not hasattr(admin_audit, "update_admin_audit")
    assert not hasattr(admin_audit, "delete_admin_audit")


def _audit_count(database_path):
    with connect(database_path) as connection:
        return connection.execute("SELECT COUNT(*) FROM admin_audit_logs").fetchone()[0]


def _entry(**overrides):
    data = {
        "actor": "operator-1",
        "source_ip": "127.0.0.1",
        "request_id": "request-1",
        "action": "DEVICE_NOTE_ADDED",
        "target_type": "DEVICE",
        "target_id": "device-1",
        "result": AuditResult.SUCCESS,
        "before_state": {"license_status": "active"},
        "after_state": {"license_status": "active"},
        "reason": "operator review",
        "failure_code": None,
        "created_at": NOW,
    }
    data.update(overrides)
    return AdminAuditEntry(**data)
