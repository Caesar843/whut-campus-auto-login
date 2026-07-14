import re
import sqlite3
from pathlib import Path

import pytest

import license_server.db as db
from license_server.db import connect, initialize_database


V3_NOTIFICATION_SCHEMA = """
CREATE TABLE payment_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_notification_id TEXT NOT NULL UNIQUE,
    order_id TEXT,
    out_trade_no TEXT,
    provider TEXT NOT NULL,
    provider_transaction_id TEXT,
    event_type TEXT,
    signature_key_id TEXT,
    signature_valid INTEGER NOT NULL DEFAULT 0,
    payload_digest_sha256 TEXT,
    reported_trade_type TEXT,
    reported_trade_state TEXT,
    reported_amount_fen INTEGER,
    reported_currency TEXT,
    merchant_identity_valid INTEGER NOT NULL DEFAULT 0,
    process_status TEXT NOT NULL,
    security_error_code TEXT,
    failure_code TEXT,
    provider_created_at TEXT,
    received_at TEXT NOT NULL,
    processing_started_at TEXT,
    lease_expires_at TEXT,
    worker_id TEXT,
    processed_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT
);
CREATE INDEX idx_payment_notifications_order
ON payment_notifications(order_id);
CREATE INDEX idx_payment_notifications_process
ON payment_notifications(process_status, next_attempt_at);
"""


def test_new_database_creates_schema_v4_with_notification_constraints(tmp_path):
    database_path = tmp_path / "license.sqlite3"

    initialize_database(database_path)

    with connect(database_path) as connection:
        assert _schema_version(connection) == 4
        assert [row[1] for row in connection.execute(
            "PRAGMA table_xinfo(payment_notifications)"
        )] == [
            "id",
            "provider_notification_id",
            "order_id",
            "out_trade_no",
            "provider",
            "provider_transaction_id",
            "event_type",
            "signature_key_id",
            "signature_valid",
            "payload_digest_sha256",
            "reported_trade_type",
            "reported_trade_state",
            "reported_amount_fen",
            "reported_currency",
            "merchant_identity_valid",
            "process_status",
            "security_error_code",
            "failure_code",
            "provider_created_at",
            "received_at",
            "processing_started_at",
            "lease_expires_at",
            "worker_id",
            "processed_at",
            "attempt_count",
            "next_attempt_at",
            "reported_appid",
            "reported_mchid",
            "reported_success_at",
            "claim_token",
        ]
        assert _foreign_keys(connection, "payment_notifications") == {
            ("payment_orders", "order_id", "order_id", "NO ACTION", "NO ACTION")
        }
        assert _explicit_indexes(connection, "payment_notifications") == {
            "idx_payment_notifications_order": ("order_id",),
            "idx_payment_notifications_process": (
                "process_status",
                "next_attempt_at",
                "lease_expires_at",
                "id",
            ),
        }
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize(
    ("column", "value"),
    (("signature_valid", 2), ("merchant_identity_valid", -1), ("attempt_count", -1)),
)
def test_v4_rejects_invalid_boolean_and_attempt_values(tmp_path, column, value):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, provider, signature_valid,
                merchant_identity_valid, process_status, failure_code,
                received_at, processed_at, attempt_count
            ) VALUES ('notice-invalid', 'wechat_native', 1, 1,
                      'ABNORMAL', 'TEST_FAILURE', '2026-07-14T00:00:00Z',
                      '2026-07-14T00:00:01Z', 0)
            """
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                f"UPDATE payment_notifications SET {column} = ?",
                (value,),
            )


def test_v4_rejects_invalid_processing_shape(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO payment_notifications (
                    provider_notification_id, provider, signature_valid,
                    merchant_identity_valid, process_status, received_at
                ) VALUES ('notice-processing', 'wechat_native', 1, 1,
                          'PROCESSING', '2026-07-14T00:00:00Z')
                """
            )


def test_v4_received_requires_complete_payment_evidence(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO payment_notifications (
                    provider_notification_id, provider, signature_valid,
                    merchant_identity_valid, process_status, received_at
                ) VALUES ('notice-received', 'wechat_native', 1, 1,
                          'RECEIVED', '2026-07-14T00:00:00Z')
                """
            )


def test_v4_order_id_foreign_key_is_enforced(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO payment_notifications (
                    provider_notification_id, order_id, provider,
                    process_status, failure_code, received_at, processed_at
                ) VALUES ('notice-orphan', 'missing-order', 'wechat_native',
                          'ORPHAN', 'PAYMENT_NOTIFICATION_ORDER_NOT_FOUND',
                          '2026-07-14T00:00:00Z', '2026-07-14T00:00:01Z')
                """
            )


def test_v4_rejects_invalid_retry_and_terminal_shapes(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        for notification_id, status in (
            ("notice-retry", "RETRY"),
            ("notice-terminal", "PROCESSED"),
            ("notice-unknown", "UNKNOWN"),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO payment_notifications (
                        provider_notification_id, provider, signature_valid,
                        merchant_identity_valid, process_status, received_at
                    ) VALUES (?, 'wechat_native', 1, 1, ?,
                              '2026-07-14T00:00:00Z')
                    """,
                    (notification_id, status),
                )


def test_exact_v3_empty_database_migrates_to_same_v4_fingerprint(tmp_path):
    migrated_path = tmp_path / "migrated.sqlite3"
    new_path = tmp_path / "new.sqlite3"
    _create_v3_database(migrated_path)

    initialize_database(migrated_path)
    initialize_database(new_path)

    assert _schema_fingerprint(migrated_path) == _schema_fingerprint(new_path)


def test_v3_terminal_notification_is_preserved(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, provider, process_status,
                received_at, processed_at
            ) VALUES ('notice-terminal', 'wechat_native', 'PROCESSED',
                      '2026-07-14T00:00:00Z', '2026-07-14T00:00:01Z')
            """
        )

    initialize_database(database_path)

    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM payment_notifications"
        ).fetchone()
        assert row["provider_notification_id"] == "notice-terminal"
        assert row["process_status"] == "PROCESSED"
        assert row["reported_appid"] is None
        assert row["reported_mchid"] is None
        assert row["reported_success_at"] is None
        assert row["claim_token"] is None


def test_v3_to_v4_preserves_notification_autoincrement_sequence(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, provider, process_status,
                received_at, processed_at
            ) VALUES ('notice-deleted', 'wechat_native', 'PROCESSED',
                      '2026-07-14T00:00:00Z', '2026-07-14T00:00:01Z')
            """
        )
        connection.execute("DELETE FROM payment_notifications")
        before = connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'payment_notifications'"
        ).fetchone()[0]

    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        after = connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'payment_notifications'"
        ).fetchone()[0]
    assert after == before


@pytest.mark.parametrize("status", ("RECEIVED", "PROCESSING", "RETRY"))
def test_v3_incomplete_claimable_notification_blocks_without_changes(tmp_path, status):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, provider, process_status,
                received_at
            ) VALUES ('notice-incomplete', 'wechat_native', ?,
                      '2026-07-14T00:00:00Z')
            """,
            (status,),
        )
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="unsafe V3 payment notification data"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_v3_unknown_status_blocks_without_changes(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, provider, process_status,
                received_at, processed_at
            ) VALUES ('notice-unknown', 'wechat_native', 'UNKNOWN',
                      '2026-07-14T00:00:00Z', '2026-07-14T00:00:01Z')
            """
        )
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="unsafe V3 payment notification data"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_v3_orphan_order_id_blocks_without_changes(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, order_id, provider, process_status,
                received_at, processed_at
            ) VALUES ('notice-orphan', 'missing-order', 'wechat_native',
                      'ORPHAN', '2026-07-14T00:00:00Z',
                      '2026-07-14T00:00:01Z')
            """
        )
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="unsafe V3 payment notification data"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_v3_core_foreign_key_violation_blocks_without_changes_and_can_recover(
    tmp_path,
):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    with sqlite3.connect(database_path) as connection:
        _insert_orphan_license(connection)
        assert connection.execute("PRAGMA foreign_key_check").fetchall()
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="DATABASE_FOREIGN_KEY_VIOLATION"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    with sqlite3.connect(database_path) as connection:
        assert _schema_version(connection) == 3
        assert connection.execute("PRAGMA foreign_key_check").fetchall()
        connection.execute("DELETE FROM licenses")

    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        assert _schema_version(connection) == 4
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_declared_v4_core_foreign_key_violation_refuses_startup(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    with sqlite3.connect(database_path) as connection:
        _insert_orphan_license(connection)
        assert connection.execute("PRAGMA foreign_key_check").fetchall()
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="DATABASE_FOREIGN_KEY_VIOLATION"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_v3_to_v4_postflight_foreign_key_violation_rolls_back(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    before = _database_snapshot(database_path)
    original = db._migrate_payment_notifications_v3_to_v4

    def migrate_and_corrupt(connection):
        original(connection)
        connection.execute("PRAGMA defer_foreign_keys = ON")
        _insert_orphan_license(connection)

    monkeypatch.setattr(
        db,
        "_migrate_payment_notifications_v3_to_v4",
        migrate_and_corrupt,
    )

    with pytest.raises(RuntimeError, match="DATABASE_FOREIGN_KEY_VIOLATION"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    with sqlite3.connect(database_path) as connection:
        assert _schema_version(connection) == 3
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_new_database_foreign_key_gate_runs_before_first_commit(tmp_path, monkeypatch):
    database_path = tmp_path / "license.sqlite3"

    def fail_gate(_connection):
        raise RuntimeError("DATABASE_FOREIGN_KEY_VIOLATION")

    monkeypatch.setattr(
        db,
        "_assert_no_foreign_key_violations",
        fail_gate,
        raising=False,
    )

    with pytest.raises(RuntimeError, match="DATABASE_FOREIGN_KEY_VIOLATION"):
        initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall() == []


def test_malformed_v3_notification_schema_blocks_before_changes(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "ALTER TABLE payment_notifications ADD COLUMN unexpected TEXT"
        )
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="declared schema version 3"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_v3_check_literal_case_change_is_not_accepted_as_exact_schema(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(
        database_path,
        admin_schema=db.ADMIN_AUDIT_SCHEMA.replace("'SUCCESS'", "'success'"),
    )
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="declared schema version 3"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


@pytest.mark.parametrize(
    "target",
    (
        "_create_payment_notifications_v4_table",
        "_copy_payment_notifications_v3_rows",
        "_drop_payment_notifications_v3_table",
        "_create_payment_notifications_v4_indexes",
    ),
)
def test_v3_to_v4_failure_at_each_ddl_stage_rolls_back(tmp_path, monkeypatch, target):
    database_path = tmp_path / f"{target}.sqlite3"
    _create_v3_database(database_path)
    before = _database_snapshot(database_path)
    original = getattr(db, target)

    def fail_after_stage(connection):
        original(connection)
        raise RuntimeError("v4 migration stage failure")

    monkeypatch.setattr(db, target, fail_after_stage)

    with pytest.raises(RuntimeError, match="v4 migration stage failure"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_v3_to_v4_failure_before_version_write_rolls_back_everything(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    before = _database_snapshot(database_path)

    def fail_before_version_write(_connection, version):
        if version == 4:
            raise RuntimeError("v4 migration failure")

    monkeypatch.setattr(db, "_set_schema_version", fail_before_version_write)

    with pytest.raises(RuntimeError, match="v4 migration failure"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_v3_to_v4_failure_after_version_write_rolls_back_everything(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "license.sqlite3"
    _create_v3_database(database_path)
    before = _database_snapshot(database_path)
    original = db._set_schema_version

    def fail_after_version_write(connection, version):
        original(connection, version)
        if version == 4:
            raise RuntimeError("v4 migration failure")

    monkeypatch.setattr(db, "_set_schema_version", fail_after_version_write)

    with pytest.raises(RuntimeError, match="v4 migration failure"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def _create_v3_database(
    database_path: Path,
    *,
    admin_schema: str | None = None,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            "\n".join(
                (
                    db.CORE_SCHEMA,
                    db.PAYMENT_ORDER_SCHEMA,
                    V3_NOTIFICATION_SCHEMA,
                    db.LICENSE_GRANT_SCHEMA,
                    admin_schema or db.ADMIN_AUDIT_SCHEMA,
                    db.SCHEMA_META_SQL,
                )
            )
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '3')"
        )


def _insert_orphan_license(connection) -> None:
    connection.execute(
        """
        INSERT INTO licenses (
            device_id, license_type, status, starts_at, expires_at, source,
            created_at
        ) VALUES (
            999, 'trial', 'active', '2026-07-14T00:00:00Z',
            '2026-07-15T00:00:00Z', 'trial', '2026-07-14T00:00:00Z'
        )
        """
    )


def _schema_version(connection) -> int:
    return int(connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0])


def _foreign_keys(connection, table: str) -> set[tuple[str, ...]]:
    return {
        (row[2], row[3], row[4], row[5], row[6])
        for row in connection.execute(f"PRAGMA foreign_key_list({table})")
    }


def _explicit_indexes(connection, table: str) -> dict[str, tuple[str, ...]]:
    indexes = {}
    for row in connection.execute(f"PRAGMA index_list({table})"):
        if row[3] == "c":
            indexes[row[1]] = tuple(
                item[2]
                for item in connection.execute(f'PRAGMA index_xinfo("{row[1]}")')
                if item[5]
            )
    return indexes


def _schema_fingerprint(database_path: Path) -> list[tuple[object, ...]]:
    with sqlite3.connect(database_path) as connection:
        objects = [
            (row[0], row[1], row[2], re.sub(r"\s+", "", row[3]).casefold())
            for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
            )
        ]
        details = []
        for table in (
            "schema_meta",
            "devices",
            "licenses",
            "payment_orders",
            "payment_notifications",
            "license_grants",
            "admin_audit_logs",
        ):
            details.append((table, tuple(connection.execute(
                f"PRAGMA table_xinfo({table})"
            ))))
            details.append((table, tuple(connection.execute(
                f"PRAGMA foreign_key_list({table})"
            ))))
            details.append((table, tuple(connection.execute(
                f"PRAGMA index_list({table})"
            ))))
        return [*objects, *details]


def _database_snapshot(database_path: Path) -> list[tuple[object, ...]]:
    with sqlite3.connect(database_path) as connection:
        schema = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        rows = []
        for table in (
            "schema_meta",
            "devices",
            "licenses",
            "payment_orders",
            "payment_notifications",
            "license_grants",
            "admin_audit_logs",
        ):
            rows.extend(
                (table, *row)
                for row in connection.execute(f'SELECT * FROM "{table}"')
            )
        rows.extend(
            ("sqlite_sequence", *row)
            for row in connection.execute(
                "SELECT name, seq FROM sqlite_sequence ORDER BY name"
            )
        )
        return [*schema, *rows]
