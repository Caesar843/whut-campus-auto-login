import sqlite3
from pathlib import Path

import pytest

import license_server.db as db
from license_server.db import connect, initialize_database


EXPECTED_COLUMNS = (
    ("order_id", "TEXT", 1, None, 1),
    ("reconcile_status", "TEXT", 1, None, 0),
    ("last_query_at", "TEXT", 0, None, 0),
    ("next_attempt_at", "TEXT", 0, None, 0),
    ("query_attempt_count", "INTEGER", 1, "0", 0),
    ("last_close_at", "TEXT", 0, None, 0),
    ("close_attempt_count", "INTEGER", 1, "0", 0),
    ("trusted_trade_state", "TEXT", 0, None, 0),
    ("last_error_code", "TEXT", 0, None, 0),
    ("terminal_reason", "TEXT", 0, None, 0),
    ("terminal_at", "TEXT", 0, None, 0),
    ("claim_token", "TEXT", 0, None, 0),
    ("claimed_by", "TEXT", 0, None, 0),
    ("claimed_at", "TEXT", 0, None, 0),
    ("lease_expires_at", "TEXT", 0, None, 0),
    ("updated_at", "TEXT", 1, None, 0),
    ("state_version", "INTEGER", 1, "0", 0),
)


def test_new_database_creates_exact_schema_v5(tmp_path):
    database_path = tmp_path / "license.sqlite3"

    initialize_database(database_path)

    with connect(database_path) as connection:
        assert _schema_version(connection) == 5
        assert _columns(connection, "payment_reconciliations") == EXPECTED_COLUMNS
        assert _foreign_keys(connection, "payment_reconciliations") == {
            ("payment_orders", "order_id", "order_id", "NO ACTION", "NO ACTION")
        }
        assert _indexes(connection, "payment_reconciliations") == {
            "idx_payment_reconciliations_claim_token": (
                True,
                True,
                ("claim_token",),
            ),
            "idx_payment_reconciliations_candidate": (
                False,
                False,
                (
                    "reconcile_status",
                    "next_attempt_at",
                    "lease_expires_at",
                    "order_id",
                ),
            ),
        }
        assert db._payment_reconciliations_signature(connection) == 5
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v4_to_v5_preserves_all_existing_business_data(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_versioned_database(database_path, 4)
    _insert_v4_business_data(database_path)
    before = _business_rows(database_path)

    initialize_database(database_path)

    after = _business_rows(database_path)
    assert after == before
    assert {table: len(rows) for table, rows in after.items()} == {
        "devices": 1,
        "licenses": 1,
        "payment_orders": 1,
        "payment_notifications": 1,
        "license_grants": 1,
        "admin_audit_logs": 1,
    }
    with connect(database_path) as connection:
        order = connection.execute(
            "SELECT status, open_slot FROM payment_orders WHERE order_id = 'order-v4'"
        ).fetchone()
        assert tuple(order) == ("WAITING_PAYMENT", "open")
        assert connection.execute(
            "SELECT COUNT(*) FROM payment_reconciliations"
        ).fetchone()[0] == 0
        assert _schema_version(connection) == 5


@pytest.mark.parametrize("version", (2, 3, 4))
def test_historical_schema_chain_upgrades_to_v5(tmp_path, version):
    database_path = tmp_path / f"v{version}.sqlite3"
    _create_versioned_database(database_path, version)

    initialize_database(database_path)

    with connect(database_path) as connection:
        assert _schema_version(connection) == 5
        assert db._payment_orders_signature(connection) == 3
        assert db._payment_notifications_signature(connection) == 4
        assert db._payment_reconciliations_signature(connection) == 5
        assert connection.execute(
            "SELECT COUNT(*) FROM payment_reconciliations"
        ).fetchone()[0] == 0


def test_v5_second_initialization_is_byte_for_byte_stable(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    _insert_order(database_path, "order-stable")
    with connect(database_path) as connection:
        _insert_reconciliation(connection, "order-stable")
        connection.commit()
    before = _database_snapshot(database_path)

    initialize_database(database_path)

    assert _database_snapshot(database_path) == before


@pytest.mark.parametrize(
    "target",
    (
        "_create_payment_reconciliations_v5_table",
        "_create_payment_reconciliations_v5_indexes",
        "_set_schema_version",
        "_require_exact_versioned_schema",
    ),
)
def test_v4_to_v5_failure_at_each_stage_rolls_back(tmp_path, monkeypatch, target):
    database_path = tmp_path / f"{target}.sqlite3"
    _create_versioned_database(database_path, 4)
    _insert_v4_business_data(database_path)
    before = _database_snapshot(database_path)
    original = getattr(db, target)

    if target in {
        "_create_payment_reconciliations_v5_table",
        "_create_payment_reconciliations_v5_indexes",
    }:

        def fail_after_stage(connection):
            original(connection)
            raise RuntimeError("v5 migration stage failure")

    else:

        def fail_after_stage(connection, version):
            original(connection, version)
            if version == 5:
                raise RuntimeError("v5 migration stage failure")

    monkeypatch.setattr(db, target, fail_after_stage)

    with pytest.raises(RuntimeError, match="v5 migration stage failure"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    with connect(database_path) as connection:
        assert _schema_version(connection) == 4
        assert not _table_exists(connection, "payment_reconciliations")
        assert not any(
            row[0].startswith("idx_payment_reconciliations_")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        )
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize(
    "overrides",
    (
        {"reconcile_status": "UNKNOWN"},
        {"query_attempt_count": -1},
        {"close_attempt_count": -1},
        {"state_version": -1},
        {"next_attempt_at": None},
        {"claim_token": "partial-claim"},
        {
            "reconcile_status": "CLAIMED",
            "next_attempt_at": None,
            "claim_token": None,
            "claimed_by": "worker-a",
            "claimed_at": "2026-07-15T00:00:00Z",
            "lease_expires_at": "2026-07-15T00:01:00Z",
        },
        {
            "reconcile_status": "CLAIMED",
            "next_attempt_at": None,
            "claim_token": "claim-a",
            "claimed_by": None,
            "claimed_at": "2026-07-15T00:00:00Z",
            "lease_expires_at": "2026-07-15T00:01:00Z",
        },
        {
            "reconcile_status": "CLAIMED",
            "next_attempt_at": None,
            "claim_token": "claim-a",
            "claimed_by": "worker-a",
            "claimed_at": None,
            "lease_expires_at": "2026-07-15T00:01:00Z",
        },
        {
            "reconcile_status": "CLAIMED",
            "next_attempt_at": None,
            "claim_token": "claim-a",
            "claimed_by": "worker-a",
            "claimed_at": "2026-07-15T00:00:00Z",
            "lease_expires_at": None,
        },
        {
            "reconcile_status": "CLAIMED",
            "next_attempt_at": None,
            "claim_token": "claim-a",
            "claimed_by": "worker-a",
            "claimed_at": "2026-07-15T00:00:00Z",
            "lease_expires_at": "2026-07-15T00:00:00Z",
        },
        {
            "reconcile_status": "CLAIMED",
            "claim_token": "claim-a",
            "claimed_by": "worker-a",
            "claimed_at": "2026-07-15T00:00:00Z",
            "lease_expires_at": "2026-07-15T00:01:00Z",
        },
        {
            "reconcile_status": "TERMINAL",
            "next_attempt_at": None,
            "terminal_reason": None,
            "terminal_at": "2026-07-15T00:01:00Z",
        },
        {
            "reconcile_status": "TERMINAL",
            "next_attempt_at": None,
            "terminal_reason": "STOPPED",
            "terminal_at": None,
        },
        {
            "reconcile_status": "TERMINAL",
            "next_attempt_at": None,
            "terminal_reason": "STOPPED",
            "terminal_at": "2026-07-15T00:01:00Z",
            "claim_token": "stale-claim",
            "claimed_by": "worker-a",
            "claimed_at": "2026-07-15T00:00:00Z",
            "lease_expires_at": "2026-07-15T00:02:00Z",
        },
        {"trusted_trade_state": "UNVERIFIED_RAW_STATE"},
    ),
)
def test_reconciliation_check_constraints_reject_invalid_shapes(tmp_path, overrides):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    _insert_order(database_path, "order-invalid")

    with connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_reconciliation(connection, "order-invalid", **overrides)


def test_ready_claimed_and_terminal_shapes_are_accepted(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    for order_id in ("order-ready", "order-claimed", "order-terminal"):
        _insert_order(database_path, order_id)

    with connect(database_path) as connection:
        _insert_reconciliation(connection, "order-ready")
        _insert_reconciliation(
            connection,
            "order-claimed",
            reconcile_status="CLAIMED",
            next_attempt_at=None,
            claim_token="claim-valid",
            claimed_by="worker-a",
            claimed_at="2026-07-15T00:00:00Z",
            lease_expires_at="2026-07-15T00:01:00Z",
            state_version=7,
        )
        _insert_reconciliation(
            connection,
            "order-terminal",
            reconcile_status="TERMINAL",
            next_attempt_at=None,
            terminal_reason="MAX_ATTEMPTS",
            terminal_at="2026-07-15T00:02:00Z",
        )
        rows = connection.execute(
            "SELECT reconcile_status, query_attempt_count, close_attempt_count, "
            "state_version FROM payment_reconciliations ORDER BY order_id"
        ).fetchall()
    assert [tuple(row) for row in rows] == [
        ("CLAIMED", 0, 0, 7),
        ("READY", 0, 0, 0),
        ("TERMINAL", 0, 0, 0),
    ]


@pytest.mark.parametrize(
    "trusted_trade_state",
    (None, "SUCCESS", "NOTPAY", "CLOSED", "REFUND", "REVOKED", "USERPAYING", "PAYERROR", "UNKNOWN"),
)
def test_trusted_trade_state_whitelist_is_accepted(tmp_path, trusted_trade_state):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    order_id = f"order-{trusted_trade_state or 'null'}"
    _insert_order(database_path, order_id)

    with connect(database_path) as connection:
        _insert_reconciliation(
            connection,
            order_id,
            trusted_trade_state=trusted_trade_state,
        )


def test_foreign_key_primary_key_claim_uniqueness_and_no_cascade(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    for order_id in ("order-a", "order-b", "order-c"):
        _insert_order(database_path, order_id)

    with connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_reconciliation(connection, "missing-order")

        _insert_reconciliation(connection, "order-a")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_reconciliation(connection, "order-a")
        _insert_reconciliation(connection, "order-b")

        connection.execute("DELETE FROM payment_reconciliations")
        _insert_reconciliation(
            connection,
            "order-a",
            reconcile_status="CLAIMED",
            next_attempt_at=None,
            claim_token="same-claim",
            claimed_by="worker-a",
            claimed_at="2026-07-15T00:00:00Z",
            lease_expires_at="2026-07-15T00:01:00Z",
        )
        with pytest.raises(sqlite3.IntegrityError):
            _insert_reconciliation(
                connection,
                "order-b",
                reconcile_status="CLAIMED",
                next_attempt_at=None,
                claim_token="same-claim",
                claimed_by="worker-b",
                claimed_at="2026-07-15T00:00:00Z",
                lease_expires_at="2026-07-15T00:01:00Z",
            )

        connection.execute("DELETE FROM payment_reconciliations")
        _insert_reconciliation(connection, "order-c")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM payment_orders WHERE order_id = 'order-c'")
        assert connection.execute(
            "SELECT COUNT(*) FROM payment_reconciliations WHERE order_id = 'order-c'"
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    "mutation",
    ("missing_table", "extra_column", "missing_candidate_index", "missing_unique_index", "weakened_status_check", "missing_foreign_key", "wrong_default"),
)
def test_declared_v5_schema_tampering_fails_closed(tmp_path, mutation):
    database_path = tmp_path / f"{mutation}.sqlite3"
    initialize_database(database_path)
    with sqlite3.connect(database_path) as connection:
        if mutation == "missing_table":
            connection.execute("DROP TABLE payment_reconciliations")
        elif mutation == "extra_column":
            connection.execute(
                "ALTER TABLE payment_reconciliations ADD COLUMN unexpected TEXT"
            )
        elif mutation == "missing_candidate_index":
            connection.execute("DROP INDEX idx_payment_reconciliations_candidate")
        elif mutation == "missing_unique_index":
            connection.execute("DROP INDEX idx_payment_reconciliations_claim_token")
        else:
            connection.execute("DROP TABLE payment_reconciliations")
            table_sql = db.PAYMENT_RECONCILIATION_V5_TABLE_SQL
            if mutation == "weakened_status_check":
                table_sql = table_sql.replace(
                    "'READY', 'CLAIMED', 'TERMINAL'",
                    "'READY', 'CLAIMED', 'TERMINAL', 'OTHER'",
                )
            elif mutation == "missing_foreign_key":
                table_sql = table_sql.replace(
                    ",\n    FOREIGN KEY (order_id) REFERENCES payment_orders(order_id)",
                    "",
                )
            else:
                table_sql = table_sql.replace(
                    "query_attempt_count INTEGER NOT NULL DEFAULT 0",
                    "query_attempt_count INTEGER NOT NULL DEFAULT 1",
                )
            connection.execute(table_sql)
            connection.execute(db.PAYMENT_RECONCILIATION_V5_CLAIM_INDEX_SQL)
            connection.execute(db.PAYMENT_RECONCILIATION_V5_CANDIDATE_INDEX_SQL)
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="declared schema version 5"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_future_schema_version_still_fails_closed(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE schema_meta SET value = '6' WHERE key = 'schema_version'"
        )

    with pytest.raises(RuntimeError, match="newer than supported 5"):
        initialize_database(database_path)


def _create_versioned_database(database_path: Path, version: int) -> None:
    order_schema = db.PAYMENT_ORDER_SCHEMA
    notification_schema = db.PAYMENT_NOTIFICATION_SCHEMA
    if version == 2:
        order_schema = "\n".join(
            (
                db.PAYMENT_ORDER_V2_TABLE_SQL + ";",
                "CREATE UNIQUE INDEX idx_payment_orders_device_open_slot "
                "ON payment_orders(device_fingerprint_hash, open_slot);",
                "CREATE INDEX idx_payment_orders_status "
                "ON payment_orders(status, expires_at);",
            )
        )
        notification_schema = db.PAYMENT_NOTIFICATION_V3_SCHEMA
    elif version == 3:
        notification_schema = db.PAYMENT_NOTIFICATION_V3_SCHEMA

    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            "\n".join(
                (
                    db.CORE_SCHEMA,
                    order_schema,
                    notification_schema,
                    db.LICENSE_GRANT_SCHEMA,
                    db.ADMIN_AUDIT_SCHEMA,
                    db.SCHEMA_META_SQL,
                )
            )
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (str(version),),
        )


def _insert_v4_business_data(database_path: Path) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO devices (product_id, device_fingerprint_hash, "
            "first_seen_at, last_seen_at) VALUES "
            "('whut-campus-auto-login', 'device-v4', '2026-07-15T00:00:00Z', "
            "'2026-07-15T00:00:00Z')"
        )
        connection.execute(
            "INSERT INTO licenses (device_id, license_type, status, starts_at, "
            "expires_at, source, order_id, created_at) VALUES "
            "(1, 'paid', 'active', '2026-07-15T00:00:00Z', "
            "'2027-07-15T00:00:00Z', 'payment', 'order-v4', "
            "'2026-07-15T00:00:00Z')"
        )
        connection.execute(
            "INSERT INTO payment_orders (order_id, device_fingerprint_hash, "
            "product_code, amount_fen, currency, provider, status, open_slot, "
            "created_at, updated_at, expires_at) VALUES "
            "('order-v4', 'device-v4', 'annual_v1', 990, 'CNY', "
            "'wechat_native', 'WAITING_PAYMENT', 'open', "
            "'2026-07-15T00:00:00Z', '2026-07-15T00:00:01Z', "
            "'2026-07-15T00:15:00Z')"
        )
        connection.execute(
            "INSERT INTO payment_notifications (provider_notification_id, "
            "order_id, provider, process_status, received_at, processed_at) "
            "VALUES ('notice-v4', 'order-v4', 'wechat_native', 'PROCESSED', "
            "'2026-07-15T00:01:00Z', '2026-07-15T00:01:01Z')"
        )
        connection.execute(
            "INSERT INTO license_grants (source_order_id, "
            "device_fingerprint_hash, license_id, product_code, grant_days, "
            "granted_at, issued_by) VALUES ('order-v4', 'device-v4', 1, "
            "'annual_v1', 365, '2026-07-15T00:02:00Z', 'wechat_native')"
        )
        connection.execute(
            "INSERT INTO admin_audit_logs (actor, source_ip, request_id, action, "
            "target_type, target_id, result, reason, created_at) VALUES "
            "('admin', '127.0.0.1', 'request-v4', 'READ', 'payment_order', "
            "'order-v4', 'SUCCESS', 'test fixture', '2026-07-15T00:03:00Z')"
        )


def _insert_order(database_path: Path, order_id: str) -> None:
    with connect(database_path) as connection:
        connection.execute(
            "INSERT INTO payment_orders (order_id, device_fingerprint_hash, "
            "product_code, amount_fen, currency, provider, status, open_slot, "
            "created_at, updated_at, expires_at) VALUES (?, ?, 'annual_v1', "
            "990, 'CNY', 'wechat_native', 'CREATED', 'open', "
            "'2026-07-15T00:00:00Z', '2026-07-15T00:00:00Z', "
            "'2026-07-15T00:15:00Z')",
            (order_id, f"device-{order_id}"),
        )
        connection.commit()


def _insert_reconciliation(connection, order_id: str, **overrides) -> None:
    values = {
        "order_id": order_id,
        "reconcile_status": "READY",
        "last_query_at": None,
        "next_attempt_at": "2026-07-15T00:00:00Z",
        "query_attempt_count": 0,
        "last_close_at": None,
        "close_attempt_count": 0,
        "trusted_trade_state": None,
        "last_error_code": None,
        "terminal_reason": None,
        "terminal_at": None,
        "claim_token": None,
        "claimed_by": None,
        "claimed_at": None,
        "lease_expires_at": None,
        "updated_at": "2026-07-15T00:00:00Z",
        "state_version": 0,
    }
    values.update(overrides)
    columns = ", ".join(values)
    placeholders = ", ".join(f":{column}" for column in values)
    connection.execute(
        f"INSERT INTO payment_reconciliations ({columns}) "
        f"VALUES ({placeholders})",
        values,
    )


def _schema_version(connection) -> int:
    return int(connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0])


def _columns(connection, table: str) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (row[1], row[2], row[3], row[4], row[5])
        for row in connection.execute(f"PRAGMA table_xinfo({table})")
    )


def _foreign_keys(connection, table: str) -> set[tuple[str, ...]]:
    return {
        (row[2], row[3], row[4], row[5], row[6])
        for row in connection.execute(f"PRAGMA foreign_key_list({table})")
    }


def _indexes(connection, table: str) -> dict[str, tuple[object, ...]]:
    result = {}
    for row in connection.execute(f"PRAGMA index_list({table})"):
        if row[3] != "c":
            continue
        columns = tuple(
            item[2]
            for item in connection.execute(f'PRAGMA index_xinfo("{row[1]}")')
            if item[5]
        )
        result[row[1]] = (bool(row[2]), bool(row[4]), columns)
    return result


def _business_rows(database_path: Path) -> dict[str, list[tuple[object, ...]]]:
    with sqlite3.connect(database_path) as connection:
        return {
            table: connection.execute(f'SELECT * FROM "{table}"').fetchall()
            for table in (
                "devices",
                "licenses",
                "payment_orders",
                "payment_notifications",
                "license_grants",
                "admin_audit_logs",
            )
        }


def _database_snapshot(database_path: Path) -> tuple[object, ...]:
    with sqlite3.connect(database_path) as connection:
        schema = tuple(connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ))
        rows = []
        for table in sorted(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
            if not row[0].startswith("sqlite_")
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
        return schema, tuple(rows)


def _table_exists(connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone() is not None
