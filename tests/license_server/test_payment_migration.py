import sqlite3
from pathlib import Path

import pytest

from license_server.db import (
    BUSY_TIMEOUT_MS,
    SUPPORTED_SCHEMA_VERSION,
    connect,
    initialize_database,
    write_transaction,
)


def test_empty_database_initializes_to_schema_version_2(tmp_path):
    database_path = tmp_path / "license.sqlite3"

    initialize_database(database_path)

    with connect(database_path) as connection:
        assert _schema_version(connection) == SUPPORTED_SCHEMA_VERSION
        assert _columns(connection, "payment_orders") >= {
            "order_id",
            "device_fingerprint_hash",
            "product_code",
            "amount_fen",
            "currency",
            "provider",
            "status",
            "open_slot",
            "provider_transaction_id",
            "security_error_code",
        }
        assert _columns(connection, "payment_notifications") >= {
            "provider_notification_id",
            "provider",
            "process_status",
            "processing_started_at",
            "lease_expires_at",
            "worker_id",
            "attempt_count",
        }
        assert _columns(connection, "license_grants") >= {
            "source_order_id",
            "device_fingerprint_hash",
            "license_id",
            "product_code",
            "grant_days",
            "issued_by",
        }


def test_initialize_database_is_idempotent(tmp_path):
    database_path = tmp_path / "license.sqlite3"

    initialize_database(database_path)
    before = _table_sql(database_path)
    initialize_database(database_path)

    assert _table_sql(database_path) == before


def test_initialize_database_rolls_back_schema_setup(tmp_path, monkeypatch):
    database_path = tmp_path / "license.sqlite3"

    def fail_payment_orders(_connection):
        raise RuntimeError("boom")

    monkeypatch.setattr("license_server.db._ensure_payment_orders", fail_payment_orders)
    with pytest.raises(RuntimeError, match="boom"):
        initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        assert "devices" not in _tables(connection)
        assert "schema_meta" not in _tables(connection)


def test_future_schema_version_refuses_startup(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
            (str(SUPPORTED_SCHEMA_VERSION + 1),),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="schema version"):
        initialize_database(database_path)


def test_nonempty_unknown_legacy_database_requires_manual_migration(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path)
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="manual migration required"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_unknown_legacy_database_does_not_reach_order_mapping(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path, amount="unknown")

    with pytest.raises(RuntimeError, match="manual migration required"):
        initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        assert "schema_meta" not in _tables(connection)
        assert "payment_orders" in _tables(connection)
        assert "payment_orders_legacy_v0" not in _tables(connection)


def test_foreign_keys_and_payment_constraints(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, created_at, updated_at,
                expires_at
            ) VALUES ('order-a', 'device-a', 'annual_v1', 990, 'CNY', 'mock',
                      'CREATED', 'open', '2026-07-06T00:00:00Z',
                      '2026-07-06T00:00:00Z', '2026-07-06T00:15:00Z')
            """
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO payment_orders (
                    order_id, device_fingerprint_hash, product_code, amount_fen,
                    currency, provider, status, open_slot, created_at, updated_at,
                    expires_at
                ) VALUES ('order-b', 'device-a', 'annual_v1', 990, 'CNY', 'mock',
                          'WAITING_PAYMENT', 'open', '2026-07-06T00:00:00Z',
                          '2026-07-06T00:00:00Z', '2026-07-06T00:15:00Z')
                """
            )
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, created_at, updated_at,
                expires_at, closed_at
            ) VALUES ('order-c', 'device-a', 'annual_v1', 990, 'CNY', 'mock',
                      'CLOSED', NULL, '2026-07-06T00:00:00Z',
                      '2026-07-06T00:00:00Z', '2026-07-06T00:15:00Z',
                      '2026-07-06T00:01:00Z')
            """
        )
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, created_at, updated_at,
                expires_at, paid_at
            ) VALUES ('order-d', 'device-a', 'annual_v1', 990, 'CNY', 'mock',
                      'PAID', NULL, '2026-07-06T00:00:00Z',
                      '2026-07-06T00:00:00Z', '2026-07-06T00:15:00Z',
                          '2026-07-06T00:01:00Z')
            """
        )


def test_connect_sets_busy_timeout(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == BUSY_TIMEOUT_MS


def test_notification_table_excludes_forbidden_raw_fields(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        columns = _columns(connection, "payment_notifications")

    assert "raw_payload" not in columns
    assert "body_raw" not in columns
    assert "body_decrypted" not in columns
    assert "openid" not in columns
    assert "bank_type" not in columns
    assert "client_ip" not in columns


def test_license_grants_source_order_id_is_unique(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO devices (
                product_id, device_fingerprint_hash, first_seen_at, last_seen_at
            ) VALUES ('whut-campus-auto-login', 'device-a',
                      '2026-07-06T00:00:00Z', '2026-07-06T00:00:00Z')
            """
        )
        cursor = connection.execute(
            """
            INSERT INTO licenses (
                device_id, license_type, status, starts_at, expires_at, source,
                order_id, created_at, revoked_at
            ) VALUES (1, 'paid', 'active', '2026-07-06T00:00:00Z',
                      '2027-07-06T00:00:00Z', 'payment', 'order-a',
                      '2026-07-06T00:00:00Z', NULL)
            """
        )
        license_id = int(cursor.lastrowid)
        connection.execute(
            """
            INSERT INTO license_grants (
                source_order_id, device_fingerprint_hash, license_id,
                product_code, grant_days, granted_at, issued_by
            ) VALUES ('order-a', 'device-a', ?, 'annual_v1', 365,
                      '2026-07-06T00:00:00Z', 'mock')
            """,
            (license_id,),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO license_grants (
                    source_order_id, device_fingerprint_hash, license_id,
                    product_code, grant_days, granted_at, issued_by
                ) VALUES ('order-a', 'device-a', ?, 'annual_v1', 365,
                          '2026-07-06T00:00:00Z', 'mock')
                """,
                (license_id,),
            )


def test_write_transaction_rolls_back_on_error(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    with pytest.raises(RuntimeError, match="boom"):
        with write_transaction(database_path) as connection:
            connection.execute(
                """
                INSERT INTO payment_orders (
                    order_id, device_fingerprint_hash, product_code, amount_fen,
                    currency, provider, status, open_slot, created_at, updated_at,
                    expires_at
                ) VALUES ('order-a', 'device-a', 'annual_v1', 990, 'CNY', 'mock',
                          'CREATED', 'open', '2026-07-06T00:00:00Z',
                          '2026-07-06T00:00:00Z', '2026-07-06T00:15:00Z')
                """
            )
            raise RuntimeError("boom")

    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM payment_orders").fetchone()[0] == 0


def _create_legacy_database(database_path: Path, *, amount: str = "9.9") -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id TEXT NOT NULL,
                device_fingerprint_hash TEXT NOT NULL UNIQUE,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            )
            """
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
                revoked_at TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE payment_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id TEXT NOT NULL UNIQUE,
                product_id TEXT NOT NULL,
                device_fingerprint_hash TEXT NOT NULL,
                amount TEXT NOT NULL,
                currency TEXT NOT NULL,
                payment_channel TEXT NOT NULL,
                order_status TEXT NOT NULL,
                payment_status TEXT NOT NULL,
                provider_status TEXT NOT NULL,
                provider_order_id TEXT,
                transaction_id TEXT,
                created_at TEXT NOT NULL,
                expire_at TEXT NOT NULL,
                paid_at TEXT,
                closed_at TEXT,
                updated_at TEXT NOT NULL,
                legacy_note TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, product_id, device_fingerprint_hash, amount, currency,
                payment_channel, order_status, payment_status, provider_status,
                created_at, expire_at, updated_at, legacy_note
            ) VALUES ('legacy-1', 'whut-campus-auto-login', 'device-a', ?, 'CNY',
                      'wechat_pay', 'created', 'unpaid', 'not_configured',
                      '2026-07-06T00:00:00Z', '2026-07-06T00:15:00Z',
                      '2026-07-06T00:00:00Z', 'keep me')
            """,
            (amount,),
        )
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, product_id, device_fingerprint_hash, amount, currency,
                payment_channel, order_status, payment_status, provider_status,
                transaction_id, created_at, expire_at, paid_at, updated_at
            ) VALUES ('legacy-2', 'whut-campus-auto-login', 'device-b', '9.9', 'CNY',
                      'wechat_pay', 'paid', 'paid', 'provider_paid', 'txn-1',
                      '2026-07-06T00:00:00Z', '2026-07-06T00:15:00Z',
                      '2026-07-06T00:02:00Z', '2026-07-06T00:02:00Z')
            """
        )


def _schema_version(connection) -> int:
    row = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()
    return int(row["value"])


def _columns(connection, table: str) -> set[str]:
    return {
        str(row["name"])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _tables(connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }


def _table_sql(database_path: Path) -> list[tuple[str, str]]:
    with sqlite3.connect(database_path) as connection:
        return connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()


def _database_snapshot(database_path: Path) -> list[tuple[object, ...]]:
    with sqlite3.connect(database_path) as connection:
        schema = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        rows = []
        for table in ("devices", "licenses", "payment_orders"):
            rows.extend((table, *row) for row in connection.execute(f"SELECT * FROM {table}"))
        return [*schema, *rows]
