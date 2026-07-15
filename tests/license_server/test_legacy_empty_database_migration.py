import sqlite3
from pathlib import Path

import pytest

import license_server.db as db
from license_server.db import connect, initialize_database


LEGACY_DDL = """
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id TEXT NOT NULL,
    device_fingerprint_hash TEXT NOT NULL UNIQUE,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
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
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
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
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_payment_orders_device_open
ON payment_orders(device_fingerprint_hash, payment_status, order_status, expire_at);
PRAGMA user_version = 0;
"""


def test_exact_empty_production_legacy_schema_upgrades_idempotently(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path)

    initialize_database(database_path)
    first = _database_snapshot(database_path)
    initialize_database(database_path)

    with connect(database_path) as connection:
        tables = _tables(connection)
        assert connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0] == "5"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert _columns(connection, "payment_orders") == [
            "id",
            "order_id",
            "device_fingerprint_hash",
            "product_code",
            "amount_fen",
            "currency",
            "provider",
            "status",
            "open_slot",
            "provider_order_id",
            "provider_transaction_id",
            "provider_trade_state",
            "created_at",
            "updated_at",
            "expires_at",
            "paid_at",
            "closed_at",
            "security_error_code",
            "provider_create_claimed_at",
            "provider_create_attempt_count",
            "provider_code_url",
            "last_provider_query_at",
            "next_provider_query_at",
            "provider_query_attempt_count",
        ]

    assert {
        "devices",
        "licenses",
        "payment_orders",
        "payment_notifications",
        "payment_reconciliations",
        "license_grants",
        "admin_audit_logs",
        "schema_meta",
    } <= tables
    assert "payment_orders_legacy_v0" not in tables
    assert _database_snapshot(database_path) == first


def test_legacy_autoincrement_accepts_keyword_case_and_whitespace(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    varied_id = "id integer\n        primary key\n        autoincrement,"
    _create_legacy_database(
        database_path,
        replacements=(("id INTEGER PRIMARY KEY AUTOINCREMENT,", varied_id),) * 3,
    )

    initialize_database(database_path)

    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0] == "5"


@pytest.mark.parametrize(
    "old,new",
    [
        ("    paid_at TEXT,\n", ""),
        ("    updated_at TEXT NOT NULL\n", "    updated_at TEXT NOT NULL,\n    unexpected TEXT\n"),
        ("    amount TEXT NOT NULL,", "    amount INTEGER NOT NULL,"),
        ("    amount TEXT NOT NULL,", "    amount TEXT,"),
        (
            "    product_id TEXT NOT NULL,",
            "    product_id TEXT NOT NULL CHECK(length(product_id) > 0),",
        ),
        (
            "    product_id TEXT NOT NULL,\n    device_fingerprint_hash TEXT NOT NULL UNIQUE,",
            "    device_fingerprint_hash TEXT NOT NULL UNIQUE,\n    product_id TEXT NOT NULL,",
        ),
        ("    id INTEGER PRIMARY KEY AUTOINCREMENT,", "    id INTEGER NOT NULL,"),
        ("REFERENCES devices(id)", "REFERENCES devices(id) ON DELETE CASCADE"),
        ("device_fingerprint_hash TEXT NOT NULL UNIQUE", "device_fingerprint_hash TEXT NOT NULL"),
        ("order_id TEXT NOT NULL UNIQUE", "order_id TEXT NOT NULL"),
        (
            "CREATE INDEX idx_payment_orders_device_open\nON payment_orders(device_fingerprint_hash, payment_status, order_status, expire_at);",
            "",
        ),
        (
            "ON payment_orders(device_fingerprint_hash, payment_status, order_status, expire_at)",
            "ON payment_orders(payment_status, device_fingerprint_hash, order_status, expire_at)",
        ),
        (
            "PRAGMA user_version = 0;",
            "CREATE INDEX unexpected_license_index ON licenses(status);\nPRAGMA user_version = 0;",
        ),
    ],
    ids=[
        "missing-column",
        "extra-column",
        "changed-type",
        "changed-not-null",
        "added-check-constraint",
        "changed-column-order",
        "changed-primary-key",
        "changed-foreign-key",
        "missing-device-unique",
        "missing-order-unique",
        "missing-index",
        "changed-index-order",
        "extra-index",
    ],
)
def test_legacy_schema_mismatch_fails_closed(tmp_path, old, new):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path, replacements=((old, new),))
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="schema does not match.*manual migration required"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    assert "schema_meta" not in _table_names(database_path)


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE TABLE devices (id INTEGER PRIMARY KEY)",
        LEGACY_DDL + "CREATE TABLE unexpected_business_table (id INTEGER PRIMARY KEY);",
    ],
    ids=["malformed-devices-only", "extra-business-table"],
)
def test_unknown_unversioned_database_fails_closed(tmp_path, ddl):
    database_path = tmp_path / "license.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(ddl)
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="schema does not match.*manual migration required"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    assert "schema_meta" not in _table_names(database_path)


@pytest.mark.parametrize(
    "kind",
    ["VIRTUAL", "STORED"],
)
def test_legacy_generated_column_fails_closed(tmp_path, kind):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(
        database_path,
        replacements=(
            (
                "    last_seen_at TEXT NOT NULL\n);",
                "    last_seen_at TEXT NOT NULL,\n"
                f"    derived_product TEXT GENERATED ALWAYS AS (product_id) {kind}\n);",
            ),
        ),
    )
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="schema does not match.*manual migration required"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    assert "schema_meta" not in _table_names(database_path)


@pytest.mark.parametrize("table", ["devices", "licenses", "payment_orders"])
def test_legacy_id_without_autoincrement_fails_closed(tmp_path, table):
    database_path = tmp_path / "license.sqlite3"
    old = f"CREATE TABLE {table} (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    new = f"CREATE TABLE {table} (\n    id INTEGER PRIMARY KEY,"
    _create_legacy_database(database_path, replacements=((old, new),))
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="schema does not match.*manual migration required"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    assert "schema_meta" not in _table_names(database_path)


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE VIEW unexpected_view AS SELECT id FROM devices;",
        """
        CREATE TRIGGER unexpected_trigger AFTER INSERT ON devices
        BEGIN
            SELECT NEW.id;
        END;
        """,
    ],
    ids=["extra-view", "extra-trigger"],
)
def test_legacy_extra_schema_object_fails_closed(tmp_path, ddl):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path, suffix=ddl)
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="schema does not match.*manual migration required"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    assert "schema_meta" not in _table_names(database_path)


@pytest.mark.parametrize("table", ["devices", "licenses", "payment_orders"])
def test_nonempty_legacy_business_table_requires_manual_migration(tmp_path, table):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path)
    _insert_placeholder_row(database_path, table)
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="contains business data.*manual migration required"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    assert "schema_meta" not in _table_names(database_path)


def test_late_empty_legacy_migration_failure_rolls_back_to_exact_snapshot(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path)
    before = _database_snapshot(database_path)
    original = db._execute_script

    def fail_admin_audit(connection, script):
        if script == db.ADMIN_AUDIT_SCHEMA:
            statements = [statement for statement in script.split(";") if statement.strip()]
            original(connection, ";".join(statements[:2]))
            raise RuntimeError("late migration failure")
        original(connection, script)

    monkeypatch.setattr(db, "_execute_script", fail_admin_audit)

    with pytest.raises(RuntimeError, match="late migration failure"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    assert "schema_meta" not in _table_names(database_path)
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        """
        CREATE TABLE schema_meta (key TEXT NOT NULL, value TEXT NOT NULL);
        INSERT INTO schema_meta VALUES ('schema_version', '1');
        INSERT INTO schema_meta VALUES ('schema_version', '1');
        """,
        """
        CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO schema_meta VALUES ('schema_version', '0');
        """,
        """
        CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO schema_meta VALUES ('schema_version', 'not-an-integer');
        """,
        """
        CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
        INSERT INTO schema_meta VALUES ('schema_version', 1);
        """,
        """
        CREATE TABLE schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL CHECK(length(value) > 0)
        );
        INSERT INTO schema_meta VALUES ('schema_version', '1');
        """,
    ],
    ids=[
        "missing-version-row",
        "duplicate-version-row",
        "version-zero",
        "non-integer-version",
        "malformed-table",
        "unexpected-table-constraint",
    ],
)
def test_invalid_schema_meta_fails_before_writes(tmp_path, ddl):
    database_path = tmp_path / "license.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(ddl)
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="schema_meta"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def test_schema_meta_zero_cannot_version_nonempty_legacy_database(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path)
    _insert_placeholder_row(database_path, "payment_orders")
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_meta VALUES ('schema_version', '0');
            """
        )
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="schema_meta"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


def _create_legacy_database(database_path: Path, replacements=(), suffix="") -> None:
    ddl = LEGACY_DDL
    for old, new in replacements:
        assert old in ddl
        ddl = ddl.replace(old, new, 1)
    with sqlite3.connect(database_path) as connection:
        connection.executescript(ddl + suffix)


def _insert_placeholder_row(database_path: Path, table: str) -> None:
    statements = {
        "devices": """
            INSERT INTO devices (
                product_id, device_fingerprint_hash, first_seen_at, last_seen_at
            ) VALUES ('product', 'placeholder-device', '2026-07-13T00:00:00Z',
                      '2026-07-13T00:00:00Z')
        """,
        "licenses": """
            INSERT INTO licenses (
                device_id, license_type, status, starts_at, expires_at, source,
                created_at
            ) VALUES (1, 'trial', 'active', '2026-07-13T00:00:00Z',
                      '2026-07-27T00:00:00Z', 'trial', '2026-07-13T00:00:00Z')
        """,
        "payment_orders": """
            INSERT INTO payment_orders (
                order_id, product_id, device_fingerprint_hash, amount, currency,
                payment_channel, order_status, payment_status, provider_status,
                created_at, expire_at, updated_at
            ) VALUES ('placeholder-order', 'product', 'placeholder-device', '9.9',
                      'CNY', 'wechat_pay', 'created', 'unpaid', 'not_configured',
                      '2026-07-13T00:00:00Z', '2026-07-13T00:15:00Z',
                      '2026-07-13T00:00:00Z')
        """,
    }
    with sqlite3.connect(database_path) as connection:
        connection.execute(statements[table])


def _database_snapshot(database_path: Path) -> list[tuple[object, ...]]:
    with sqlite3.connect(database_path) as connection:
        schema = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        rows = []
        for table in sorted(_tables(connection)):
            if not table.startswith("sqlite_"):
                rows.extend((table, *row) for row in connection.execute(f'SELECT * FROM "{table}"'))
        return [*schema, *rows]


def _table_names(database_path: Path) -> set[str]:
    with sqlite3.connect(database_path) as connection:
        return _tables(connection)


def _tables(connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def _columns(connection, table: str) -> list[str]:
    return [row["name"] for row in connection.execute(f"PRAGMA table_info({table})")]
