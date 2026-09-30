"""历史库升级到免费版 schema（版本 6）的边界测试。

免费版核心表只有 devices / licenses / admin_audit_logs / schema_meta。
历史库里可能残留支付时代的表（payment_orders 等）：它们保持原样、不参与结构校验、
也不会被读写；新建库不再创建它们。
"""

import sqlite3
from pathlib import Path

import pytest

import license_server.db as db
from license_server.db import connect, initialize_database


FREE_SCHEMA_VERSION = "6"

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

PAYMENT_ORDER_COLUMNS = [
    "id",
    "order_id",
    "product_id",
    "device_fingerprint_hash",
    "amount",
    "currency",
    "payment_channel",
    "order_status",
    "payment_status",
    "provider_status",
    "provider_order_id",
    "transaction_id",
    "created_at",
    "expire_at",
    "paid_at",
    "closed_at",
    "updated_at",
]


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
        ).fetchone()[0] == FREE_SCHEMA_VERSION
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        # 支付遗留表保持历史结构，不再被迁移成支付时代的 V3 结构
        assert _columns(connection, "payment_orders") == PAYMENT_ORDER_COLUMNS

    assert {
        "devices",
        "licenses",
        "payment_orders",
        "admin_audit_logs",
        "schema_meta",
    } <= tables
    # 免费版不再创建任何支付表，也不再产生 legacy 迁移中间表
    assert "payment_orders_legacy_v0" not in tables
    assert "payment_notifications" not in tables
    assert "payment_reconciliations" not in tables
    assert "license_grants" not in tables
    assert _database_snapshot(database_path) == first


def test_free_schema_creates_no_payment_tables(tmp_path):
    database_path = tmp_path / "license.sqlite3"

    initialize_database(database_path)

    tables = _table_names(database_path)
    assert {name for name in tables if not name.startswith("sqlite_")} == {
        "devices",
        "licenses",
        "admin_audit_logs",
        "schema_meta",
    }
    assert db.SUPPORTED_SCHEMA_VERSION == 6
    assert set(db.LEGACY_PAYMENT_TABLES).isdisjoint(tables)


def test_payment_leftover_tables_are_listed_for_ignoring():
    """历史遗留支付表清单必须覆盖旧库可能出现的表名。"""
    assert {
        "payment_orders",
        "payment_notifications",
        "payment_reconciliations",
        "license_grants",
    } <= set(db.LEGACY_PAYMENT_TABLES)


def test_versioned_legacy_database_upgrades_and_keeps_payment_data(tmp_path):
    """真实历史库：schema_version=1 且带支付表与数据，升级后数据原样保留。"""
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path)
    _insert_placeholder_row(database_path, "devices")
    _insert_placeholder_row(database_path, "licenses")
    _insert_placeholder_row(database_path, "payment_orders")
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_meta VALUES ('schema_version', '1');
            CREATE TABLE payment_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_notification_id TEXT NOT NULL
            );
            INSERT INTO payment_notifications (provider_notification_id) VALUES ('legacy-note');
            """
        )
    before_orders = _rows(database_path, "payment_orders")
    before_notifications = _rows(database_path, "payment_notifications")

    initialize_database(database_path)

    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0] == FREE_SCHEMA_VERSION
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses").fetchone()[0] == 1

    assert _rows(database_path, "payment_orders") == before_orders
    assert _rows(database_path, "payment_notifications") == before_notifications
    assert _database_snapshot_stable_after_second_run(database_path)


def test_database_newer_than_supported_fails_closed(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE schema_meta SET value = '7' WHERE key = 'schema_version'"
        )
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="newer than supported"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before


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
        ).fetchone()[0] == FREE_SCHEMA_VERSION


@pytest.mark.parametrize(
    "old,new",
    [
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
        (
            "PRAGMA user_version = 0;",
            "CREATE INDEX unexpected_license_index ON licenses(status);\nPRAGMA user_version = 0;",
        ),
    ],
    ids=[
        "added-check-constraint",
        "changed-column-order",
        "changed-primary-key",
        "changed-foreign-key",
        "missing-device-unique",
        "extra-index",
    ],
)
def test_legacy_core_schema_mismatch_fails_closed(tmp_path, old, new):
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path, replacements=((old, new),))
    before = _database_snapshot(database_path)

    with pytest.raises(RuntimeError, match="schema does not match.*manual migration required"):
        initialize_database(database_path)

    assert _database_snapshot(database_path) == before
    assert "schema_meta" not in _table_names(database_path)


@pytest.mark.parametrize(
    "old,new",
    [
        ("    paid_at TEXT,\n", ""),
        ("    updated_at TEXT NOT NULL\n", "    updated_at TEXT NOT NULL,\n    unexpected TEXT\n"),
        ("    amount TEXT NOT NULL,", "    amount INTEGER NOT NULL,"),
        ("order_id TEXT NOT NULL UNIQUE", "order_id TEXT NOT NULL"),
        (
            "CREATE INDEX idx_payment_orders_device_open\nON payment_orders(device_fingerprint_hash, payment_status, order_status, expire_at);",
            "",
        ),
        (
            "ON payment_orders(device_fingerprint_hash, payment_status, order_status, expire_at)",
            "ON payment_orders(payment_status, device_fingerprint_hash, order_status, expire_at)",
        ),
    ],
    ids=[
        "missing-column",
        "extra-column",
        "changed-type",
        "missing-order-unique",
        "missing-index",
        "changed-index-order",
    ],
)
def test_legacy_payment_schema_mismatch_is_ignored_and_preserved(tmp_path, old, new):
    """支付遗留表结构异常不再挡住免费版升级，也不会被改写。"""
    database_path = tmp_path / "license.sqlite3"
    _create_legacy_database(database_path, replacements=((old, new),))
    before_columns = _table_columns(database_path, "payment_orders")

    initialize_database(database_path)

    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0] == FREE_SCHEMA_VERSION
    assert _rows(database_path, "payment_orders") == []
    assert _table_columns(database_path, "payment_orders") == before_columns


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


@pytest.mark.parametrize("table", ["devices", "licenses"])
def test_legacy_core_id_without_autoincrement_fails_closed(tmp_path, table):
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


def _database_snapshot_stable_after_second_run(database_path: Path) -> bool:
    first = _database_snapshot(database_path)
    initialize_database(database_path)
    return _database_snapshot(database_path) == first


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
            ) VALUES (1, 'free', 'active', '2026-07-13T00:00:00Z',
                      '9999-12-31T00:00:00Z', 'free', '2026-07-13T00:00:00Z')
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


def _table_columns(database_path: Path, table: str) -> list[str]:
    with sqlite3.connect(database_path) as connection:
        return [
            row[1]
            for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        ]


def _rows(database_path: Path, table: str) -> list[tuple[object, ...]]:
    with sqlite3.connect(database_path) as connection:
        return connection.execute(f'SELECT * FROM "{table}"').fetchall()


def _tables(connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }


def _columns(connection, table: str) -> list[str]:
    return [row["name"] for row in connection.execute(f"PRAGMA table_info({table})")]