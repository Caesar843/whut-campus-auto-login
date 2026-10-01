"""免费版授权服务数据库层。

schema 版本 6 = 免费版核心结构：
    devices / licenses / admin_audit_logs / schema_meta

历史版本遗留的表（payment_orders、payment_notifications、payment_reconciliations、
license_grants 等）已随旧模块一起移除：
- 新建库不再创建这些表；
- 历史库里如果还留着它们，保持原样、不再读写、也不参与结构校验，
  以免误删历史数据。
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path


SUPPORTED_SCHEMA_VERSION = 6
BUSY_TIMEOUT_MS = 5000

LEGACY_REMOVED_DEVICE_COLUMNS = (
    "campus_account_hash",
    "campus_account_masked",
    "device_name",
    "os",
    "app_version",
)
LEGACY_REMOVED_LICENSE_COLUMNS = (
    "revoked_reason",
)

# 免费版核心表：结构会被严格校验。
CORE_TABLES = (
    "devices",
    "licenses",
    "admin_audit_logs",
    "schema_meta",
)

# 历史版本遗留的表：只识别名称，不校验、不读写。
LEGACY_PAYMENT_TABLES = (
    "payment_orders",
    "payment_notifications",
    "payment_reconciliations",
    "license_grants",
    "payment_orders_legacy_v0",
    "payment_notifications_v3",
)

LEGACY_UNVERSIONED_COLUMNS = {
    "devices": (
        ("id", "INTEGER", 0, None, 1, 0),
        ("product_id", "TEXT", 1, None, 0, 0),
        ("device_fingerprint_hash", "TEXT", 1, None, 0, 0),
        ("first_seen_at", "TEXT", 1, None, 0, 0),
        ("last_seen_at", "TEXT", 1, None, 0, 0),
    ),
    "licenses": (
        ("id", "INTEGER", 0, None, 1, 0),
        ("device_id", "INTEGER", 1, None, 0, 0),
        ("license_type", "TEXT", 1, None, 0, 0),
        ("status", "TEXT", 1, None, 0, 0),
        ("starts_at", "TEXT", 1, None, 0, 0),
        ("expires_at", "TEXT", 1, None, 0, 0),
        ("source", "TEXT", 1, None, 0, 0),
        ("order_id", "TEXT", 0, None, 0, 0),
        ("created_at", "TEXT", 1, None, 0, 0),
        ("revoked_at", "TEXT", 0, None, 0, 0),
    ),
}

SCHEMA_META_COLUMNS = (
    ("key", "TEXT", 0, None, 1, 0),
    ("value", "TEXT", 1, None, 0, 0),
)

LEGACY_UNVERSIONED_FOREIGN_KEYS = {
    "devices": set(),
    "licenses": {
        ("devices", "device_id", "id", "NO ACTION", "NO ACTION", "NONE"),
    },
}

LEGACY_UNVERSIONED_INDEXES = {
    "devices": {
        (None, 1, "u", 0, (("device_fingerprint_hash", 0, "BINARY"),)),
    },
    "licenses": set(),
}

SCHEMA_META_INDEXES = {
    (None, 1, "pk", 0, (("key", 0, "BINARY"),)),
}

LEGACY_UNVERSIONED_OBJECTS = {
    ("table", "devices"),
    ("table", "licenses"),
}

LEGACY_UNVERSIONED_TABLE_SQL = {
    "devices": """
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id TEXT NOT NULL,
            device_fingerprint_hash TEXT NOT NULL UNIQUE,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        )
    """,
    "licenses": """
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
        )
    """,
}

SCHEMA_META_SQL = """
    CREATE TABLE schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
"""

CORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id TEXT NOT NULL,
    device_fingerprint_hash TEXT NOT NULL UNIQUE,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
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
"""

ADMIN_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL CHECK(length(trim(actor)) > 0),
    source_ip TEXT NOT NULL CHECK(length(trim(source_ip)) > 0),
    request_id TEXT NOT NULL CHECK(length(trim(request_id)) > 0),
    action TEXT NOT NULL CHECK(length(trim(action)) > 0),
    target_type TEXT NOT NULL CHECK(length(trim(target_type)) > 0),
    target_id TEXT NOT NULL CHECK(length(trim(target_id)) > 0),
    result TEXT NOT NULL CHECK(result IN ('SUCCESS', 'REJECTED', 'FAILED')),
    before_state_json TEXT,
    after_state_json TEXT,
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    failure_code TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_target_created
ON admin_audit_logs(target_type, target_id, created_at);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_created_at
ON admin_audit_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_request_id
ON admin_audit_logs(request_id);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_result
ON admin_audit_logs(result);
"""


def connect(database_path: Path) -> sqlite3.Connection:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def write_transaction(database_path: Path):
    connection = connect(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()
    finally:
        connection.close()


def initialize_database(database_path: Path) -> None:
    """初始化/升级到免费版核心 schema，并兼容历史版本的库。

    历史库（无 schema_meta 的旧库、schema_version 1..5）只做核心表结构与外键校验，
    随后把版本标记为 6；历史版本遗留的表保持原样。
    """
    with write_transaction(database_path) as connection:
        if _table_exists(connection, "schema_meta"):
            _schema_version(connection)
        elif _has_user_schema_objects(connection):
            _require_compatible_legacy_database(connection)
        _assert_no_foreign_key_violations(connection)
        _execute_script(connection, CORE_SCHEMA)
        _drop_legacy_sensitive_columns(connection)
        _execute_script(connection, ADMIN_AUDIT_SCHEMA)
        _assert_no_foreign_key_violations(connection)
        _set_schema_version(connection, SUPPORTED_SCHEMA_VERSION)
        _require_core_schema(connection)


def _require_compatible_legacy_database(connection: sqlite3.Connection) -> None:
    """无 schema_meta 的历史库：允许历史遗留表存在，但核心表必须符合预期且没有业务数据。"""
    core_tables = set(LEGACY_UNVERSIONED_COLUMNS)
    leftover_tables = set(LEGACY_PAYMENT_TABLES)
    unexpected_objects: set[tuple[str, str]] = set()
    for row in connection.execute(
        """
        SELECT type, name, tbl_name
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
          AND type IN ('table', 'index', 'view', 'trigger')
        """
    ):
        object_type = str(row["type"])
        name = str(row["name"])
        table_name = str(row["tbl_name"])
        if object_type == "table":
            if name not in core_tables and name not in leftover_tables:
                unexpected_objects.add((object_type, name))
        elif object_type == "index":
            if table_name in leftover_tables:
                # 历史遗留表的索引随表一起忽略，不校验命名与结构。
                continue
            if table_name not in core_tables or name not in _declared_core_index_names(table_name):
                unexpected_objects.add((object_type, name))
        else:
            # 免费版核心库不使用 view / trigger，历史库里也不接受。
            unexpected_objects.add((object_type, name))
    if unexpected_objects:
        raise RuntimeError(
            "unversioned database schema does not match the supported empty "
            "legacy schema; manual migration required"
        )

    for table, expected_columns in LEGACY_UNVERSIONED_COLUMNS.items():
        if (
            _table_signature(connection, table) != expected_columns
            or _foreign_key_signature(connection, table)
            != LEGACY_UNVERSIONED_FOREIGN_KEYS[table]
            or _index_signature(connection, table) != LEGACY_UNVERSIONED_INDEXES[table]
            or _table_options(connection, table) != (0, 0)
            or not _table_sql_matches(
                connection, table, LEGACY_UNVERSIONED_TABLE_SQL[table]
            )
        ):
            raise RuntimeError(
                "unversioned database schema does not match the supported empty "
                "legacy schema; manual migration required"
            )

    data_tables = [
        table
        for table in (*LEGACY_UNVERSIONED_COLUMNS, *LEGACY_PAYMENT_TABLES)
        if _table_exists(connection, table)
    ]
    if any(
        connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        for table in data_tables
    ):
        raise RuntimeError(
            "unversioned legacy database contains business data; "
            "manual migration required"
        )


def _declared_core_index_names(table: str) -> set[str]:
    """核心 legacy 表允许出现的显式索引名（自动索引不在 sqlite_master 查询里）。"""
    return {
        str(entry[0])
        for entry in LEGACY_UNVERSIONED_INDEXES[table]
        if entry[0] is not None
    }


def _assert_no_foreign_key_violations(connection: sqlite3.Connection) -> None:
    try:
        violation = connection.execute("PRAGMA foreign_key_check").fetchone()
    except sqlite3.DatabaseError:
        raise RuntimeError("DATABASE_FOREIGN_KEY_VIOLATION") from None
    if violation is not None:
        raise RuntimeError("DATABASE_FOREIGN_KEY_VIOLATION")


def _drop_legacy_sensitive_columns(connection: sqlite3.Connection) -> None:
    for table, legacy_columns in (
        ("devices", LEGACY_REMOVED_DEVICE_COLUMNS),
        ("licenses", LEGACY_REMOVED_LICENSE_COLUMNS),
    ):
        if not _table_exists(connection, table):
            continue
        columns = _columns(connection, table)
        for column in legacy_columns:
            if column in columns:
                connection.execute(f'ALTER TABLE {table} DROP COLUMN "{column}"')


def _schema_version(connection: sqlite3.Connection) -> int:
    if not _table_exists(connection, "schema_meta"):
        return 0
    if (
        _table_signature(connection, "schema_meta") != SCHEMA_META_COLUMNS
        or _index_signature(connection, "schema_meta") != SCHEMA_META_INDEXES
        or _table_options(connection, "schema_meta") != (0, 0)
        or not _table_sql_matches(connection, "schema_meta", SCHEMA_META_SQL)
    ):
        raise RuntimeError("schema_meta structure is invalid")

    rows = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError("schema_meta must contain exactly one schema_version row")
    raw_version = str(rows[0]["value"])
    try:
        schema_version = int(raw_version)
    except ValueError as exc:
        raise RuntimeError("schema_meta schema_version is not a valid integer") from exc
    if raw_version != str(schema_version) or schema_version <= 0:
        raise RuntimeError("schema_meta schema_version is invalid")
    if schema_version > SUPPORTED_SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {schema_version} is newer than supported "
            f"{SUPPORTED_SCHEMA_VERSION}"
        )
    return schema_version


def _require_core_schema(connection: sqlite3.Connection) -> None:
    """只校验免费版核心表；历史遗留的表不参与校验。"""
    expected = sqlite3.connect(":memory:")
    expected.row_factory = sqlite3.Row
    expected.execute("PRAGMA foreign_keys = ON")
    try:
        _execute_script(expected, CORE_SCHEMA)
        _execute_script(expected, ADMIN_AUDIT_SCHEMA)
        _execute_script(expected, SCHEMA_META_SQL)
        if _core_structure_signature(connection) != _core_structure_signature(expected):
            raise RuntimeError("database schema does not match the free-version core schema")
    finally:
        expected.close()


def _core_structure_signature(connection: sqlite3.Connection) -> tuple[object, ...]:
    return tuple(
        (
            table,
            _table_signature(connection, table),
            frozenset(_foreign_key_signature(connection, table)),
            frozenset(_index_signature(connection, table)),
            _table_options(connection, table),
            _table_object_sql(connection, table),
        )
        for table in CORE_TABLES
    )


def _table_object_sql(
    connection: sqlite3.Connection, table: str
) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (
            str(row["type"]),
            str(row["name"]),
            _normalize_sql(str(row["sql"] or "")),
        )
        for row in connection.execute(
            """
            SELECT type, name, sql
            FROM sqlite_master
            WHERE tbl_name = ?
              AND name NOT LIKE 'sqlite_%'
              AND type IN ('table', 'index')
            ORDER BY type, name
            """,
            (table,),
        )
    )


def _set_schema_version(connection: sqlite3.Connection, version: int) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO schema_meta (key, value)
        VALUES ('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (str(version),),
    )


def _execute_script(connection: sqlite3.Connection, script: str) -> None:
    for statement in script.split(";"):
        statement = statement.strip()
        if statement:
            connection.execute(statement)


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _has_user_schema_objects(connection: sqlite3.Connection) -> bool:
    return bool(_user_schema_objects(connection))


def _user_schema_objects(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    return {
        (str(row["type"]), str(row["name"]))
        for row in connection.execute(
            """
            SELECT type, name
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
              AND type IN ('table', 'index', 'view', 'trigger')
            """
        )
    }


def _table_signature(
    connection: sqlite3.Connection, table: str
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            str(row["name"]),
            str(row["type"]),
            int(row["notnull"]),
            row["dflt_value"],
            int(row["pk"]),
            int(row["hidden"]),
        )
        for row in connection.execute(f'PRAGMA table_xinfo("{table}")')
    )


def _table_sql_matches(
    connection: sqlite3.Connection, table: str, expected_sql: str
) -> bool:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if row is None or not isinstance(row["sql"], str):
        return False
    return _normalize_sql(row["sql"]) == _normalize_sql(expected_sql)


def _normalize_sql(sql: str) -> str:
    tokens = []
    index = 0
    closing_quotes = {"'": "'", '"': '"', "`": "`", "[": "]"}
    while index < len(sql):
        character = sql[index]
        if character.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            end = sql.find("\n", index)
            end = len(sql) if end < 0 else end
            tokens.append(sql[index:end])
            index = end
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            end = len(sql) if end < 0 else end + 2
            tokens.append(sql[index:end])
            index = end
            continue
        if character in closing_quotes:
            closing = closing_quotes[character]
            start = index
            index += 1
            while index < len(sql):
                if sql[index] != closing:
                    index += 1
                    continue
                if index + 1 < len(sql) and sql[index + 1] == closing:
                    index += 2
                    continue
                index += 1
                break
            tokens.append(sql[start:index])
            continue
        if character.isalnum() or character in {"_", "$"}:
            start = index
            index += 1
            while index < len(sql) and (
                sql[index].isalnum() or sql[index] in {"_", "$"}
            ):
                index += 1
            tokens.append(sql[start:index].casefold())
            continue
        tokens.append(character)
        index += 1
    return "\x1f".join(tokens)


def _foreign_key_signature(
    connection: sqlite3.Connection, table: str
) -> set[tuple[object, ...]]:
    return {
        (
            str(row["table"]),
            str(row["from"]),
            str(row["to"]),
            str(row["on_update"]),
            str(row["on_delete"]),
            str(row["match"]),
        )
        for row in connection.execute(f'PRAGMA foreign_key_list("{table}")')
    }


def _index_signature(
    connection: sqlite3.Connection, table: str
) -> set[tuple[object, ...]]:
    indexes = set()
    for row in connection.execute(f'PRAGMA index_list("{table}")'):
        name = str(row["name"])
        quoted_name = name.replace('"', '""')
        columns = tuple(
            (str(column["name"]), int(column["desc"]), str(column["coll"]))
            for column in connection.execute(f'PRAGMA index_xinfo("{quoted_name}")')
            if int(column["key"])
        )
        indexes.add(
            (
                name if str(row["origin"]) == "c" else None,
                int(row["unique"]),
                str(row["origin"]),
                int(row["partial"]),
                columns,
            )
        )
    return indexes


def _table_options(connection: sqlite3.Connection, table: str) -> tuple[int, int]:
    row = connection.execute(
        "SELECT wr, strict FROM pragma_table_list WHERE schema = 'main' AND name = ?",
        (table,),
    ).fetchone()
    return (int(row["wr"]), int(row["strict"])) if row is not None else (-1, -1)


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row["name"])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }