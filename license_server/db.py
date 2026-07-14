from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path

from license_server.payment import ANNUAL_V1, OrderStatus


SUPPORTED_SCHEMA_VERSION = 4
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
    "payment_orders": (
        ("id", "INTEGER", 0, None, 1, 0),
        ("order_id", "TEXT", 1, None, 0, 0),
        ("product_id", "TEXT", 1, None, 0, 0),
        ("device_fingerprint_hash", "TEXT", 1, None, 0, 0),
        ("amount", "TEXT", 1, None, 0, 0),
        ("currency", "TEXT", 1, None, 0, 0),
        ("payment_channel", "TEXT", 1, None, 0, 0),
        ("order_status", "TEXT", 1, None, 0, 0),
        ("payment_status", "TEXT", 1, None, 0, 0),
        ("provider_status", "TEXT", 1, None, 0, 0),
        ("provider_order_id", "TEXT", 0, None, 0, 0),
        ("transaction_id", "TEXT", 0, None, 0, 0),
        ("created_at", "TEXT", 1, None, 0, 0),
        ("expire_at", "TEXT", 1, None, 0, 0),
        ("paid_at", "TEXT", 0, None, 0, 0),
        ("closed_at", "TEXT", 0, None, 0, 0),
        ("updated_at", "TEXT", 1, None, 0, 0),
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
    "payment_orders": set(),
}

LEGACY_UNVERSIONED_INDEXES = {
    "devices": {
        (None, 1, "u", 0, (("device_fingerprint_hash", 0, "BINARY"),)),
    },
    "licenses": set(),
    "payment_orders": {
        (None, 1, "u", 0, (("order_id", 0, "BINARY"),)),
        (
            "idx_payment_orders_device_open",
            0,
            "c",
            0,
            (
                ("device_fingerprint_hash", 0, "BINARY"),
                ("payment_status", 0, "BINARY"),
                ("order_status", 0, "BINARY"),
                ("expire_at", 0, "BINARY"),
            ),
        ),
    },
}

SCHEMA_META_INDEXES = {
    (None, 1, "pk", 0, (("key", 0, "BINARY"),)),
}

LEGACY_UNVERSIONED_OBJECTS = {
    ("table", "devices"),
    ("table", "licenses"),
    ("table", "payment_orders"),
    ("index", "idx_payment_orders_device_open"),
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
    "payment_orders": """
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

PAYMENT_ORDER_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS payment_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT NOT NULL UNIQUE,
    device_fingerprint_hash TEXT NOT NULL,
    product_code TEXT NOT NULL,
    amount_fen INTEGER NOT NULL CHECK(amount_fen > 0),
    currency TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        '{OrderStatus.CREATED.value}',
        '{OrderStatus.WAITING_PAYMENT.value}',
        '{OrderStatus.PAID.value}',
        '{OrderStatus.CLOSED.value}',
        '{OrderStatus.ABNORMAL.value}'
    )),
    open_slot TEXT CHECK(open_slot IS NULL OR open_slot = 'open'),
    provider_order_id TEXT,
    provider_transaction_id TEXT UNIQUE,
    provider_trade_state TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    paid_at TEXT,
    closed_at TEXT,
    security_error_code TEXT,
    provider_create_claimed_at TEXT,
    provider_create_attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK(provider_create_attempt_count IN (0, 1)),
    provider_code_url TEXT,
    last_provider_query_at TEXT,
    next_provider_query_at TEXT,
    provider_query_attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK(provider_query_attempt_count >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_orders_device_open_slot
ON payment_orders(device_fingerprint_hash, open_slot);

CREATE INDEX IF NOT EXISTS idx_payment_orders_status
ON payment_orders(status, expires_at);
"""

PAYMENT_ORDER_V2_TABLE_SQL = f"""
CREATE TABLE payment_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT NOT NULL UNIQUE,
    device_fingerprint_hash TEXT NOT NULL,
    product_code TEXT NOT NULL,
    amount_fen INTEGER NOT NULL CHECK(amount_fen > 0),
    currency TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        '{OrderStatus.CREATED.value}',
        '{OrderStatus.WAITING_PAYMENT.value}',
        '{OrderStatus.PAID.value}',
        '{OrderStatus.CLOSED.value}',
        '{OrderStatus.ABNORMAL.value}'
    )),
    open_slot TEXT CHECK(open_slot IS NULL OR open_slot = 'open'),
    provider_order_id TEXT,
    provider_transaction_id TEXT UNIQUE,
    provider_trade_state TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    paid_at TEXT,
    closed_at TEXT,
    security_error_code TEXT
)
"""

PAYMENT_ORDER_V2_COLUMNS = (
    ("id", "INTEGER", 0, None, 1, 0),
    ("order_id", "TEXT", 1, None, 0, 0),
    ("device_fingerprint_hash", "TEXT", 1, None, 0, 0),
    ("product_code", "TEXT", 1, None, 0, 0),
    ("amount_fen", "INTEGER", 1, None, 0, 0),
    ("currency", "TEXT", 1, None, 0, 0),
    ("provider", "TEXT", 1, None, 0, 0),
    ("status", "TEXT", 1, None, 0, 0),
    ("open_slot", "TEXT", 0, None, 0, 0),
    ("provider_order_id", "TEXT", 0, None, 0, 0),
    ("provider_transaction_id", "TEXT", 0, None, 0, 0),
    ("provider_trade_state", "TEXT", 0, None, 0, 0),
    ("created_at", "TEXT", 1, None, 0, 0),
    ("updated_at", "TEXT", 1, None, 0, 0),
    ("expires_at", "TEXT", 1, None, 0, 0),
    ("paid_at", "TEXT", 0, None, 0, 0),
    ("closed_at", "TEXT", 0, None, 0, 0),
    ("security_error_code", "TEXT", 0, None, 0, 0),
)

PAYMENT_ORDER_V3_COLUMNS = PAYMENT_ORDER_V2_COLUMNS + (
    ("provider_create_claimed_at", "TEXT", 0, None, 0, 0),
    ("provider_create_attempt_count", "INTEGER", 1, "0", 0, 0),
    ("provider_code_url", "TEXT", 0, None, 0, 0),
    ("last_provider_query_at", "TEXT", 0, None, 0, 0),
    ("next_provider_query_at", "TEXT", 0, None, 0, 0),
    ("provider_query_attempt_count", "INTEGER", 1, "0", 0, 0),
)

PAYMENT_ORDER_INDEXES = {
    (None, 1, "u", 0, (("order_id", 0, "BINARY"),)),
    (None, 1, "u", 0, (("provider_transaction_id", 0, "BINARY"),)),
    (
        "idx_payment_orders_device_open_slot",
        1,
        "c",
        0,
        (("device_fingerprint_hash", 0, "BINARY"), ("open_slot", 0, "BINARY")),
    ),
    (
        "idx_payment_orders_status",
        0,
        "c",
        0,
        (("status", 0, "BINARY"), ("expires_at", 0, "BINARY")),
    ),
}

PAYMENT_NOTIFICATION_V3_SCHEMA = """
CREATE TABLE IF NOT EXISTS payment_notifications (
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

CREATE INDEX IF NOT EXISTS idx_payment_notifications_order
ON payment_notifications(order_id);

CREATE INDEX IF NOT EXISTS idx_payment_notifications_process
ON payment_notifications(process_status, next_attempt_at);
"""

PAYMENT_NOTIFICATION_V3_COLUMNS = (
    ("id", "INTEGER", 0, None, 1, 0),
    ("provider_notification_id", "TEXT", 1, None, 0, 0),
    ("order_id", "TEXT", 0, None, 0, 0),
    ("out_trade_no", "TEXT", 0, None, 0, 0),
    ("provider", "TEXT", 1, None, 0, 0),
    ("provider_transaction_id", "TEXT", 0, None, 0, 0),
    ("event_type", "TEXT", 0, None, 0, 0),
    ("signature_key_id", "TEXT", 0, None, 0, 0),
    ("signature_valid", "INTEGER", 1, "0", 0, 0),
    ("payload_digest_sha256", "TEXT", 0, None, 0, 0),
    ("reported_trade_type", "TEXT", 0, None, 0, 0),
    ("reported_trade_state", "TEXT", 0, None, 0, 0),
    ("reported_amount_fen", "INTEGER", 0, None, 0, 0),
    ("reported_currency", "TEXT", 0, None, 0, 0),
    ("merchant_identity_valid", "INTEGER", 1, "0", 0, 0),
    ("process_status", "TEXT", 1, None, 0, 0),
    ("security_error_code", "TEXT", 0, None, 0, 0),
    ("failure_code", "TEXT", 0, None, 0, 0),
    ("provider_created_at", "TEXT", 0, None, 0, 0),
    ("received_at", "TEXT", 1, None, 0, 0),
    ("processing_started_at", "TEXT", 0, None, 0, 0),
    ("lease_expires_at", "TEXT", 0, None, 0, 0),
    ("worker_id", "TEXT", 0, None, 0, 0),
    ("processed_at", "TEXT", 0, None, 0, 0),
    ("attempt_count", "INTEGER", 1, "0", 0, 0),
    ("next_attempt_at", "TEXT", 0, None, 0, 0),
)

PAYMENT_NOTIFICATION_V3_INDEXES = {
    (None, 1, "u", 0, (("provider_notification_id", 0, "BINARY"),)),
    (
        "idx_payment_notifications_order",
        0,
        "c",
        0,
        (("order_id", 0, "BINARY"),),
    ),
    (
        "idx_payment_notifications_process",
        0,
        "c",
        0,
        (("process_status", 0, "BINARY"), ("next_attempt_at", 0, "BINARY")),
    ),
}

PAYMENT_NOTIFICATION_V4_TABLE_SQL = """
CREATE TABLE payment_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_notification_id TEXT NOT NULL UNIQUE,
    order_id TEXT,
    out_trade_no TEXT,
    provider TEXT NOT NULL,
    provider_transaction_id TEXT,
    event_type TEXT,
    signature_key_id TEXT,
    signature_valid INTEGER NOT NULL DEFAULT 0 CHECK(signature_valid IN (0, 1)),
    payload_digest_sha256 TEXT,
    reported_trade_type TEXT,
    reported_trade_state TEXT,
    reported_amount_fen INTEGER,
    reported_currency TEXT,
    merchant_identity_valid INTEGER NOT NULL DEFAULT 0
        CHECK(merchant_identity_valid IN (0, 1)),
    process_status TEXT NOT NULL CHECK(process_status IN (
        'RECEIVED', 'PROCESSING', 'PROCESSED', 'RETRY',
        'DUPLICATE', 'ABNORMAL', 'ORPHAN'
    )),
    security_error_code TEXT,
    failure_code TEXT,
    provider_created_at TEXT,
    received_at TEXT NOT NULL,
    processing_started_at TEXT,
    lease_expires_at TEXT,
    worker_id TEXT,
    processed_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    next_attempt_at TEXT,
    reported_appid TEXT,
    reported_mchid TEXT,
    reported_success_at TEXT,
    claim_token TEXT,
    FOREIGN KEY (order_id) REFERENCES payment_orders(order_id),
    CHECK(
        (process_status = 'PROCESSING'
         AND worker_id IS NOT NULL
         AND claim_token IS NOT NULL
         AND processing_started_at IS NOT NULL
         AND lease_expires_at IS NOT NULL
         AND processed_at IS NULL)
        OR
        (process_status <> 'PROCESSING'
         AND worker_id IS NULL
         AND claim_token IS NULL
         AND processing_started_at IS NULL
         AND lease_expires_at IS NULL)
    ),
    CHECK(
        process_status <> 'RETRY'
        OR (next_attempt_at IS NOT NULL
            AND failure_code IS NOT NULL
            AND processed_at IS NULL)
    ),
    CHECK(process_status = 'RETRY' OR next_attempt_at IS NULL),
    CHECK(
        process_status NOT IN ('PROCESSED', 'DUPLICATE', 'ABNORMAL', 'ORPHAN')
        OR processed_at IS NOT NULL
    ),
    CHECK(
        process_status IN ('PROCESSED', 'DUPLICATE', 'ABNORMAL', 'ORPHAN')
        OR processed_at IS NULL
    ),
    CHECK(process_status <> 'PROCESSED' OR failure_code IS NULL),
    CHECK(process_status NOT IN ('ABNORMAL', 'ORPHAN') OR failure_code IS NOT NULL),
    CHECK(
        process_status NOT IN ('RECEIVED', 'PROCESSING', 'RETRY')
        OR (
            out_trade_no IS NOT NULL
            AND provider_transaction_id IS NOT NULL
            AND event_type IS NOT NULL
            AND signature_key_id IS NOT NULL
            AND signature_valid = 1
            AND payload_digest_sha256 IS NOT NULL
            AND reported_trade_type IS NOT NULL
            AND reported_trade_state IS NOT NULL
            AND reported_amount_fen IS NOT NULL
            AND reported_currency IS NOT NULL
            AND merchant_identity_valid = 1
            AND provider_created_at IS NOT NULL
            AND reported_appid IS NOT NULL
            AND reported_mchid IS NOT NULL
            AND reported_success_at IS NOT NULL
        )
    )
)
"""

PAYMENT_NOTIFICATION_SCHEMA = PAYMENT_NOTIFICATION_V4_TABLE_SQL.replace(
    "CREATE TABLE payment_notifications",
    "CREATE TABLE IF NOT EXISTS payment_notifications",
) + """;

CREATE INDEX IF NOT EXISTS idx_payment_notifications_order
ON payment_notifications(order_id);

CREATE INDEX IF NOT EXISTS idx_payment_notifications_process
ON payment_notifications(process_status, next_attempt_at, lease_expires_at, id);
"""

PAYMENT_NOTIFICATION_V4_COLUMNS = PAYMENT_NOTIFICATION_V3_COLUMNS + (
    ("reported_appid", "TEXT", 0, None, 0, 0),
    ("reported_mchid", "TEXT", 0, None, 0, 0),
    ("reported_success_at", "TEXT", 0, None, 0, 0),
    ("claim_token", "TEXT", 0, None, 0, 0),
)

PAYMENT_NOTIFICATION_V4_INDEXES = {
    (None, 1, "u", 0, (("provider_notification_id", 0, "BINARY"),)),
    (
        "idx_payment_notifications_order",
        0,
        "c",
        0,
        (("order_id", 0, "BINARY"),),
    ),
    (
        "idx_payment_notifications_process",
        0,
        "c",
        0,
        (
            ("process_status", 0, "BINARY"),
            ("next_attempt_at", 0, "BINARY"),
            ("lease_expires_at", 0, "BINARY"),
            ("id", 0, "BINARY"),
        ),
    ),
}

LICENSE_GRANT_SCHEMA = """
CREATE TABLE IF NOT EXISTS license_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_order_id TEXT NOT NULL UNIQUE,
    device_fingerprint_hash TEXT NOT NULL,
    license_id INTEGER NOT NULL,
    product_code TEXT NOT NULL,
    grant_days INTEGER NOT NULL CHECK(grant_days > 0),
    previous_expire_at TEXT,
    new_expire_at TEXT,
    granted_at TEXT NOT NULL,
    issued_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (license_id) REFERENCES licenses(id)
);

CREATE INDEX IF NOT EXISTS idx_license_grants_device
ON license_grants(device_fingerprint_hash);
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
    with write_transaction(database_path) as connection:
        unversioned_legacy = False
        if _table_exists(connection, "schema_meta"):
            schema_version = _schema_version(connection)
        else:
            schema_version = 0
            if _has_user_schema_objects(connection):
                _require_exact_empty_legacy_database(connection)
                unversioned_legacy = True
        if schema_version == 3:
            _require_exact_versioned_schema(connection, 3)
            _assert_no_foreign_key_violations(connection)
            _require_safe_v3_payment_notifications(connection)
        elif schema_version == 4:
            _require_exact_versioned_schema(connection, 4)
            _assert_no_foreign_key_violations(connection)
            return
        elif schema_version > 0:
            _assert_no_foreign_key_violations(connection)
        _execute_script(connection, CORE_SCHEMA)
        _drop_legacy_sensitive_columns(connection)
        _ensure_payment_orders(connection)
        _ensure_payment_orders_v3(connection, declared_version=schema_version)
        if unversioned_legacy:
            connection.execute("DROP TABLE payment_orders_legacy_v0")
        _ensure_payment_notifications_v4(
            connection,
            declared_version=schema_version,
        )
        _execute_script(connection, LICENSE_GRANT_SCHEMA)
        if unversioned_legacy:
            _set_schema_version(connection, 1)
        _execute_script(connection, ADMIN_AUDIT_SCHEMA)
        _assert_no_foreign_key_violations(connection)
        if _payment_notifications_signature(connection) != 4:
            raise RuntimeError("payment_notifications V3 to V4 migration failed")
        _set_schema_version(connection, SUPPORTED_SCHEMA_VERSION)


def _require_exact_empty_legacy_database(connection: sqlite3.Connection) -> None:
    expected_tables = set(LEGACY_UNVERSIONED_COLUMNS)
    if _user_schema_objects(connection) != LEGACY_UNVERSIONED_OBJECTS:
        raise RuntimeError(
            "unversioned database schema does not match the supported empty "
            "legacy schema; manual migration required"
        )

    for table in expected_tables:
        if (
            _table_signature(connection, table) != LEGACY_UNVERSIONED_COLUMNS[table]
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

    if any(
        connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        for table in expected_tables
    ):
        raise RuntimeError(
            "unversioned legacy database contains business data; "
            "manual migration required"
        )


def _ensure_payment_orders(connection: sqlite3.Connection) -> None:
    if not _table_exists(connection, "payment_orders"):
        _execute_script(connection, PAYMENT_ORDER_SCHEMA)
        return
    if _payment_orders_is_v1(connection):
        _execute_script(connection, PAYMENT_ORDER_SCHEMA)
        return
    _migrate_legacy_payment_orders(connection)


def _ensure_payment_orders_v3(
    connection: sqlite3.Connection,
    *,
    declared_version: int,
) -> None:
    signature = _payment_orders_signature(connection)
    if declared_version == 3:
        if signature != 3:
            raise RuntimeError(
                "payment_orders schema does not match declared schema version 3"
            )
        return
    if declared_version == 2 and signature != 2:
        raise RuntimeError(
            "payment_orders schema does not match declared schema version 2"
        )
    if signature == 3:
        return
    if signature == 2:
        _migrate_payment_orders_v2_to_v3(connection)
        if _payment_orders_signature(connection) == 3:
            return
    raise RuntimeError("payment_orders schema is not a supported V2 or V3 schema")


def _ensure_payment_notifications_v4(
    connection: sqlite3.Connection,
    *,
    declared_version: int,
) -> None:
    if not _table_exists(connection, "payment_notifications"):
        _execute_script(connection, PAYMENT_NOTIFICATION_SCHEMA)
        return

    signature = _payment_notifications_signature(connection)
    if declared_version == 4:
        if signature != 4:
            raise RuntimeError(
                "payment_notifications schema does not match declared schema version 4"
            )
        return
    if signature == 4:
        raise RuntimeError(
            "payment_notifications schema does not match declared schema version"
        )
    if signature != 3:
        raise RuntimeError("payment_notifications schema is not a supported V3 schema")

    _require_safe_v3_payment_notifications(connection)
    _migrate_payment_notifications_v3_to_v4(connection)


def _payment_notifications_signature(connection: sqlite3.Connection) -> int | None:
    columns = _table_signature(connection, "payment_notifications")
    indexes = _index_signature(connection, "payment_notifications")
    foreign_keys = _foreign_key_signature(connection, "payment_notifications")
    if _table_options(connection, "payment_notifications") != (0, 0):
        return None
    if (
        columns == PAYMENT_NOTIFICATION_V3_COLUMNS
        and indexes == PAYMENT_NOTIFICATION_V3_INDEXES
        and not foreign_keys
        and _table_sql_matches(
            connection,
            "payment_notifications",
            PAYMENT_NOTIFICATION_V3_SCHEMA.split(";")[0].replace(
                "IF NOT EXISTS ", ""
            ),
        )
    ):
        return 3
    if (
        columns == PAYMENT_NOTIFICATION_V4_COLUMNS
        and indexes == PAYMENT_NOTIFICATION_V4_INDEXES
        and foreign_keys
        == {("payment_orders", "order_id", "order_id", "NO ACTION", "NO ACTION", "NONE")}
        and _table_sql_matches(
            connection,
            "payment_notifications",
            PAYMENT_NOTIFICATION_V4_TABLE_SQL,
        )
    ):
        return 4
    return None


def _require_safe_v3_payment_notifications(connection: sqlite3.Connection) -> None:
    unsafe = connection.execute(
        """
        SELECT 1
        FROM payment_notifications
        WHERE process_status NOT IN ('PROCESSED', 'DUPLICATE', 'ABNORMAL', 'ORPHAN')
           OR processed_at IS NULL
           OR worker_id IS NOT NULL
           OR processing_started_at IS NOT NULL
           OR lease_expires_at IS NOT NULL
           OR next_attempt_at IS NOT NULL
           OR signature_valid NOT IN (0, 1)
           OR merchant_identity_valid NOT IN (0, 1)
           OR attempt_count < 0
           OR (process_status = 'PROCESSED' AND failure_code IS NOT NULL)
           OR (process_status IN ('ABNORMAL', 'ORPHAN') AND failure_code IS NULL)
        LIMIT 1
        """
    ).fetchone()
    orphan = connection.execute(
        """
        SELECT 1
        FROM payment_notifications AS notification
        LEFT JOIN payment_orders AS payment_order
          ON payment_order.order_id = notification.order_id
        WHERE notification.order_id IS NOT NULL
          AND payment_order.order_id IS NULL
        LIMIT 1
        """
    ).fetchone()
    if unsafe is not None or orphan is not None:
        raise RuntimeError(
            "unsafe V3 payment notification data; manual migration required"
        )


def _assert_no_foreign_key_violations(connection: sqlite3.Connection) -> None:
    try:
        violation = connection.execute("PRAGMA foreign_key_check").fetchone()
    except sqlite3.DatabaseError:
        raise RuntimeError("DATABASE_FOREIGN_KEY_VIOLATION") from None
    if violation is not None:
        raise RuntimeError("DATABASE_FOREIGN_KEY_VIOLATION")


def _migrate_payment_notifications_v3_to_v4(
    connection: sqlite3.Connection,
) -> None:
    sequence_row = connection.execute(
        "SELECT seq FROM sqlite_sequence WHERE name = 'payment_notifications'"
    ).fetchone()
    sequence = int(sequence_row["seq"]) if sequence_row is not None else 0
    _create_payment_notifications_v4_table(connection)
    _copy_payment_notifications_v3_rows(connection)
    _drop_payment_notifications_v3_table(connection)
    _restore_payment_notifications_sequence(connection, sequence)
    _create_payment_notifications_v4_indexes(connection)


def _create_payment_notifications_v4_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        "ALTER TABLE payment_notifications RENAME TO payment_notifications_v3"
    )
    connection.execute(PAYMENT_NOTIFICATION_V4_TABLE_SQL)


def _copy_payment_notifications_v3_rows(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO payment_notifications (
            id, provider_notification_id, order_id, out_trade_no, provider,
            provider_transaction_id, event_type, signature_key_id,
            signature_valid, payload_digest_sha256, reported_trade_type,
            reported_trade_state, reported_amount_fen, reported_currency,
            merchant_identity_valid, process_status, security_error_code,
            failure_code, provider_created_at, received_at,
            processing_started_at, lease_expires_at, worker_id, processed_at,
            attempt_count, next_attempt_at, reported_appid, reported_mchid,
            reported_success_at, claim_token
        )
        SELECT
            id, provider_notification_id, order_id, out_trade_no, provider,
            provider_transaction_id, event_type, signature_key_id,
            signature_valid, payload_digest_sha256, reported_trade_type,
            reported_trade_state, reported_amount_fen, reported_currency,
            merchant_identity_valid, process_status, security_error_code,
            failure_code, provider_created_at, received_at,
            processing_started_at, lease_expires_at, worker_id, processed_at,
            attempt_count, next_attempt_at, NULL, NULL, NULL, NULL
        FROM payment_notifications_v3
        ORDER BY id
        """
    )


def _drop_payment_notifications_v3_table(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TABLE payment_notifications_v3")


def _restore_payment_notifications_sequence(
    connection: sqlite3.Connection,
    sequence: int,
) -> None:
    cursor = connection.execute(
        """
        UPDATE sqlite_sequence
        SET seq = CASE WHEN seq < ? THEN ? ELSE seq END
        WHERE name = 'payment_notifications'
        """,
        (sequence, sequence),
    )
    if cursor.rowcount == 0:
        connection.execute(
            "INSERT INTO sqlite_sequence (name, seq) VALUES ('payment_notifications', ?)",
            (sequence,),
        )


def _create_payment_notifications_v4_indexes(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE INDEX idx_payment_notifications_order "
        "ON payment_notifications(order_id)"
    )
    connection.execute(
        "CREATE INDEX idx_payment_notifications_process "
        "ON payment_notifications("
        "process_status, next_attempt_at, lease_expires_at, id)"
    )


def _payment_orders_signature(connection: sqlite3.Connection) -> int | None:
    columns = _table_signature(connection, "payment_orders")
    if (
        _index_signature(connection, "payment_orders") != PAYMENT_ORDER_INDEXES
        or _foreign_key_signature(connection, "payment_orders")
        or _table_options(connection, "payment_orders") != (0, 0)
    ):
        return None
    if columns == PAYMENT_ORDER_V2_COLUMNS and _table_sql_matches(
        connection, "payment_orders", PAYMENT_ORDER_V2_TABLE_SQL
    ):
        return 2
    if columns == PAYMENT_ORDER_V3_COLUMNS and _table_sql_matches(
        connection,
        "payment_orders",
        PAYMENT_ORDER_SCHEMA.split(";")[0].replace("IF NOT EXISTS ", ""),
    ):
        return 3
    return None


def _migrate_payment_orders_v2_to_v3(connection: sqlite3.Connection) -> None:
    connection.execute(
        "ALTER TABLE payment_orders ADD COLUMN provider_create_claimed_at TEXT"
    )
    connection.execute(
        """
        ALTER TABLE payment_orders
        ADD COLUMN provider_create_attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK(provider_create_attempt_count IN (0, 1))
        """
    )
    connection.execute("ALTER TABLE payment_orders ADD COLUMN provider_code_url TEXT")
    connection.execute("ALTER TABLE payment_orders ADD COLUMN last_provider_query_at TEXT")
    connection.execute("ALTER TABLE payment_orders ADD COLUMN next_provider_query_at TEXT")
    connection.execute(
        """
        ALTER TABLE payment_orders
        ADD COLUMN provider_query_attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK(provider_query_attempt_count >= 0)
        """
    )


def _migrate_legacy_payment_orders(connection: sqlite3.Connection) -> None:
    rows = connection.execute("SELECT * FROM payment_orders ORDER BY id").fetchall()
    migrated_rows = [_legacy_payment_order(row) for row in rows]
    connection.execute("ALTER TABLE payment_orders RENAME TO payment_orders_legacy_v0")
    _execute_script(connection, PAYMENT_ORDER_SCHEMA)
    connection.executemany(
        """
        INSERT INTO payment_orders (
            order_id, device_fingerprint_hash, product_code, amount_fen,
            currency, provider, status, open_slot, provider_order_id,
            provider_transaction_id, provider_trade_state, created_at, updated_at,
            expires_at, paid_at, closed_at, security_error_code
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        migrated_rows,
    )


def _legacy_payment_order(row: sqlite3.Row) -> tuple[object, ...]:
    amount_fen = _legacy_amount_fen(str(row["amount"]))
    currency = str(row["currency"]).strip().upper()
    if currency != ANNUAL_V1.currency:
        raise RuntimeError(f"legacy payment currency is not supported: {currency}")
    status, open_slot, error_code = _legacy_status(row)
    return (
        str(row["order_id"]),
        str(row["device_fingerprint_hash"]),
        ANNUAL_V1.product_code,
        amount_fen,
        currency,
        str(row["payment_channel"]),
        status,
        open_slot,
        row["provider_order_id"],
        row["transaction_id"],
        str(row["provider_status"]),
        str(row["created_at"]),
        str(row["updated_at"]),
        str(row["expire_at"]),
        row["paid_at"] if status == OrderStatus.ABNORMAL.value else None,
        row["closed_at"] if status == OrderStatus.CLOSED.value else None,
        error_code,
    )


def _legacy_amount_fen(raw_amount: str) -> int:
    try:
        amount = Decimal(raw_amount)
        fen = amount * Decimal(100)
        if fen != fen.to_integral_exact():
            raise InvalidOperation
        amount_fen = int(fen)
    except (InvalidOperation, ValueError) as exc:
        raise RuntimeError(f"legacy payment amount cannot be converted: {raw_amount}") from exc
    if amount_fen != ANNUAL_V1.amount_fen:
        raise RuntimeError(f"legacy payment amount is not supported: {raw_amount}")
    return amount_fen


def _legacy_status(row: sqlite3.Row) -> tuple[str, str | None, str]:
    values = {
        str(row["order_status"]).strip().lower(),
        str(row["payment_status"]).strip().lower(),
        str(row["provider_status"]).strip().lower(),
    }
    paid_like = {"paid", "success", "provider_paid"}
    closed_like = {
        "created",
        "unpaid",
        "pending_payment",
        "not_configured",
        "expired",
        "closed",
    }
    if values & paid_like:
        return OrderStatus.ABNORMAL.value, "open", "legacy_paid_like_status"
    if values <= closed_like:
        return OrderStatus.CLOSED.value, None, "legacy_closed_unpaid_order"
    return OrderStatus.ABNORMAL.value, "open", "legacy_unknown_status"


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


def _require_exact_versioned_schema(
    connection: sqlite3.Connection,
    version: int,
) -> None:
    expected = sqlite3.connect(":memory:")
    expected.row_factory = sqlite3.Row
    expected.execute("PRAGMA foreign_keys = ON")
    try:
        notification_schema = (
            PAYMENT_NOTIFICATION_V3_SCHEMA
            if version == 3
            else PAYMENT_NOTIFICATION_SCHEMA
        )
        for script in (
            CORE_SCHEMA,
            PAYMENT_ORDER_SCHEMA,
            notification_schema,
            LICENSE_GRANT_SCHEMA,
            ADMIN_AUDIT_SCHEMA,
            SCHEMA_META_SQL,
        ):
            _execute_script(expected, script)
        if _schema_structure_signature(connection) != _schema_structure_signature(
            expected
        ):
            raise RuntimeError(
                f"database schema does not match declared schema version {version}"
            )
    finally:
        expected.close()


def _schema_structure_signature(connection: sqlite3.Connection) -> tuple[object, ...]:
    objects = tuple(
        (
            str(row["type"]),
            str(row["name"]),
            str(row["tbl_name"]),
            _normalize_sql(str(row["sql"])),
        )
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
              AND type IN ('table', 'index', 'view', 'trigger')
            ORDER BY type, name
            """
        )
    )
    tables = sorted(
        str(row["name"])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        )
    )
    return (
        objects,
        tuple(
            (
                table,
                _table_signature(connection, table),
                frozenset(_foreign_key_signature(connection, table)),
                frozenset(_index_signature(connection, table)),
                _table_options(connection, table),
            )
            for table in tables
        ),
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


def _payment_orders_is_v1(connection: sqlite3.Connection) -> bool:
    return {
        "product_code",
        "amount_fen",
        "status",
        "open_slot",
        "expires_at",
    } <= _columns(connection, "payment_orders")


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
