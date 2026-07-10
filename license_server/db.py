from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path

from license_server.payment import ANNUAL_V1, OrderStatus


SUPPORTED_SCHEMA_VERSION = 2
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
    security_error_code TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_orders_device_open_slot
ON payment_orders(device_fingerprint_hash, open_slot);

CREATE INDEX IF NOT EXISTS idx_payment_orders_status
ON payment_orders(status, expires_at);
"""

PAYMENT_NOTIFICATION_SCHEMA = """
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
        schema_version = _schema_version(connection)
        if schema_version > SUPPORTED_SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {schema_version} is newer than supported "
                f"{SUPPORTED_SCHEMA_VERSION}"
            )
        _execute_script(connection, CORE_SCHEMA)
        _drop_legacy_sensitive_columns(connection)
        _ensure_payment_orders(connection)
        _execute_script(connection, PAYMENT_NOTIFICATION_SCHEMA)
        _execute_script(connection, LICENSE_GRANT_SCHEMA)
        _execute_script(connection, ADMIN_AUDIT_SCHEMA)
        _set_schema_version(connection, SUPPORTED_SCHEMA_VERSION)


def _ensure_payment_orders(connection: sqlite3.Connection) -> None:
    if not _table_exists(connection, "payment_orders"):
        _execute_script(connection, PAYMENT_ORDER_SCHEMA)
        return
    if _payment_orders_is_v1(connection):
        _execute_script(connection, PAYMENT_ORDER_SCHEMA)
        return
    _migrate_legacy_payment_orders(connection)


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
    row = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()
    return int(row["value"]) if row is not None else 0


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


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row["name"])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
