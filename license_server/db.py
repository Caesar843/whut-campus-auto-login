from __future__ import annotations

import sqlite3
from pathlib import Path


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

SCHEMA = """
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

CREATE TABLE IF NOT EXISTS payment_orders (
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

CREATE INDEX IF NOT EXISTS idx_payment_orders_device_open
ON payment_orders(device_fingerprint_hash, payment_status, order_status, expire_at);
"""


def connect(database_path: Path) -> sqlite3.Connection:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(database_path: Path) -> None:
    with connect(database_path) as connection:
        connection.executescript(SCHEMA)
        for table, legacy_columns in (
            ("devices", LEGACY_REMOVED_DEVICE_COLUMNS),
            ("licenses", LEGACY_REMOVED_LICENSE_COLUMNS),
        ):
            columns = {
                str(row["name"])
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for column in legacy_columns:
                if column in columns:
                    connection.execute(f'ALTER TABLE {table} DROP COLUMN "{column}"')
