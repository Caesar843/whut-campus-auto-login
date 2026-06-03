from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id TEXT NOT NULL,
    device_fingerprint_hash TEXT NOT NULL UNIQUE,
    device_name TEXT,
    os TEXT,
    app_version TEXT,
    campus_account_hash TEXT,
    campus_account_masked TEXT,
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
    revoked_reason TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
"""


def connect(database_path: Path) -> sqlite3.Connection:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(database_path: Path) -> None:
    with connect(database_path) as connection:
        connection.executescript(SCHEMA)
