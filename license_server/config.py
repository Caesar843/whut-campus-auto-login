from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LicenseServerConfig:
    database_path: Path
    private_key_b64: str
    admin_token: str


def load_config() -> LicenseServerConfig:
    database_path = Path(os.environ.get("LICENSE_DB_PATH", "license_server.sqlite3"))
    private_key_b64 = os.environ.get("LICENSE_PRIVATE_KEY", "").strip()
    private_key_file = os.environ.get("LICENSE_PRIVATE_KEY_FILE", "").strip()
    if not private_key_b64 and private_key_file:
        private_key_b64 = Path(private_key_file).read_text(encoding="utf-8").strip()
    admin_token = os.environ.get("LICENSE_ADMIN_TOKEN", "").strip()
    if not private_key_b64:
        raise RuntimeError("LICENSE_PRIVATE_KEY or LICENSE_PRIVATE_KEY_FILE is required.")
    if not admin_token:
        raise RuntimeError("LICENSE_ADMIN_TOKEN is required.")
    return LicenseServerConfig(
        database_path=database_path,
        private_key_b64=private_key_b64,
        admin_token=admin_token,
    )
