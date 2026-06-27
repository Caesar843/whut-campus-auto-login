from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from license_client.constants import PRICE_AMOUNT, PRICE_CURRENCY

DEFAULT_PAYMENT_CHANNELS = ("wechat_pay", "alipay")
DEFAULT_PAYMENT_ORDER_TTL_MINUTES = 15


@dataclass(frozen=True)
class LicenseServerConfig:
    database_path: Path
    private_key_b64: str
    admin_token: str
    payment_amount: str
    payment_currency: str
    payment_channels: tuple[str, ...]
    payment_order_ttl_minutes: int


def load_config() -> LicenseServerConfig:
    database_path = _database_path_from_env()
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
        payment_amount=os.environ.get("PAYMENT_YEARLY_AMOUNT", PRICE_AMOUNT).strip() or PRICE_AMOUNT,
        payment_currency=os.environ.get("PAYMENT_CURRENCY", PRICE_CURRENCY).strip() or PRICE_CURRENCY,
        payment_channels=_payment_channels_from_env(),
        payment_order_ttl_minutes=_payment_order_ttl_minutes_from_env(),
    )


def _database_path_from_env() -> Path:
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if database_url:
        return _sqlite_database_path(database_url)
    return Path(os.environ.get("LICENSE_DB_PATH", "license_server.sqlite3"))


def _sqlite_database_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise RuntimeError("Only sqlite:/// DATABASE_URL values are supported.")
    raw_path = database_url[len(prefix):]
    if not raw_path:
        raise RuntimeError("DATABASE_URL must include a SQLite database path.")
    return Path(unquote(raw_path))


def _payment_channels_from_env() -> tuple[str, ...]:
    raw_channels = os.environ.get("PAYMENT_CHANNELS", ",".join(DEFAULT_PAYMENT_CHANNELS))
    channels = tuple(channel.strip() for channel in raw_channels.split(",") if channel.strip())
    if not channels:
        raise RuntimeError("PAYMENT_CHANNELS must include at least one channel.")
    return channels


def _payment_order_ttl_minutes_from_env() -> int:
    raw_value = os.environ.get(
        "PAYMENT_ORDER_TTL_MINUTES",
        str(DEFAULT_PAYMENT_ORDER_TTL_MINUTES),
    ).strip()
    try:
        ttl_minutes = int(raw_value)
    except ValueError as exc:
        raise RuntimeError("PAYMENT_ORDER_TTL_MINUTES must be an integer.") from exc
    if ttl_minutes < 1:
        raise RuntimeError("PAYMENT_ORDER_TTL_MINUTES must be at least 1.")
    return ttl_minutes
