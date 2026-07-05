from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import unquote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from license_client.constants import PRICE_AMOUNT, PRICE_CURRENCY

DEFAULT_ENVIRONMENT = "development"
VALID_ENVIRONMENTS = {"development", "test", "production"}
DEFAULT_PAYMENT_CHANNELS = ("wechat_pay", "alipay")
DEFAULT_PAYMENT_ORDER_TTL_MINUTES = 15
PRODUCTION_ADMIN_TOKEN_MIN_LENGTH = 32
INSECURE_ADMIN_TOKEN_MARKERS = (
    "change-me",
    "changeme",
    "replace",
    "placeholder",
    "admin-token",
    "admin_placeholder",
    "admin-placeholder",
)


@dataclass(frozen=True)
class LicenseServerConfig:
    environment: str
    database_path: Path
    private_key_b64: str
    admin_token: str
    payment_amount: str
    payment_currency: str
    payment_channels: tuple[str, ...]
    payment_order_ttl_minutes: int


def load_config(env: Mapping[str, str] | None = None) -> LicenseServerConfig:
    values = os.environ if env is None else env
    environment = _environment_from_env(values)
    database_path = _database_path_from_env(values, environment)
    private_key_b64 = _private_key_from_env(values, environment)
    admin_token = _admin_token_from_env(values, environment)
    return LicenseServerConfig(
        environment=environment,
        database_path=database_path,
        private_key_b64=private_key_b64,
        admin_token=admin_token,
        payment_amount=values.get("PAYMENT_YEARLY_AMOUNT", PRICE_AMOUNT).strip() or PRICE_AMOUNT,
        payment_currency=values.get("PAYMENT_CURRENCY", PRICE_CURRENCY).strip() or PRICE_CURRENCY,
        payment_channels=_payment_channels_from_env(values),
        payment_order_ttl_minutes=_payment_order_ttl_minutes_from_env(values),
    )


def is_production_environment(env: Mapping[str, str] | None = None) -> bool:
    values = os.environ if env is None else env
    return _environment_from_env(values) == "production"


def validate_private_key_b64(private_key_b64: str, *, source: str = "LICENSE_PRIVATE_KEY") -> None:
    try:
        key_bytes = base64.b64decode(private_key_b64, validate=True)
        Ed25519PrivateKey.from_private_bytes(key_bytes)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(
            f"{source} must be a base64-encoded 32-byte Ed25519 private key."
        ) from exc


def _environment_from_env(values: Mapping[str, str]) -> str:
    environment = (
        values.get("LICENSE_SERVER_ENV", "").strip()
        or values.get("SERVER_ENV", "").strip()
        or DEFAULT_ENVIRONMENT
    ).lower()
    if environment not in VALID_ENVIRONMENTS:
        allowed = ", ".join(sorted(VALID_ENVIRONMENTS))
        raise RuntimeError(f"LICENSE_SERVER_ENV must be one of: {allowed}.")
    return environment


def _database_path_from_env(values: Mapping[str, str], environment: str) -> Path:
    database_url = values.get("DATABASE_URL", "").strip()
    license_db_path = values.get("LICENSE_DB_PATH", "").strip()
    if environment == "production" and not database_url and not license_db_path:
        raise RuntimeError("DATABASE_URL or LICENSE_DB_PATH is required in production.")
    if database_url:
        database_path = _sqlite_database_path(database_url)
    else:
        database_path = Path(license_db_path or "license_server.sqlite3")
    if environment == "production" and not _is_absolute_path(database_path):
        raise RuntimeError(
            "DATABASE_URL or LICENSE_DB_PATH must be an absolute path in production."
        )
    return database_path


def _sqlite_database_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise RuntimeError("Only sqlite:/// DATABASE_URL values are supported.")
    raw_path = database_url[len(prefix):]
    if not raw_path:
        raise RuntimeError("DATABASE_URL must include a SQLite database path.")
    return Path(unquote(raw_path))


def _private_key_from_env(values: Mapping[str, str], environment: str) -> str:
    private_key_b64 = values.get("LICENSE_PRIVATE_KEY", "").strip()
    private_key_file = values.get("LICENSE_PRIVATE_KEY_FILE", "").strip()
    if not private_key_b64 and private_key_file:
        path = Path(private_key_file)
        if environment == "production" and not _is_absolute_path(path):
            raise RuntimeError("LICENSE_PRIVATE_KEY_FILE must be absolute in production.")
        try:
            private_key_b64 = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(
                f"Failed to read LICENSE_PRIVATE_KEY_FILE: {private_key_file}"
            ) from exc
    if not private_key_b64:
        raise RuntimeError("LICENSE_PRIVATE_KEY or LICENSE_PRIVATE_KEY_FILE is required.")
    validate_private_key_b64(
        private_key_b64,
        source="LICENSE_PRIVATE_KEY_FILE" if private_key_file and not values.get("LICENSE_PRIVATE_KEY", "").strip() else "LICENSE_PRIVATE_KEY",
    )
    return private_key_b64


def _admin_token_from_env(values: Mapping[str, str], environment: str) -> str:
    admin_token = values.get("LICENSE_ADMIN_TOKEN", "").strip()
    if not admin_token:
        raise RuntimeError("LICENSE_ADMIN_TOKEN is required.")
    if environment == "production":
        _validate_production_admin_token(admin_token)
    return admin_token


def _validate_production_admin_token(admin_token: str) -> None:
    normalized = admin_token.lower()
    if len(admin_token) < PRODUCTION_ADMIN_TOKEN_MIN_LENGTH:
        raise RuntimeError(
            "LICENSE_ADMIN_TOKEN must be at least 32 characters in production."
        )
    if any(marker in normalized for marker in INSECURE_ADMIN_TOKEN_MARKERS):
        raise RuntimeError("LICENSE_ADMIN_TOKEN uses an insecure placeholder value.")
    if len(set(admin_token)) < 8:
        raise RuntimeError("LICENSE_ADMIN_TOKEN is too weak for production.")


def _is_absolute_path(path: Path) -> bool:
    return path.is_absolute() or str(path).startswith(("/", "\\"))


def _payment_channels_from_env(values: Mapping[str, str]) -> tuple[str, ...]:
    raw_channels = values.get("PAYMENT_CHANNELS", ",".join(DEFAULT_PAYMENT_CHANNELS))
    channels = tuple(channel.strip() for channel in raw_channels.split(",") if channel.strip())
    if not channels:
        raise RuntimeError("PAYMENT_CHANNELS must include at least one channel.")
    return channels


def _payment_order_ttl_minutes_from_env(values: Mapping[str, str]) -> int:
    raw_value = values.get(
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
