from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import os
import string
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from license_client.constants import PRICE_AMOUNT, PRICE_CURRENCY
from license_server.payment import ANNUAL_V1

if TYPE_CHECKING:
    from license_server.payment_reconciliation_service import (
        PaymentReconciliationPolicy,
    )
    from license_server.payment_reconciliation_worker import (
        PaymentReconciliationWorkerPolicy,
    )

DEFAULT_ENVIRONMENT = "development"
VALID_ENVIRONMENTS = {"development", "test", "production"}
DEFAULT_PAYMENT_CHANNELS = ("wechat_pay",)
DEFAULT_PAYMENT_ORDER_TTL_MINUTES = 15
DEFAULT_PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS = 1.0
MAX_PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS = 300.0
DEFAULT_PAYMENT_NOTIFICATION_MAX_ATTEMPTS = 8
MAX_PAYMENT_NOTIFICATION_MAX_ATTEMPTS = 100
DEFAULT_PAYMENT_NOTIFICATION_LEASE_SECONDS = 60
DEFAULT_PAYMENT_NOTIFICATION_RETRY_BASE_SECONDS = 5
DEFAULT_PAYMENT_NOTIFICATION_RETRY_MAX_SECONDS = 300
DEFAULT_PAYMENT_RECONCILIATION_WORKER_SCAN_INTERVAL_SECONDS = 30
DEFAULT_PAYMENT_RECONCILIATION_WORKER_RECENT_ORDER_WINDOW_SECONDS = 600
DEFAULT_PAYMENT_RECONCILIATION_WORKER_MAX_CLAIMS_PER_CYCLE = 10
DEFAULT_PAYMENT_RECONCILIATION_WORKER_LEASE_SECONDS = 60
DEFAULT_PAYMENT_RECONCILIATION_WORKER_IDLE_WAIT_SECONDS = 1
DEFAULT_PAYMENT_RECONCILIATION_WORKER_MAX_ORDERS_PER_SCAN = 100
DEFAULT_PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS = 5
DEFAULT_PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS = 300
DEFAULT_PAYMENT_RECONCILIATION_MAX_QUERY_ATTEMPTS = 8
DEFAULT_PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS = 5
DEFAULT_PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS = 300
DEFAULT_PAYMENT_RECONCILIATION_MAX_CLOSE_ATTEMPTS = 8
VALID_PAYMENT_PROVIDERS = {"disabled", "mock", "wechat_native"}
MOCK_ADMIN_TOKEN_MIN_LENGTH = 16
SHA256_HEX_LENGTH = 64
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off", ""}
INSECURE_ADMIN_TOKEN_MARKERS = (
    "change-me",
    "changeme",
    "replace",
    "placeholder",
    "admin-token",
    "admin_placeholder",
    "admin-placeholder",
)


@dataclass(frozen=True, repr=False)
class WechatPayConfig:
    app_id: str
    mch_id: str
    merchant_serial_no: str
    merchant_private_key_path: Path
    public_key_id: str
    public_key_path: Path
    api_v3_key: bytes
    notify_url: str


@dataclass(frozen=True, repr=False)
class LicenseServerConfig:
    environment: str
    database_path: Path
    private_key_b64: str
    payment_provider: str | None
    payment_mock_admin_token: str | None
    wechat_pay: WechatPayConfig | None
    payment_price_fen: int
    payment_amount: str
    payment_currency: str
    payment_channels: tuple[str, ...]
    payment_order_ttl_minutes: int
    payment_notification_worker_enabled: bool
    payment_notification_worker_poll_seconds: float
    payment_notification_max_attempts: int
    payment_notification_lease_seconds: int
    payment_notification_retry_base_seconds: int
    payment_notification_retry_max_seconds: int
    payment_reconciliation_worker_enabled: bool
    payment_reconciliation_worker_policy: PaymentReconciliationWorkerPolicy
    payment_reconciliation_policy: PaymentReconciliationPolicy
    admin_enabled: bool
    admin_operator_name: str
    admin_access_token_sha256: str | None


def load_config(env: Mapping[str, str] | None = None) -> LicenseServerConfig:
    values = os.environ if env is None else env
    environment = _environment_from_env(values)
    notification_worker_enabled = _boolean_from_env(
        values,
        "PAYMENT_NOTIFICATION_WORKER_ENABLED",
    )
    reconciliation_worker_enabled = _boolean_from_env(
        values,
        "PAYMENT_RECONCILIATION_WORKER_ENABLED",
    )
    database_path = _database_path_from_env(
        values,
        environment,
        notification_worker_enabled=notification_worker_enabled,
        reconciliation_worker_enabled=reconciliation_worker_enabled,
    )
    private_key_b64 = _private_key_from_env(values, environment)
    payment_price_fen = _payment_price_fen_from_env(values)
    payment_currency = _payment_currency_from_env(values)
    payment_provider = _payment_provider_from_env(values, environment)
    if notification_worker_enabled and payment_provider != "wechat_native":
        raise RuntimeError(
            "PAYMENT_NOTIFICATION_WORKER_ENABLED requires "
            "PAYMENT_PROVIDER=wechat_native."
        )
    if reconciliation_worker_enabled and payment_provider != "wechat_native":
        raise RuntimeError("PAYMENT_RECONCILIATION_WORKER_PROVIDER_UNAVAILABLE")
    reconciliation_worker_policy, reconciliation_policy = (
        _payment_reconciliation_policies_from_env(values)
    )
    return LicenseServerConfig(
        environment=environment,
        database_path=database_path,
        private_key_b64=private_key_b64,
        payment_provider=payment_provider,
        payment_mock_admin_token=_payment_mock_admin_token_from_env(values, environment),
        wechat_pay=_wechat_pay_from_env(values) if payment_provider == "wechat_native" else None,
        payment_price_fen=payment_price_fen,
        payment_amount=_payment_amount_text(payment_price_fen),
        payment_currency=payment_currency,
        payment_channels=_payment_channels_from_env(values),
        payment_order_ttl_minutes=_payment_order_ttl_minutes_from_env(values),
        payment_notification_worker_enabled=notification_worker_enabled,
        payment_notification_worker_poll_seconds=(
            _payment_notification_worker_poll_seconds_from_env(values)
        ),
        payment_notification_max_attempts=(
            _payment_notification_max_attempts_from_env(values)
        ),
        payment_notification_lease_seconds=(
            DEFAULT_PAYMENT_NOTIFICATION_LEASE_SECONDS
        ),
        payment_notification_retry_base_seconds=(
            DEFAULT_PAYMENT_NOTIFICATION_RETRY_BASE_SECONDS
        ),
        payment_notification_retry_max_seconds=(
            DEFAULT_PAYMENT_NOTIFICATION_RETRY_MAX_SECONDS
        ),
        payment_reconciliation_worker_enabled=reconciliation_worker_enabled,
        payment_reconciliation_worker_policy=reconciliation_worker_policy,
        payment_reconciliation_policy=reconciliation_policy,
        admin_enabled=_admin_enabled_from_env(values),
        admin_operator_name=values.get("ADMIN_OPERATOR_NAME", "").strip(),
        admin_access_token_sha256=_admin_access_token_sha256_from_env(values),
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


def _database_path_from_env(
    values: Mapping[str, str],
    environment: str,
    *,
    notification_worker_enabled: bool,
    reconciliation_worker_enabled: bool,
) -> Path:
    database_url = values.get("DATABASE_URL", "").strip()
    license_db_path = values.get("LICENSE_DB_PATH", "").strip()
    if environment == "production" and not database_url and not license_db_path:
        raise RuntimeError("DATABASE_URL or LICENSE_DB_PATH is required in production.")
    if database_url:
        database_path = _sqlite_database_path(database_url)
    else:
        database_path = Path(license_db_path or "license_server.sqlite3")
    if notification_worker_enabled and not _is_absolute_path(database_path):
        raise RuntimeError(
            "PAYMENT_NOTIFICATION_WORKER_DATABASE_PATH_NOT_ABSOLUTE"
        )
    if reconciliation_worker_enabled and not _is_absolute_path(database_path):
        raise RuntimeError(
            "PAYMENT_RECONCILIATION_WORKER_DATABASE_PATH_NOT_ABSOLUTE"
        )
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


def _is_absolute_path(path: Path) -> bool:
    return path.is_absolute() and bool(path.name)


def _payment_channels_from_env(values: Mapping[str, str]) -> tuple[str, ...]:
    raw_channels = values.get("PAYMENT_CHANNELS", ",".join(DEFAULT_PAYMENT_CHANNELS))
    channels = tuple(channel.strip() for channel in raw_channels.split(",") if channel.strip())
    if channels != DEFAULT_PAYMENT_CHANNELS:
        raise RuntimeError("PAYMENT_CHANNELS must be exactly: wechat_pay.")
    return channels


def _payment_provider_from_env(values: Mapping[str, str], environment: str) -> str | None:
    provider = values.get("PAYMENT_PROVIDER", "").strip().lower()
    if not provider:
        if environment == "production" and _raw_mock_admin_token(values):
            raise RuntimeError("PAYMENT_MOCK_ADMIN_TOKEN is not allowed in production.")
        return None
    if provider not in VALID_PAYMENT_PROVIDERS:
        allowed = ", ".join(sorted(VALID_PAYMENT_PROVIDERS))
        raise RuntimeError(f"PAYMENT_PROVIDER must be one of: {allowed}.")
    if environment == "production" and provider == "mock":
        raise RuntimeError("PAYMENT_PROVIDER=mock is not allowed in production.")
    return None if provider == "disabled" else provider


def _wechat_pay_from_env(values: Mapping[str, str]) -> WechatPayConfig:
    required = (
        "WECHAT_PAY_APP_ID",
        "WECHAT_PAY_MCH_ID",
        "WECHAT_PAY_MERCHANT_SERIAL_NO",
        "WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH",
        "WECHAT_PAY_PUBLIC_KEY_ID",
        "WECHAT_PAY_PUBLIC_KEY_PATH",
        "WECHAT_PAY_API_V3_KEY",
        "WECHAT_PAY_NOTIFY_URL",
    )
    missing = [name for name in required if not values.get(name, "").strip()]
    if missing:
        raise RuntimeError(f"{missing[0]} is required when PAYMENT_PROVIDER=wechat_native.")

    merchant_path = Path(values["WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH"].strip())
    public_path = Path(values["WECHAT_PAY_PUBLIC_KEY_PATH"].strip())
    _require_rsa_key(merchant_path, "WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH", private=True)
    _require_rsa_key(public_path, "WECHAT_PAY_PUBLIC_KEY_PATH", private=False)

    api_v3_key = values["WECHAT_PAY_API_V3_KEY"].strip().encode("utf-8")
    if len(api_v3_key) != 32:
        raise RuntimeError("WECHAT_PAY_API_V3_KEY must be exactly 32 bytes.")
    notify_url = values["WECHAT_PAY_NOTIFY_URL"].strip()
    _validate_wechat_notify_url(notify_url)
    return WechatPayConfig(
        app_id=values["WECHAT_PAY_APP_ID"].strip(),
        mch_id=values["WECHAT_PAY_MCH_ID"].strip(),
        merchant_serial_no=values["WECHAT_PAY_MERCHANT_SERIAL_NO"].strip(),
        merchant_private_key_path=merchant_path,
        public_key_id=values["WECHAT_PAY_PUBLIC_KEY_ID"].strip(),
        public_key_path=public_path,
        api_v3_key=api_v3_key,
        notify_url=notify_url,
    )


def _require_rsa_key(path: Path, name: str, *, private: bool) -> None:
    try:
        pem = path.read_bytes()
        key = load_pem_private_key(pem, password=None) if private else load_pem_public_key(pem)
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise RuntimeError(f"{name} must reference a readable RSA key.") from exc
    expected = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
    if not isinstance(key, expected):
        raise RuntimeError(f"{name} must reference a readable RSA key.")


def _validate_wechat_notify_url(value: str) -> None:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise RuntimeError("WECHAT_PAY_NOTIFY_URL must be a safe public HTTPS URL.") from exc
    host = parsed.hostname or ""
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
        or host.casefold().rstrip(".") == "localhost"
        or is_loopback
    ):
        raise RuntimeError("WECHAT_PAY_NOTIFY_URL must be a public HTTPS URL without query or fragment.")


def _payment_mock_admin_token_from_env(
    values: Mapping[str, str],
    environment: str,
) -> str | None:
    token = _raw_mock_admin_token(values)
    if environment == "production" and token:
        raise RuntimeError("PAYMENT_MOCK_ADMIN_TOKEN is not allowed in production.")
    if values.get("PAYMENT_PROVIDER", "").strip().lower() != "mock":
        return None
    if not token:
        raise RuntimeError("PAYMENT_MOCK_ADMIN_TOKEN is required when PAYMENT_PROVIDER=mock.")
    validate_mock_admin_token(token)
    return token


def _raw_mock_admin_token(values: Mapping[str, str]) -> str:
    return (
        values.get("PAYMENT_MOCK_ADMIN_TOKEN", "").strip()
        or values.get("MOCK_PAYMENT_ADMIN_TOKEN", "").strip()
    )


def validate_mock_admin_token(token: str) -> None:
    normalized = token.lower()
    if len(token) < MOCK_ADMIN_TOKEN_MIN_LENGTH:
        raise RuntimeError("PAYMENT_MOCK_ADMIN_TOKEN is too short.")
    if any(marker in normalized for marker in INSECURE_ADMIN_TOKEN_MARKERS):
        raise RuntimeError("PAYMENT_MOCK_ADMIN_TOKEN uses an insecure placeholder value.")
    if len(set(token)) < 8:
        raise RuntimeError("PAYMENT_MOCK_ADMIN_TOKEN is too weak.")


def validate_admin_access_token_sha256(value: str | None) -> None:
    digest = str(value or "").strip().lower()
    if len(digest) != SHA256_HEX_LENGTH or any(
        character not in string.hexdigits for character in digest
    ):
        raise RuntimeError("ADMIN_ACCESS_TOKEN_SHA256 must be a 64-character SHA-256 hex digest.")


def _payment_price_fen_from_env(values: Mapping[str, str]) -> int:
    raw_value = values.get("PAYMENT_PRICE_FEN", str(ANNUAL_V1.amount_fen)).strip()
    try:
        price_fen = int(raw_value)
    except ValueError as exc:
        raise RuntimeError("PAYMENT_PRICE_FEN must be an integer number of fen.") from exc
    if price_fen != ANNUAL_V1.amount_fen:
        raise RuntimeError("PAYMENT_PRICE_FEN must match annual_v1 product catalog.")
    return price_fen


def _payment_currency_from_env(values: Mapping[str, str]) -> str:
    currency = (values.get("PAYMENT_CURRENCY", ANNUAL_V1.currency).strip() or PRICE_CURRENCY).upper()
    if currency != ANNUAL_V1.currency:
        raise RuntimeError("PAYMENT_CURRENCY must match annual_v1 product catalog.")
    return currency


def _payment_amount_text(amount_fen: int) -> str:
    whole, cents = divmod(amount_fen, 100)
    return f"{whole}.{cents:02d}".rstrip("0").rstrip(".")


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


def _boolean_from_env(values: Mapping[str, str], name: str) -> bool:
    value = values.get(name, "")
    if not isinstance(value, str):
        raise RuntimeError(f"{name} must be true or false.")
    raw_value = value.strip().lower()
    if raw_value in TRUE_VALUES:
        return True
    if raw_value in FALSE_VALUES:
        return False
    raise RuntimeError(f"{name} must be true or false.")


def _payment_notification_worker_poll_seconds_from_env(
    values: Mapping[str, str],
) -> float:
    raw_value = values.get(
        "PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS",
        str(DEFAULT_PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS),
    ).strip()
    try:
        poll_seconds = float(raw_value)
    except ValueError as exc:
        raise RuntimeError(
            "PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS must be a finite number."
        ) from exc
    if not math.isfinite(poll_seconds) or not (
        0 < poll_seconds <= MAX_PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS
    ):
        raise RuntimeError(
            "PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS must be greater than 0 "
            f"and at most {MAX_PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS:g}."
        )
    return poll_seconds


def _payment_notification_max_attempts_from_env(
    values: Mapping[str, str],
) -> int:
    raw_value = values.get(
        "PAYMENT_NOTIFICATION_MAX_ATTEMPTS",
        str(DEFAULT_PAYMENT_NOTIFICATION_MAX_ATTEMPTS),
    ).strip(" \t")
    if not raw_value or not raw_value.isascii() or not raw_value.isdigit():
        raise RuntimeError(
            "PAYMENT_NOTIFICATION_MAX_ATTEMPTS must be an integer."
        )
    normalized = raw_value.lstrip("0") or "0"
    maximum = str(MAX_PAYMENT_NOTIFICATION_MAX_ATTEMPTS)
    if len(normalized) > len(maximum) or (
        len(normalized) == len(maximum) and normalized > maximum
    ):
        raise RuntimeError(
            "PAYMENT_NOTIFICATION_MAX_ATTEMPTS must be between 1 and "
            f"{MAX_PAYMENT_NOTIFICATION_MAX_ATTEMPTS}."
        )
    max_attempts = int(normalized)
    if not 1 <= max_attempts <= MAX_PAYMENT_NOTIFICATION_MAX_ATTEMPTS:
        raise RuntimeError(
            "PAYMENT_NOTIFICATION_MAX_ATTEMPTS must be between 1 and "
            f"{MAX_PAYMENT_NOTIFICATION_MAX_ATTEMPTS}."
        )
    return max_attempts


def _payment_reconciliation_policies_from_env(
    values: Mapping[str, str],
) -> tuple[PaymentReconciliationWorkerPolicy, PaymentReconciliationPolicy]:
    from license_server.payment_reconciliation_service import (
        PaymentReconciliationPolicy,
    )
    from license_server.payment_reconciliation_worker import (
        PaymentReconciliationWorkerPolicy,
    )

    worker_values = {
        "scan_interval_seconds": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_WORKER_SCAN_INTERVAL_SECONDS",
            DEFAULT_PAYMENT_RECONCILIATION_WORKER_SCAN_INTERVAL_SECONDS,
        ),
        "recent_order_window_seconds": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_WORKER_RECENT_ORDER_WINDOW_SECONDS",
            DEFAULT_PAYMENT_RECONCILIATION_WORKER_RECENT_ORDER_WINDOW_SECONDS,
        ),
        "max_claims_per_cycle": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_WORKER_MAX_CLAIMS_PER_CYCLE",
            DEFAULT_PAYMENT_RECONCILIATION_WORKER_MAX_CLAIMS_PER_CYCLE,
        ),
        "lease_seconds": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_WORKER_LEASE_SECONDS",
            DEFAULT_PAYMENT_RECONCILIATION_WORKER_LEASE_SECONDS,
        ),
        "idle_wait_seconds": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_WORKER_IDLE_WAIT_SECONDS",
            DEFAULT_PAYMENT_RECONCILIATION_WORKER_IDLE_WAIT_SECONDS,
        ),
        "max_orders_per_scan": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_WORKER_MAX_ORDERS_PER_SCAN",
            DEFAULT_PAYMENT_RECONCILIATION_WORKER_MAX_ORDERS_PER_SCAN,
        ),
    }
    service_values = {
        "query_retry_base_seconds": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS",
            DEFAULT_PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS,
        ),
        "query_retry_max_seconds": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS",
            DEFAULT_PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS,
        ),
        "max_query_attempts": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_MAX_QUERY_ATTEMPTS",
            DEFAULT_PAYMENT_RECONCILIATION_MAX_QUERY_ATTEMPTS,
        ),
        "close_retry_base_seconds": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS",
            DEFAULT_PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS,
        ),
        "close_retry_max_seconds": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS",
            DEFAULT_PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS,
        ),
        "max_close_attempts": _strict_positive_integer_from_env(
            values,
            "PAYMENT_RECONCILIATION_MAX_CLOSE_ATTEMPTS",
            DEFAULT_PAYMENT_RECONCILIATION_MAX_CLOSE_ATTEMPTS,
        ),
    }
    try:
        return (
            PaymentReconciliationWorkerPolicy(**worker_values),
            PaymentReconciliationPolicy(**service_values),
        )
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc


def _strict_positive_integer_from_env(
    values: Mapping[str, str],
    name: str,
    default: int,
) -> int:
    value = values.get(name, str(default))
    if not isinstance(value, str):
        raise RuntimeError(f"{name} must be a positive decimal integer.")
    raw_value = value
    if (
        not raw_value
        or not raw_value.isascii()
        or not raw_value.isdigit()
        or len(raw_value) > 10
    ):
        raise RuntimeError(f"{name} must be a positive decimal integer.")
    parsed = int(raw_value)
    if parsed <= 0:
        raise RuntimeError(f"{name} must be a positive decimal integer.")
    return parsed


def _admin_enabled_from_env(values: Mapping[str, str]) -> bool:
    return _boolean_from_env(values, "ADMIN_ENABLED")


def _admin_access_token_sha256_from_env(values: Mapping[str, str]) -> str | None:
    if not _admin_enabled_from_env(values):
        return None
    digest = values.get("ADMIN_ACCESS_TOKEN_SHA256", "").strip().lower()
    validate_admin_access_token_sha256(digest)
    return digest
