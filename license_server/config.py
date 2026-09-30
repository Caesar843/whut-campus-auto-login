from __future__ import annotations

import os
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import unquote

from license_server.ed25519_keys import (
    Ed25519KeyFormatError,
    validate_private_key_b64_text,
)

DEFAULT_ENVIRONMENT = "development"
VALID_ENVIRONMENTS = {"development", "test", "production"}
SHA256_HEX_LENGTH = 64
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off", ""}


@dataclass(frozen=True, repr=False)
class LicenseServerConfig:
    """免费版授权服务配置：只保留设备注册/授权签发与后台所需项。

    支付相关的配置项已随支付模块一并移除，授权服务不再承载任何支付能力。
    """

    environment: str
    database_path: Path
    private_key_b64: str
    admin_enabled: bool
    admin_operator_name: str
    admin_access_token_sha256: str | None
    runtime_attestation_enabled: bool
    runtime_source_commit: str | None


def load_config(env: Mapping[str, str] | None = None) -> LicenseServerConfig:
    values = os.environ if env is None else env
    environment = _environment_from_env(values)
    database_path = _database_path_from_env(values, environment)
    private_key_b64 = _private_key_from_env(values, environment)
    runtime_attestation_enabled, runtime_source_commit = (
        _runtime_attestation_from_env(values, environment)
    )
    return LicenseServerConfig(
        environment=environment,
        database_path=database_path,
        private_key_b64=private_key_b64,
        admin_enabled=_admin_enabled_from_env(values),
        admin_operator_name=values.get("ADMIN_OPERATOR_NAME", "").strip(),
        admin_access_token_sha256=_admin_access_token_sha256_from_env(values),
        runtime_attestation_enabled=runtime_attestation_enabled,
        runtime_source_commit=runtime_source_commit,
    )


def is_production_environment(env: Mapping[str, str] | None = None) -> bool:
    values = os.environ if env is None else env
    return _environment_from_env(values) == "production"


def validate_private_key_b64(private_key_b64: str, *, source: str = "LICENSE_PRIVATE_KEY") -> None:
    try:
        validate_private_key_b64_text(private_key_b64, source=source)
    except Ed25519KeyFormatError as exc:
        raise RuntimeError(str(exc)) from exc


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


def _is_absolute_path(path: Path) -> bool:
    return path.is_absolute() and bool(path.name)


def validate_admin_access_token_sha256(value: str | None) -> None:
    digest = str(value or "").strip().lower()
    if len(digest) != SHA256_HEX_LENGTH or any(
        character not in string.hexdigits for character in digest
    ):
        raise RuntimeError("ADMIN_ACCESS_TOKEN_SHA256 must be a 64-character SHA-256 hex digest.")


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


def _runtime_attestation_from_env(
    values: Mapping[str, str],
    environment: str,
) -> tuple[bool, str | None]:
    enabled = _boolean_from_env(
        values,
        "LICENSE_RUNTIME_ATTESTATION_ENABLED",
    )
    if not enabled:
        return False, None
    if environment != "production":
        raise RuntimeError(
            "LICENSE_RUNTIME_ATTESTATION_ENABLED requires production."
        )
    source_commit = values.get("LICENSE_RUNTIME_SOURCE_COMMIT", "").strip()
    if (
        len(source_commit) != 40
        or not source_commit.isascii()
        or any(character not in "0123456789abcdef" for character in source_commit)
    ):
        raise RuntimeError(
            "LICENSE_RUNTIME_SOURCE_COMMIT must be a 40-character lowercase "
            "Git commit."
        )
    from license_server.runtime_attestation import (
        require_supported_production_platform,
    )

    require_supported_production_platform()
    return True, source_commit


def _admin_enabled_from_env(values: Mapping[str, str]) -> bool:
    return _boolean_from_env(values, "ADMIN_ENABLED")


def _admin_access_token_sha256_from_env(values: Mapping[str, str]) -> str | None:
    if not _admin_enabled_from_env(values):
        return None
    digest = values.get("ADMIN_ACCESS_TOKEN_SHA256", "").strip().lower()
    validate_admin_access_token_sha256(digest)
    return digest