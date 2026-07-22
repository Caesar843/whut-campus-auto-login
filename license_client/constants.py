import os
from pathlib import Path
from typing import Callable, Mapping, Optional

from campus_login.local_config import APP_DIR_NAME, default_config_path
from license_client.public_key import (
    EmbeddedConfig,
    RELEASE_BUILD_ENVIRONMENTS,
    resolve_build_environment,
    resolve_embedded_license_server_url,
    validate_release_server_url,
)


PRODUCT_ID = "whut-campus-auto-login"
TRIAL_DAYS = 14
PAID_LICENSE_DAYS = 365
PRICE_AMOUNT = "9.9"
PRICE_CURRENCY = "CNY"
DEFAULT_LICENSE_SERVER_URL = "http://127.0.0.1:8787"
APP_VERSION = "0.1.0"
LICENSE_TOKEN_FILE_NAME = "license_token.json"


def resolve_license_server_url(
    env: Optional[Mapping[str, str]] = None,
    *,
    embedded_config_loader: Optional[Callable[[], EmbeddedConfig]] = None,
) -> str:
    build_environment = resolve_build_environment(
        embedded_config_loader=embedded_config_loader,
    )
    if build_environment in RELEASE_BUILD_ENVIRONMENTS:
        return validate_release_server_url(
            resolve_embedded_license_server_url(
                embedded_config_loader=embedded_config_loader,
            )
        )
    if build_environment != "development":
        raise RuntimeError("Embedded build configuration is missing or invalid.")
    values = os.environ if env is None else env
    configured_url = values.get("LICENSE_SERVER_URL", "").strip()
    return (configured_url or DEFAULT_LICENSE_SERVER_URL).rstrip("/")


def default_license_token_path() -> Path:
    return default_config_path().with_name(LICENSE_TOKEN_FILE_NAME)
