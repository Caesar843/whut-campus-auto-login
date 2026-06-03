from pathlib import Path

from campus_login.local_config import APP_DIR_NAME, default_config_path


PRODUCT_ID = "whut-campus-auto-login"
TRIAL_DAYS = 14
PAID_LICENSE_DAYS = 365
PRICE_AMOUNT = "9.9"
PRICE_CURRENCY = "CNY"
DEFAULT_LICENSE_SERVER_URL = "http://127.0.0.1:8787"
APP_VERSION = "0.1.0"
LICENSE_TOKEN_FILE_NAME = "license_token.json"


def default_license_token_path() -> Path:
    return default_config_path().with_name(LICENSE_TOKEN_FILE_NAME)
