import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from license_server.config import load_config
from tests.license_server.test_license_server import _production_env


WECHAT_KEYS = (
    "WECHAT_PAY_APP_ID",
    "WECHAT_PAY_MCH_ID",
    "WECHAT_PAY_MERCHANT_SERIAL_NO",
    "WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH",
    "WECHAT_PAY_PUBLIC_KEY_ID",
    "WECHAT_PAY_PUBLIC_KEY_PATH",
    "WECHAT_PAY_API_V3_KEY",
    "WECHAT_PAY_NOTIFY_URL",
)


def test_explicit_disabled_payment_provider_loads_without_wechat_config(tmp_path):
    config = load_config(_production_env(tmp_path, PAYMENT_PROVIDER="disabled"))

    assert config.payment_provider is None
    assert config.wechat_pay is None


def test_payment_notification_worker_defaults_are_disabled_and_bounded(tmp_path):
    config = load_config(_production_env(tmp_path, PAYMENT_PROVIDER="disabled"))

    assert config.payment_notification_worker_enabled is False
    assert config.payment_notification_worker_poll_seconds == 1.0
    assert config.payment_notification_max_attempts == 8
    assert config.payment_notification_lease_seconds == 60
    assert config.payment_notification_retry_base_seconds == 5
    assert config.payment_notification_retry_max_seconds == 300


def test_payment_reconciliation_worker_defaults_are_disabled_and_bounded(tmp_path):
    config = load_config(_production_env(tmp_path, PAYMENT_PROVIDER="disabled"))

    assert config.payment_reconciliation_worker_enabled is False
    assert config.payment_reconciliation_worker_policy.scan_interval_seconds == 30
    assert config.payment_reconciliation_worker_policy.recent_order_window_seconds == 600
    assert config.payment_reconciliation_worker_policy.max_claims_per_cycle == 10
    assert config.payment_reconciliation_worker_policy.lease_seconds == 60
    assert config.payment_reconciliation_worker_policy.idle_wait_seconds == 1
    assert config.payment_reconciliation_worker_policy.max_orders_per_scan == 100
    assert config.payment_reconciliation_policy.query_retry_base_seconds == 5
    assert config.payment_reconciliation_policy.query_retry_max_seconds == 300
    assert config.payment_reconciliation_policy.max_query_attempts == 8
    assert config.payment_reconciliation_policy.close_retry_base_seconds == 5
    assert config.payment_reconciliation_policy.close_retry_max_seconds == 300
    assert config.payment_reconciliation_policy.max_close_attempts == 8


@pytest.mark.parametrize("value", ("1", "true", "yes", "on", "TRUE"))
def test_payment_reconciliation_worker_accepts_enabled_values(tmp_path, value):
    env = _wechat_env(tmp_path)
    env["PAYMENT_RECONCILIATION_WORKER_ENABLED"] = value

    assert load_config(env).payment_reconciliation_worker_enabled is True


@pytest.mark.parametrize("value", ("0", "false", "no", "off", "", "FALSE"))
def test_payment_reconciliation_worker_accepts_disabled_values(tmp_path, value):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_RECONCILIATION_WORKER_ENABLED=value,
    )

    assert load_config(env).payment_reconciliation_worker_enabled is False


@pytest.mark.parametrize("value", ("enabled", "2", "none"))
def test_payment_reconciliation_worker_rejects_invalid_boolean(tmp_path, value):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_RECONCILIATION_WORKER_ENABLED=value,
    )

    with pytest.raises(RuntimeError, match="PAYMENT_RECONCILIATION_WORKER_ENABLED"):
        load_config(env)


RECONCILIATION_INTEGER_SETTINGS = (
    ("PAYMENT_RECONCILIATION_WORKER_SCAN_INTERVAL_SECONDS", 30),
    ("PAYMENT_RECONCILIATION_WORKER_RECENT_ORDER_WINDOW_SECONDS", 600),
    ("PAYMENT_RECONCILIATION_WORKER_MAX_CLAIMS_PER_CYCLE", 10),
    ("PAYMENT_RECONCILIATION_WORKER_LEASE_SECONDS", 60),
    ("PAYMENT_RECONCILIATION_WORKER_IDLE_WAIT_SECONDS", 1),
    ("PAYMENT_RECONCILIATION_WORKER_MAX_ORDERS_PER_SCAN", 100),
    ("PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS", 5),
    ("PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS", 300),
    ("PAYMENT_RECONCILIATION_MAX_QUERY_ATTEMPTS", 8),
    ("PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS", 5),
    ("PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS", 300),
    ("PAYMENT_RECONCILIATION_MAX_CLOSE_ATTEMPTS", 8),
)


@pytest.mark.parametrize(("name", "expected"), RECONCILIATION_INTEGER_SETTINGS)
def test_payment_reconciliation_worker_accepts_strict_positive_integer_settings(
    tmp_path, name, expected
):
    env = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    env[name] = f"00{expected}"

    config = load_config(env)

    values = {
        "PAYMENT_RECONCILIATION_WORKER_SCAN_INTERVAL_SECONDS": (
            config.payment_reconciliation_worker_policy.scan_interval_seconds
        ),
        "PAYMENT_RECONCILIATION_WORKER_RECENT_ORDER_WINDOW_SECONDS": (
            config.payment_reconciliation_worker_policy.recent_order_window_seconds
        ),
        "PAYMENT_RECONCILIATION_WORKER_MAX_CLAIMS_PER_CYCLE": (
            config.payment_reconciliation_worker_policy.max_claims_per_cycle
        ),
        "PAYMENT_RECONCILIATION_WORKER_LEASE_SECONDS": (
            config.payment_reconciliation_worker_policy.lease_seconds
        ),
        "PAYMENT_RECONCILIATION_WORKER_IDLE_WAIT_SECONDS": (
            config.payment_reconciliation_worker_policy.idle_wait_seconds
        ),
        "PAYMENT_RECONCILIATION_WORKER_MAX_ORDERS_PER_SCAN": (
            config.payment_reconciliation_worker_policy.max_orders_per_scan
        ),
        "PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS": (
            config.payment_reconciliation_policy.query_retry_base_seconds
        ),
        "PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS": (
            config.payment_reconciliation_policy.query_retry_max_seconds
        ),
        "PAYMENT_RECONCILIATION_MAX_QUERY_ATTEMPTS": (
            config.payment_reconciliation_policy.max_query_attempts
        ),
        "PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS": (
            config.payment_reconciliation_policy.close_retry_base_seconds
        ),
        "PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS": (
            config.payment_reconciliation_policy.close_retry_max_seconds
        ),
        "PAYMENT_RECONCILIATION_MAX_CLOSE_ATTEMPTS": (
            config.payment_reconciliation_policy.max_close_attempts
        ),
    }
    assert values[name] == expected


@pytest.mark.parametrize(("name", "_default"), RECONCILIATION_INTEGER_SETTINGS)
@pytest.mark.parametrize(
    "value",
    ("", "0", "-1", "+1", "1.5", "nan", "inf", "true", "９", "9" * 5000, True),
)
def test_payment_reconciliation_worker_rejects_non_strict_integer_settings(
    tmp_path, name, _default, value
):
    env = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    env[name] = value

    with pytest.raises(RuntimeError, match=name) as exc_info:
        load_config(env)

    if str(value):
        assert str(value) not in str(exc_info.value) or str(value) == name


@pytest.mark.parametrize("value", (" 1", "1 ", "\t1", "1\t"))
def test_payment_reconciliation_worker_rejects_integer_whitespace(tmp_path, value):
    env = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    name = "PAYMENT_RECONCILIATION_WORKER_SCAN_INTERVAL_SECONDS"
    env[name] = value

    with pytest.raises(RuntimeError, match=name):
        load_config(env)


@pytest.mark.parametrize(
    "overrides",
    (
        {
            "PAYMENT_RECONCILIATION_WORKER_SCAN_INTERVAL_SECONDS": "1",
            "PAYMENT_RECONCILIATION_WORKER_IDLE_WAIT_SECONDS": "2",
        },
        {
            "PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS": "10",
            "PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS": "5",
        },
        {
            "PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS": "10",
            "PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS": "5",
        },
    ),
)
def test_payment_reconciliation_worker_reuses_policy_cross_field_validation(
    tmp_path, overrides
):
    env = _production_env(tmp_path, PAYMENT_PROVIDER="disabled", **overrides)

    with pytest.raises(RuntimeError, match="PAYMENT_RECONCILIATION_.*POLICY_INVALID"):
        load_config(env)


def test_enabled_payment_reconciliation_worker_rejects_non_wechat_provider(tmp_path):
    env = _production_env(
        tmp_path,
        LICENSE_SERVER_ENV="development",
        PAYMENT_PROVIDER="mock",
        PAYMENT_MOCK_ADMIN_TOKEN="localR4ndomValue123456",
        PAYMENT_RECONCILIATION_WORKER_ENABLED="true",
    )

    with pytest.raises(RuntimeError, match="PAYMENT_RECONCILIATION_WORKER_PROVIDER"):
        load_config(env)


@pytest.mark.parametrize("environment", ("development", "test", "production"))
def test_enabled_payment_reconciliation_worker_requires_absolute_database_path(
    monkeypatch, tmp_path, environment
):
    env = _wechat_env(tmp_path)
    env.update(
        LICENSE_SERVER_ENV=environment,
        DATABASE_URL="sqlite:///relative-reconciliation.sqlite3",
        PAYMENT_RECONCILIATION_WORKER_ENABLED="true",
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(
        RuntimeError,
        match="PAYMENT_RECONCILIATION_WORKER_DATABASE_PATH_NOT_ABSOLUTE",
    ):
        load_config(env)

    assert not (tmp_path / "relative-reconciliation.sqlite3").exists()


@pytest.mark.parametrize("value", ("1", "true", "yes", "on", "TRUE"))
def test_payment_notification_worker_accepts_enabled_values(tmp_path, value):
    env = _wechat_env(tmp_path)
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = value

    assert load_config(env).payment_notification_worker_enabled is True


@pytest.mark.parametrize("value", ("0", "false", "no", "off", "", "FALSE"))
def test_payment_notification_worker_accepts_disabled_values(tmp_path, value):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_NOTIFICATION_WORKER_ENABLED=value,
    )

    assert load_config(env).payment_notification_worker_enabled is False


@pytest.mark.parametrize("value", ("enabled", "2", "none"))
def test_payment_notification_worker_rejects_invalid_boolean(tmp_path, value):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_NOTIFICATION_WORKER_ENABLED=value,
    )

    with pytest.raises(RuntimeError, match="PAYMENT_NOTIFICATION_WORKER_ENABLED"):
        load_config(env)


@pytest.mark.parametrize(
    ("value", "expected"),
    (("0.25", 0.25), ("1", 1.0), ("300", 300.0)),
)
def test_payment_notification_worker_accepts_bounded_poll_seconds(
    tmp_path, value, expected
):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS=value,
    )

    assert load_config(env).payment_notification_worker_poll_seconds == expected


@pytest.mark.parametrize(
    "value",
    ("", "0", "-1", "nan", "inf", "-inf", "301", "true", "1e309"),
)
def test_payment_notification_worker_rejects_invalid_poll_seconds(tmp_path, value):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS=value,
    )

    with pytest.raises(RuntimeError, match="PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS"):
        load_config(env)


@pytest.mark.parametrize("value", ("1", "8", "008", "100"))
def test_payment_notification_worker_accepts_bounded_max_attempts(tmp_path, value):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_NOTIFICATION_MAX_ATTEMPTS=value,
    )

    assert load_config(env).payment_notification_max_attempts == int(value)


@pytest.mark.parametrize(
    "value",
    (
        "",
        "0",
        "-1",
        "+8",
        "101",
        "1.5",
        "8 8",
        "8e0",
        "true",
        "1e2",
        "８",
        "١٢",
        "9" * 5000,
    ),
)
def test_payment_notification_worker_rejects_invalid_max_attempts(tmp_path, value):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_NOTIFICATION_MAX_ATTEMPTS=value,
    )

    with pytest.raises(RuntimeError, match="PAYMENT_NOTIFICATION_MAX_ATTEMPTS"):
        load_config(env)


def test_payment_notification_worker_max_attempts_error_does_not_leak_long_value(
    tmp_path,
):
    value = "9" * 5000
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_NOTIFICATION_MAX_ATTEMPTS=value,
    )

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    assert value not in str(exc_info.value)


def test_enabled_payment_notification_worker_rejects_non_wechat_provider(tmp_path):
    env = _production_env(
        tmp_path,
        LICENSE_SERVER_ENV="development",
        PAYMENT_PROVIDER="mock",
        PAYMENT_MOCK_ADMIN_TOKEN="localR4ndomValue123456",
        PAYMENT_NOTIFICATION_WORKER_ENABLED="true",
    )

    with pytest.raises(RuntimeError, match="PAYMENT_PROVIDER=wechat_native"):
        load_config(env)


@pytest.mark.parametrize("environment", ("development", "test", "production"))
@pytest.mark.parametrize("source", ("DATABASE_URL", "LICENSE_DB_PATH"))
@pytest.mark.parametrize(
    "relative_path",
    (
        "relative-worker.sqlite3",
        "./data/license.sqlite3",
        r"\var\lib\worker.sqlite3",
        r"C:worker.sqlite3",
        r"C:relative\worker.sqlite3",
    ),
)
def test_enabled_payment_notification_worker_requires_absolute_database_path(
    monkeypatch, tmp_path, environment, source, relative_path
):
    env = _wechat_env(tmp_path)
    env["LICENSE_SERVER_ENV"] = environment
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"
    if source == "DATABASE_URL":
        env["DATABASE_URL"] = f"sqlite:///{relative_path}"
    else:
        env["DATABASE_URL"] = ""
        env["LICENSE_DB_PATH"] = relative_path
    monkeypatch.chdir(tmp_path)

    with pytest.raises(
        RuntimeError,
        match="PAYMENT_NOTIFICATION_WORKER_DATABASE_PATH_NOT_ABSOLUTE",
    ) as exc_info:
        load_config(env)

    assert relative_path not in str(exc_info.value)
    assert not (tmp_path / relative_path).exists()


@pytest.mark.parametrize("environment", ("development", "test", "production"))
def test_enabled_payment_notification_worker_accepts_absolute_database_path(
    tmp_path, environment
):
    env = _wechat_env(tmp_path)
    env["LICENSE_SERVER_ENV"] = environment
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"

    config = load_config(env)

    assert config.database_path.is_absolute()


@pytest.mark.skipif(os.name != "posix", reason="POSIX path semantics are required")
@pytest.mark.parametrize("source", ("DATABASE_URL", "LICENSE_DB_PATH"))
@pytest.mark.parametrize(
    "database_path",
    (r"C:\data\worker.sqlite3", r"\\server\share\worker.sqlite3"),
)
def test_posix_worker_rejects_windows_absolute_paths(
    tmp_path, source, database_path
):
    env = _wechat_env(tmp_path)
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"
    if source == "DATABASE_URL":
        env["DATABASE_URL"] = f"sqlite:///{database_path}"
    else:
        env["DATABASE_URL"] = ""
        env["LICENSE_DB_PATH"] = database_path

    with pytest.raises(
        RuntimeError,
        match="PAYMENT_NOTIFICATION_WORKER_DATABASE_PATH_NOT_ABSOLUTE",
    ):
        load_config(env)


@pytest.mark.skipif(os.name != "posix", reason="POSIX path semantics are required")
@pytest.mark.parametrize("source", ("DATABASE_URL", "LICENSE_DB_PATH"))
def test_posix_worker_accepts_posix_absolute_path(tmp_path, source):
    database_path = "/tmp/worker-test.sqlite3"
    env = _wechat_env(tmp_path)
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"
    if source == "DATABASE_URL":
        env["DATABASE_URL"] = f"sqlite:///{database_path}"
    else:
        env["DATABASE_URL"] = ""
        env["LICENSE_DB_PATH"] = database_path

    assert load_config(env).database_path == Path(database_path)


@pytest.mark.skipif(os.name != "nt", reason="Windows path semantics are required")
@pytest.mark.parametrize("source", ("DATABASE_URL", "LICENSE_DB_PATH"))
@pytest.mark.parametrize(
    "database_path",
    (r"C:\data\worker.sqlite3", r"\\server\share\worker.sqlite3"),
)
def test_windows_worker_accepts_drive_and_unc_absolute_paths(
    tmp_path, source, database_path
):
    env = _wechat_env(tmp_path)
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"
    if source == "DATABASE_URL":
        env["DATABASE_URL"] = f"sqlite:///{database_path}"
    else:
        env["DATABASE_URL"] = ""
        env["LICENSE_DB_PATH"] = database_path

    assert load_config(env).database_path == Path(database_path)


@pytest.mark.skipif(os.name != "nt", reason="Windows path semantics are required")
@pytest.mark.parametrize("source", ("DATABASE_URL", "LICENSE_DB_PATH"))
@pytest.mark.parametrize("database_path", (r"\\server", "\\\\server\\"))
def test_windows_worker_rejects_incomplete_unc_paths(
    tmp_path, source, database_path
):
    env = _wechat_env(tmp_path)
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"
    if source == "DATABASE_URL":
        env["DATABASE_URL"] = f"sqlite:///{database_path}"
    else:
        env["DATABASE_URL"] = ""
        env["LICENSE_DB_PATH"] = database_path

    with pytest.raises(
        RuntimeError,
        match="PAYMENT_NOTIFICATION_WORKER_DATABASE_PATH_NOT_ABSOLUTE",
    ):
        load_config(env)


@pytest.mark.parametrize("source", ("DATABASE_URL", "LICENSE_DB_PATH"))
def test_disabled_payment_notification_worker_keeps_relative_database_compatibility(
    tmp_path, source
):
    env = _production_env(
        tmp_path,
        LICENSE_SERVER_ENV="test",
        PAYMENT_PROVIDER="disabled",
        PAYMENT_NOTIFICATION_WORKER_ENABLED="false",
    )
    if source == "DATABASE_URL":
        env["DATABASE_URL"] = "sqlite:///relative-web.sqlite3"
    else:
        env["DATABASE_URL"] = ""
        env["LICENSE_DB_PATH"] = "relative-web.sqlite3"

    config = load_config(env)

    assert config.database_path == Path("relative-web.sqlite3")


@pytest.mark.parametrize("channels", ("wechat_pay,alipay", "alipay", ""))
def test_payment_channels_are_wechat_native_only(tmp_path, channels):
    env = _production_env(tmp_path, PAYMENT_CHANNELS=channels)

    with pytest.raises(RuntimeError, match="PAYMENT_CHANNELS"):
        load_config(env)


def test_payment_order_ttl_defaults_to_fifteen_minutes(tmp_path):
    config = load_config(_production_env(tmp_path, PAYMENT_PROVIDER="disabled"))

    assert config.payment_order_ttl_minutes == 15


def test_payment_order_ttl_accepts_exact_fifteen_and_keeps_catalog(tmp_path):
    env = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="disabled",
        PAYMENT_ORDER_TTL_MINUTES="15",
        PAYMENT_PRICE_FEN="990",
        PAYMENT_CURRENCY="CNY",
        PAYMENT_CHANNELS="wechat_pay",
    )

    config = load_config(env)

    assert config.payment_order_ttl_minutes == 15
    assert config.payment_price_fen == 990
    assert config.payment_currency == "CNY"
    assert config.payment_channels == ("wechat_pay",)


@pytest.mark.parametrize("value", ("", "0", "1", "14", "16", "60", "-1", "abc", "15.0"))
def test_payment_order_ttl_rejects_every_non_fifteen_value(tmp_path, value):
    env = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    env["PAYMENT_ORDER_TTL_MINUTES"] = value
    env["WECHAT_PAY_API_V3_KEY"] = "SECRET_VALUE_THAT_MUST_NOT_LEAK"

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    message = str(exc_info.value)
    assert "PAYMENT_ORDER_TTL_MINUTES" in message
    assert "15" in message
    assert "SECRET_VALUE_THAT_MUST_NOT_LEAK" not in message


def test_valid_wechat_native_config_is_loaded_without_secret_repr(tmp_path):
    env = _wechat_env(tmp_path)
    config = load_config(env)

    assert config.payment_provider == "wechat_native"
    assert config.wechat_pay is not None
    assert config.wechat_pay.app_id == "wx-test-app"
    rendered = repr(config)
    assert env["WECHAT_PAY_API_V3_KEY"] not in rendered
    assert env["WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH"] not in rendered
    assert env["WECHAT_PAY_PUBLIC_KEY_PATH"] not in rendered


@pytest.mark.parametrize("missing", WECHAT_KEYS)
def test_wechat_native_requires_every_configuration_variable(tmp_path, missing):
    env = _wechat_env(tmp_path)
    env.pop(missing)

    with pytest.raises(RuntimeError, match=missing):
        load_config(env)


def test_wechat_api_v3_key_requires_exactly_32_bytes_without_leaking_value(tmp_path):
    env = _wechat_env(tmp_path)
    secret = "short-secret-value"
    env["WECHAT_PAY_API_V3_KEY"] = secret

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    assert "WECHAT_PAY_API_V3_KEY" in str(exc_info.value)
    assert secret not in str(exc_info.value)


@pytest.mark.parametrize(
    "url",
    (
        "http://pay.example.test/notify",
        "https://pay.example.test/notify?source=wechat",
        "https://pay.example.test/notify#fragment",
        "https://localhost/notify",
        "https://127.0.0.1/notify",
        "https://[::1]/notify",
        "https://[invalid/notify",
    ),
)
def test_wechat_notify_url_rejects_unsafe_destinations(tmp_path, url):
    env = _wechat_env(tmp_path)
    env["WECHAT_PAY_NOTIFY_URL"] = url

    with pytest.raises(RuntimeError, match="WECHAT_PAY_NOTIFY_URL"):
        load_config(env)


def test_wechat_key_paths_must_exist_without_leaking_path(tmp_path):
    env = _wechat_env(tmp_path)
    missing_path = tmp_path / "merchant-secret-name.pem"
    env["WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH"] = str(missing_path)

    with pytest.raises(RuntimeError) as exc_info:
        load_config(env)

    assert "WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH" in str(exc_info.value)
    assert str(missing_path) not in str(exc_info.value)


@pytest.mark.parametrize("key_kind", ("private", "public"))
def test_wechat_keys_must_be_rsa(tmp_path, key_kind):
    env = _wechat_env(tmp_path)
    if key_kind == "private":
        path = Path(env["WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH"])
        path.write_bytes(
            ed25519.Ed25519PrivateKey.generate().private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption(),
            )
        )
        expected = "WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH"
    else:
        path = Path(env["WECHAT_PAY_PUBLIC_KEY_PATH"])
        path.write_bytes(
            ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo,
            )
        )
        expected = "WECHAT_PAY_PUBLIC_KEY_PATH"

    with pytest.raises(RuntimeError, match=expected):
        load_config(env)


def test_production_rejects_mock_residue_with_wechat_provider(tmp_path):
    env = _wechat_env(tmp_path)
    env["PAYMENT_MOCK_ADMIN_TOKEN"] = "mockR4ndomValue123456"

    with pytest.raises(RuntimeError, match="PAYMENT_MOCK_ADMIN_TOKEN"):
        load_config(env)


def _wechat_env(tmp_path) -> dict[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    merchant_path = tmp_path / "merchant.pem"
    public_path = tmp_path / "wechat-public.pem"
    merchant_path.write_bytes(
        private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return _production_env(
        tmp_path,
        PAYMENT_PROVIDER="wechat_native",
        WECHAT_PAY_APP_ID="wx-test-app",
        WECHAT_PAY_MCH_ID="1900000109",
        WECHAT_PAY_MERCHANT_SERIAL_NO="MERCHANT-SERIAL",
        WECHAT_PAY_MERCHANT_PRIVATE_KEY_PATH=str(merchant_path),
        WECHAT_PAY_PUBLIC_KEY_ID="PUB_KEY_ID_TEST",
        WECHAT_PAY_PUBLIC_KEY_PATH=str(public_path),
        WECHAT_PAY_API_V3_KEY="0123456789abcdef0123456789abcdef",
        WECHAT_PAY_NOTIFY_URL="https://pay.example.test/wechat/notify",
    )
