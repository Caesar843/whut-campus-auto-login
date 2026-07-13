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


@pytest.mark.parametrize("channels", ("wechat_pay,alipay", "alipay", ""))
def test_payment_channels_are_wechat_native_only(tmp_path, channels):
    env = _production_env(tmp_path, PAYMENT_CHANNELS=channels)

    with pytest.raises(RuntimeError, match="PAYMENT_CHANNELS"):
        load_config(env)


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
