import base64
import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from license_client.constants import DEFAULT_LICENSE_SERVER_URL, resolve_license_server_url
from license_client.license_api import LicenseApiClient
from license_client.license_guard import get_current_license_state
from license_client.license_state import LicenseStatus
from license_client.public_key import (
    EMBEDDED_CONFIG_FILENAME,
    EMBEDDED_CONFIG_MODULE_NAME,
    _load_embedded_build_config,
    resolve_build_environment,
    resolve_license_public_key,
    write_embedded_build_config,
)
from license_client.token_store import save_signed_license_token  # noqa: F401  (保留 token 存储能力)


PRODUCT_ID = "whut-campus-auto-login"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _key_pair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_b64 = base64.b64encode(
        public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    ).decode("ascii")
    return private_key, public_key_b64


def _use_real_embedded_module(module_dir: Path):
    original_sys_path = sys.path.copy()
    missing_module = object()
    original_module = sys.modules.get(EMBEDDED_CONFIG_MODULE_NAME, missing_module)
    sys.path.insert(0, str(module_dir))
    sys.modules.pop(EMBEDDED_CONFIG_MODULE_NAME, None)
    importlib.invalidate_caches()

    def restore():
        if original_module is missing_module:
            sys.modules.pop(EMBEDDED_CONFIG_MODULE_NAME, None)
        else:
            sys.modules[EMBEDDED_CONFIG_MODULE_NAME] = original_module
        sys.path[:] = original_sys_path
        importlib.invalidate_caches()

    return restore


def _signed_license_token(private_key, **overrides):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "product_id": PRODUCT_ID,
        "device_fingerprint_hash": "device-a",
        "license_id": "lic-1",
        "license_type": "paid",
        "license_status": "active",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=365)).isoformat().replace("+00:00", "Z"),
        "features": ["auto_login"],
    }
    payload.update(overrides)
    payload_segment = _b64url(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature_segment = _b64url(private_key.sign(payload_segment.encode("ascii")))
    return f"{payload_segment}.{signature_segment}"


def test_development_build_allows_environment_public_key_override(monkeypatch):
    monkeypatch.setenv("LICENSE_PUBLIC_KEY", "env-key")

    assert (
        resolve_license_public_key(
            explicit_public_key=" explicit-key ",
            embedded_config_loader=lambda: ("production", "packaged-key"),
        )
        == "explicit-key"
    )
    assert (
        resolve_license_public_key(
            embedded_config_loader=lambda: ("development", "packaged-key"),
        )
        == "env-key"
    )

    monkeypatch.delenv("LICENSE_PUBLIC_KEY", raising=False)

    assert (
        resolve_license_public_key(
            embedded_config_loader=lambda: ("development", " packaged-key "),
        )
        == "packaged-key"
    )
    assert (
        resolve_build_environment(embedded_config_loader=lambda: None)
        == "development"
    )
    assert (
        resolve_build_environment(embedded_config_loader=lambda: (" production ", "packaged-key"))
        == "production"
    )
    assert (
        resolve_license_public_key(
            env={"LICENSE_PUBLIC_KEY": "env-key"},
            embedded_config_loader=lambda: ("staging", "packaged-key"),
        )
        == ""
    )
    assert (
        resolve_license_public_key(
            embedded_config_loader=lambda: ("development", ""),
        )
        == ""
    )


def test_frozen_app_missing_build_environment_fails_closed(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    assert resolve_build_environment(embedded_config_loader=lambda: None) == ""
    assert (
        resolve_license_public_key(
            env={"LICENSE_PUBLIC_KEY": "env-key"},
            embedded_config_loader=lambda: None,
        )
        == ""
    )


@pytest.mark.parametrize("build_environment", ["production", "preproduction", "public-beta"])
def test_release_builds_ignore_runtime_public_key_env(build_environment):
    assert (
        resolve_license_public_key(
            env={"LICENSE_PUBLIC_KEY": "malicious-key"},
            embedded_config_loader=lambda: (build_environment, "packaged-key"),
        )
        == "packaged-key"
    )


def test_free_license_state_allows_use_without_local_token(tmp_path, monkeypatch):
    """免费版：没有本地凭证也直接放行，且只上报设备使用情况。"""
    monkeypatch.setenv("LICENSE_PUBLIC_KEY", "malicious-key")
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", "packaged-key"),
    )

    decision = get_current_license_state()

    assert decision.status == LicenseStatus.FREE
    assert decision.allowed is True
    assert decision.usage_sync_required is True


def test_free_license_state_ignores_missing_or_invalid_public_key(tmp_path, monkeypatch):
    """免费版：公钥缺失/错误不再影响放行，也不因签名问题阻断登录。"""
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", ""),
    )
    missing_key = get_current_license_state()

    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", "not-a-public-key"),
    )
    invalid_key = get_current_license_state()

    assert missing_key.status == LicenseStatus.FREE
    assert missing_key.allowed is True
    assert invalid_key.status == LicenseStatus.FREE
    assert invalid_key.allowed is True


def test_write_embedded_build_config_writes_only_allowed_constants(tmp_path):
    _private_key, public_key_b64 = _key_pair()
    output_path = tmp_path / "generated" / EMBEDDED_CONFIG_FILENAME

    write_embedded_build_config(
        public_key_b64=public_key_b64,
        build_environment=" production ",
        license_server_url="https://license.example.test/",
        build_session_id="session-1",
        output_path=output_path,
    )

    content = output_path.read_text(encoding="utf-8")
    assert content == (
        'BUILD_ENVIRONMENT = "production"\n'
        f'LICENSE_PUBLIC_KEY_B64 = "{public_key_b64}"\n'
        'LICENSE_SERVER_URL = "https://license.example.test"\n'
        'BUILD_SESSION_ID = "session-1"\n'
    )
    assert "PRIVATE" not in content
    assert "TOKEN" not in content
    with pytest.raises(ValueError):
        write_embedded_build_config(
            public_key_b64=public_key_b64,
            build_environment="staging",
            license_server_url="https://license.example.test",
            build_session_id="session-1",
            output_path=output_path,
        )
    with pytest.raises(ValueError):
        write_embedded_build_config(
            public_key_b64="not-a-public-key",
            build_environment="production",
            license_server_url="https://license.example.test",
            build_session_id="session-1",
            output_path=output_path,
        )


def test_development_server_url_keeps_runtime_override_and_loopback_default():
    loader = lambda: ("development", "packaged-key", "")

    assert resolve_license_server_url(env={}, embedded_config_loader=loader) == DEFAULT_LICENSE_SERVER_URL
    assert (
        resolve_license_server_url(
            env={"LICENSE_SERVER_URL": "http://dev-license.local:8787/"},
            embedded_config_loader=loader,
        )
        == "http://dev-license.local:8787"
    )


@pytest.mark.parametrize("build_environment", ["preproduction", "production", "public-beta"])
def test_release_server_url_uses_embedded_value_and_ignores_runtime_env(build_environment):
    assert (
        resolve_license_server_url(
            env={"LICENSE_SERVER_URL": "http://127.0.0.1:8787"},
            embedded_config_loader=lambda: (
                build_environment,
                "packaged-key",
                "https://license.example.test/",
            ),
        )
        == "https://license.example.test"
    )


def test_public_beta_build_config_requires_approved_https_server_url(tmp_path):
    _private_key, public_key_b64 = _key_pair()
    output_path = tmp_path / EMBEDDED_CONFIG_FILENAME

    write_embedded_build_config(
        public_key_b64=public_key_b64,
        build_environment="public-beta",
        license_server_url="https://license.example.test/",
        build_session_id="session-public-beta",
        output_path=output_path,
    )

    assert output_path.read_text(encoding="utf-8") == (
        'BUILD_ENVIRONMENT = "public-beta"\n'
        f'LICENSE_PUBLIC_KEY_B64 = "{public_key_b64}"\n'
        'LICENSE_SERVER_URL = "https://license.example.test"\n'
        'BUILD_SESSION_ID = "session-public-beta"\n'
    )


def test_release_clients_use_same_url_from_real_embedded_module(tmp_path, monkeypatch):
    _private_key, public_key_b64 = _key_pair()
    output_path = tmp_path / EMBEDDED_CONFIG_FILENAME
    write_embedded_build_config(
        public_key_b64=public_key_b64,
        build_environment="production",
        license_server_url="https://frozen-license.example.test/",
        build_session_id="session-production",
        output_path=output_path,
    )
    monkeypatch.setenv("LICENSE_SERVER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("LICENSE_PUBLIC_KEY", "malicious-runtime-key")
    restore = _use_real_embedded_module(tmp_path)
    try:
        assert _load_embedded_build_config() == (
            "production",
            public_key_b64,
            "https://frozen-license.example.test",
        )
        assert resolve_build_environment() == "production"
        assert resolve_license_public_key() == public_key_b64
        license_client = LicenseApiClient()
    finally:
        restore()

    assert license_client.base_url == "https://frozen-license.example.test"


def test_real_embedded_module_reload_does_not_reuse_sys_modules_cache(tmp_path):
    _private_key, public_key_b64 = _key_pair()
    output_path = tmp_path / EMBEDDED_CONFIG_FILENAME
    write_embedded_build_config(
        public_key_b64=public_key_b64,
        build_environment="preproduction",
        license_server_url="https://preproduction.example.test",
        build_session_id="session-preproduction",
        output_path=output_path,
    )
    restore = _use_real_embedded_module(tmp_path)
    try:
        assert _load_embedded_build_config()[0] == "preproduction"
        write_embedded_build_config(
            public_key_b64=public_key_b64,
            build_environment="production",
            license_server_url="https://production.example.test",
            build_session_id="session-production",
            output_path=output_path,
        )
        sys.modules.pop(EMBEDDED_CONFIG_MODULE_NAME, None)
        importlib.invalidate_caches()
        assert _load_embedded_build_config() == (
            "production",
            public_key_b64,
            "https://production.example.test",
        )
    finally:
        restore()


@pytest.mark.parametrize(
    "module_content",
    [
        None,
        "this is not valid Python =\n",
        (
            'BUILD_ENVIRONMENT = "unknown"\n'
            'LICENSE_PUBLIC_KEY_B64 = "key"\n'
            'LICENSE_SERVER_URL = "https://license.example.test"\n'
        ),
    ],
)
def test_frozen_real_embedded_module_missing_or_corrupt_fails_closed(
    tmp_path,
    monkeypatch,
    module_content,
):
    if module_content is not None:
        (tmp_path / EMBEDDED_CONFIG_FILENAME).write_text(module_content, encoding="utf-8")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("LICENSE_SERVER_URL", "http://127.0.0.1:8787")
    restore = _use_real_embedded_module(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="build configuration"):
            resolve_license_server_url()
    finally:
        restore()


@pytest.mark.parametrize(
    "server_url",
    [
        "",
        "http://license.example.com",
        "http://127.0.0.1:8787",
        "https://127.0.0.1:8787",
        "https://127.42.1.9",
        "https://127.0.0.2",
        "https://localhost",
        "https://LOCALHOST",
        "https://localhost.",
        "LOCALHOST",
        "localhost.",
        "https://[::1]",
        "https://[0:0:0:0:0:0:0:1]",
        "https://[::ffff:127.0.0.1]",
        "license.example.com",
        "/license",
        "https://user:password@license.example.com",
        "https://license.example.com/#fragment",
        "https://license.example.com:invalid",
        " https://license.example.com",
        "https://license.example.com ",
        "https://license.example.com/path\nnext",
        "https://license.example.com/\x00next",
    ],
)
def test_release_server_url_rejects_unsafe_embedded_value(server_url):
    with pytest.raises(ValueError, match="license server URL"):
        resolve_license_server_url(
            env={"LICENSE_SERVER_URL": "https://runtime.example.test"},
            embedded_config_loader=lambda: ("production", "packaged-key", server_url),
        )


def test_unknown_build_environment_fails_closed_for_server_url():
    with pytest.raises(RuntimeError, match="build configuration"):
        resolve_license_server_url(
            env={"LICENSE_SERVER_URL": "https://runtime.example.test"},
            embedded_config_loader=lambda: (
                "unknown",
                "packaged-key",
                "https://license.example.test",
            ),
        )


@pytest.mark.parametrize(
    "server_url",
    [" https://license.example.test", "https://license.example.test "],
)
def test_release_build_config_writer_rejects_boundary_whitespace(tmp_path, server_url):
    _private_key, public_key_b64 = _key_pair()

    with pytest.raises(ValueError, match="license server URL"):
        write_embedded_build_config(
            public_key_b64=public_key_b64,
            build_environment="production",
            license_server_url=server_url,
            build_session_id="session-production",
            output_path=tmp_path / EMBEDDED_CONFIG_FILENAME,
        )


def test_pyinstaller_config_freezes_embedded_config_module_not_external_txt():
    root = Path(__file__).resolve().parents[2]
    spec = (root / "WHUTCampusAutoLogin.spec").read_text(encoding="utf-8")
    build_script = (root / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    gitignore = (root / ".gitignore").read_text(encoding="utf-8")

    assert EMBEDDED_CONFIG_FILENAME in spec
    assert EMBEDDED_CONFIG_FILENAME in build_script
    assert EMBEDDED_CONFIG_MODULE_NAME in spec
    assert "license_public_key.txt" not in spec
    assert "build_environment.txt" not in spec
    assert "whut_campus_auto_login.ico" in spec
    assert "windows_version_info.txt" in spec
    assert "whut_campus_auto_login_icon_source.png" not in spec
    assert "license_public_key.txt" not in build_script
    assert "build_environment.txt" not in build_script
    assert "BuildEnvironment" in build_script
    assert "LicenseServerUrl" in build_script
    assert "--license-server-url" in build_script
    assert "BUILD_SESSION_ID" in spec
    assert "WHUT_BUILD_SESSION_ID" in spec
    assert "WHUT_BUILD_SESSION_ID" in build_script
    assert "--build-session-id" in build_script
    assert '[string]$BuildEnvironment = "production"' not in build_script
    assert "build/generated/" in gitignore
    for forbidden in (
        "LICENSE_PRIVATE_KEY",
        "ADMIN_ACCESS_TOKEN_SHA256",
    ):
        assert forbidden not in spec
        assert forbidden not in build_script
