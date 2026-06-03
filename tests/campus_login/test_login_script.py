import importlib.util
from pathlib import Path

from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from license_client.license_state import LicenseDecision, LicenseStatus as LicenseStateStatus


def load_login_script():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "dev" / "test_login.py"
    spec = importlib.util.spec_from_file_location("dev_test_login", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _allow_license():
    return LicenseDecision(
        status=LicenseStateStatus.TRIAL_ACTIVE,
        allowed=True,
        reason="trial_active",
        message_for_ui="授权允许",
    )


def test_script_requires_environment_credentials(capsys):
    module = load_login_script()

    exit_code = module.main(env={})

    output = capsys.readouterr().out
    assert exit_code == 2
    assert "WHUT_NET_USERNAME" in output
    assert "WHUT_NET_PASSWORD" in output


def test_script_prints_safe_summary_without_password(capsys):
    module = load_login_script()

    class FakeAdapter:
        def login(self, username, password):
            assert username == "202400001234"
            assert password == "secret-password"
            return LoginResult(
                status=LoginStatus.SUCCESS,
                message="Login succeeded.",
                http_status=200,
                portal_host="172.30.21.100",
                nas_id="14",
                response_summary={"code": 0, "msg": "ok"},
            )

    exit_code = module.main(
        env={
            "WHUT_NET_USERNAME": "202400001234",
            "WHUT_NET_PASSWORD": "secret-password",
        },
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
        license_check_func=_allow_license,
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "status: success" in output
    assert "account: 2024****1234" in output
    assert "secret-password" not in output
    assert "202400001234" not in output


def test_script_prints_failed_stage_without_password(capsys):
    module = load_login_script()

    class FakeAdapter:
        def login(self, username, password):
            return LoginResult(
                status=LoginStatus.TIMEOUT,
                message="Network request timed out.",
                portal_host="172.30.21.100",
                nas_id="14",
                failed_stage="account_status",
            )

    exit_code = module.main(
        env={
            "WHUT_NET_USERNAME": "202400001234",
            "WHUT_NET_PASSWORD": "secret-password",
        },
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
        license_check_func=_allow_license,
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "status: timeout" in output
    assert "failed_stage: account_status" in output
    assert "account: 2024****1234" in output
    assert "secret-password" not in output
    assert "202400001234" not in output


def test_script_prints_attempted_url_without_sensitive_values(capsys):
    module = load_login_script()

    class FakeAdapter:
        def login(self, username, password):
            return LoginResult(
                status=LoginStatus.AUTH_SERVICE_UNAVAILABLE,
                message="Portal detected but endpoint returned 404.",
                http_status=404,
                portal_host="172.30.21.100",
                nas_id="14",
                failed_stage="account_status",
                attempted_url=(
                    "http://172.30.21.100/api/account/status?"
                    "username=202400001234&password=secret-password&"
                    "token=raw-token&csrf=raw-csrf&cookie=raw-cookie"
                ),
            )

    exit_code = module.main(
        env={
            "WHUT_NET_USERNAME": "202400001234",
            "WHUT_NET_PASSWORD": "secret-password",
        },
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
        license_check_func=_allow_license,
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "status: auth_service_unavailable" in output
    assert "failed_stage: account_status" in output
    assert "attempted_url: http://172.30.21.100/api/account/status" in output
    assert "username=redacted" in output
    assert "password=redacted" in output
    assert "token=redacted" in output
    assert "csrf=redacted" in output
    assert "cookie=redacted" in output
    assert "secret-password" not in output
    assert "202400001234" not in output
    assert "raw-token" not in output
    assert "raw-csrf" not in output
    assert "raw-cookie" not in output


def test_script_prints_error_code_without_password(capsys):
    module = load_login_script()

    class FakeAdapter:
        def login(self, username, password):
            return LoginResult(
                status=LoginStatus.AUTH_SERVICE_UNAVAILABLE,
                message="校园网门户尚未识别当前设备 IP，请确认已连接 WHUT 校园网 Wi-Fi，并稍后重试。",
                portal_host="172.30.21.100",
                nas_id="14",
                failed_stage="portal_context_or_ip_online_check",
                error_code="IP_NOT_ONLINE",
                response_summary={
                    "code": 1,
                    "msg": "您的设备IP不在线，请断开网网络重新连接后再次登陆。",
                },
            )

    exit_code = module.main(
        env={
            "WHUT_NET_USERNAME": "202400001234",
            "WHUT_NET_PASSWORD": "secret-password",
        },
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
        license_check_func=_allow_license,
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "status: auth_service_unavailable" in output
    assert "error_code: IP_NOT_ONLINE" in output
    assert "failed_stage: portal_context_or_ip_online_check" in output
    assert "account: 2024****1234" in output
    assert "secret-password" not in output
    assert "202400001234" not in output


def test_script_prints_nas_id_source_without_sensitive_values(capsys):
    module = load_login_script()

    class FakeAdapter:
        def login(self, username, password):
            return LoginResult(
                status=LoginStatus.SUCCESS,
                message="Login succeeded.",
                portal_host="172.30.21.100",
                nas_id="14",
                nas_id_source="url_query",
            )

    exit_code = module.main(
        env={
            "WHUT_NET_USERNAME": "202400001234",
            "WHUT_NET_PASSWORD": "secret-password",
        },
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
        license_check_func=_allow_license,
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "nas_id_source: url_query" in output
    assert "secret-password" not in output
    assert "202400001234" not in output


def test_script_can_use_saved_config_without_printing_sensitive_values(capsys):
    module = load_login_script()

    class FakeAdapter:
        def login(self, username, password):
            assert username == "202400001234"
            assert password == "secret-password"
            return LoginResult(
                status=LoginStatus.SUCCESS,
                message="Login succeeded.",
                portal_host="172.30.21.100",
                nas_id="52",
            )

    class SavedConfig:
        username = "202400001234"
        password = "secret-password"
        config_exists = True
        credential_exists = True

    exit_code = module.main(
        env={},
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--use-saved-config", "--timeout", "0.1"],
        config_loader=lambda: SavedConfig(),
        license_check_func=_allow_license,
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "status: success" in output
    assert "account: 2024****1234" in output
    assert "secret-password" not in output
    assert "202400001234" not in output


def test_script_reports_missing_saved_config_without_password(capsys):
    module = load_login_script()

    class MissingConfig:
        username = "202400001234"
        password = None
        config_exists = True
        credential_exists = False

    exit_code = module.main(
        env={},
        argv=["--use-saved-config", "--timeout", "0.1"],
        config_loader=lambda: MissingConfig(),
    )

    output = capsys.readouterr().out
    assert exit_code == 2
    assert "Saved login config is incomplete" in output
    assert "config_exists: true" in output
    assert "password_saved: false" in output
    assert "202400001234" not in output


def test_script_prints_request_summary_without_sensitive_values(capsys):
    module = load_login_script()

    class FakeAdapter:
        def login(self, username, password):
            return LoginResult(
                status=LoginStatus.AUTH_FAILED,
                message="认证失败",
                portal_host="172.30.21.100",
                nas_id="52",
                nas_id_source="default_fallback",
                failed_stage="account_login",
                error_code="AUTH_FAILED",
                request_summary={
                    "method": "POST",
                    "content_type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "login_payload_keys": ["username", "password", "nasId"],
                    "login_payload_sanitized": {
                        "username": "2024****1234",
                        "password": "<PASSWORD>",
                        "nasId": "52",
                    },
                    "cookie_present": True,
                    "reused_same_session": True,
                    "token": "raw-token",
                    "SessionId": "raw-session",
                    "UserMac": "aa:bb:cc:dd:ee:ff",
                    "Name": "张三",
                },
            )

    exit_code = module.main(
        env={
            "WHUT_NET_USERNAME": "202400001234",
            "WHUT_NET_PASSWORD": "secret-password",
        },
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
        license_check_func=_allow_license,
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "request_summary: " in output
    assert "method=POST" in output
    assert "content_type=application/x-www-form-urlencoded; charset=UTF-8" in output
    assert "login_payload_keys=username,password,nasId" in output
    assert "username=2024****1234" in output
    assert "password=<PASSWORD>" in output
    assert "nasId=52" in output
    assert "cookie_present=True" in output
    assert "reused_same_session=True" in output
    assert "secret-password" not in output
    assert "202400001234" not in output
    assert "raw-token" not in output
    assert "raw-session" not in output
    assert "aa:bb:cc:dd:ee:ff" not in output
    assert "张三" not in output


def test_script_checks_license_before_login(capsys):
    module = load_login_script()
    calls = []

    class FakeAdapter:
        def login(self, username, password):
            calls.append((username, password))
            return LoginResult(status=LoginStatus.SUCCESS, message="ok")

    blocked = LicenseDecision(
        status=LicenseStateStatus.TRIAL_EXPIRED,
        allowed=False,
        reason="trial_expired",
        message_for_ui="授权已过期",
    )

    exit_code = module.main(
        env={
            "WHUT_NET_USERNAME": "202400001234",
            "WHUT_NET_PASSWORD": "secret-password",
        },
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
        license_check_func=lambda: blocked,
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert calls == []
    assert "status: unknown_error" in output
    assert "error_code: LICENSE_BLOCKED" in output
    assert "授权已过期" in output
    assert "secret-password" not in output
    assert "202400001234" not in output
