from dataclasses import dataclass
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from campus_login.local_config import LocalConfigError
from desktop_app.main_window import MainWindowController, login_result_display


@dataclass
class FakeConfig:
    username: str = ""
    password: str = ""
    auto_login_enabled: bool = True
    config_exists: bool = False
    credential_exists: bool = False


def test_controller_loads_config_and_autostart_state():
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(
            username="366369",
            password="secret-password",
            auto_login_enabled=True,
            config_exists=True,
            credential_exists=True,
        ),
        is_autostart_enabled_func=lambda: True,
    )

    state = controller.load_state()

    assert state.username == "366369"
    assert state.password == "secret-password"
    assert state.config_exists is True
    assert state.credential_exists is True
    assert state.autostart_enabled is True


def test_save_config_uses_secure_config_api_and_enables_autostart():
    calls = []

    def save_config(username, password, *, auto_login_enabled):
        calls.append(("save", username, password, auto_login_enabled))
        return FakeConfig(username=username, password=password)

    controller = MainWindowController(
        save_config_func=save_config,
        enable_autostart_func=lambda: calls.append(("enable",)) or True,
        disable_autostart_func=lambda: calls.append(("disable",)) or True,
    )

    message = controller.save(" 366369 ", "secret-password", True)

    assert "配置已保存" in message
    assert calls == [
        ("save", "366369", "secret-password", True),
        ("enable",),
    ]


def test_save_config_disables_autostart_when_unchecked():
    calls = []

    controller = MainWindowController(
        save_config_func=lambda username, password, *, auto_login_enabled: calls.append(
            ("save", username, password, auto_login_enabled)
        )
        or FakeConfig(username=username, password=password),
        enable_autostart_func=lambda: calls.append(("enable",)) or True,
        disable_autostart_func=lambda: calls.append(("disable",)) or True,
    )

    controller.save("366369", "secret-password", False)

    assert calls == [
        ("save", "366369", "secret-password", False),
        ("disable",),
    ]


def test_save_rejects_missing_username_or_password():
    controller = MainWindowController()

    try:
        controller.save("", "secret-password", True)
    except LocalConfigError as exc:
        assert "账号" in str(exc)
    else:
        raise AssertionError("missing username should fail")

    try:
        controller.save("366369", "", True)
    except LocalConfigError as exc:
        assert "密码" in str(exc)
    else:
        raise AssertionError("missing password should fail")


def test_save_rejects_when_saved_password_does_not_round_trip():
    controller = MainWindowController(
        save_config_func=lambda username, password, *, auto_login_enabled: FakeConfig(
            username=username,
            password="old-password",
        ),
    )

    try:
        controller.save("366369", "new-password", True)
    except LocalConfigError as exc:
        assert "校验失败" in str(exc)
    else:
        raise AssertionError("save should fail when credential does not round-trip")


def test_clear_config_only_calls_clear_login_config():
    calls = []
    controller = MainWindowController(
        clear_config_func=lambda: calls.append("clear") or FakeConfig(),
    )

    message = controller.clear()

    assert "已清除" in message
    assert calls == ["clear"]


def test_test_login_uses_injected_runner_without_real_network():
    calls = []

    def login_runner(username, password):
        calls.append((username, password))
        return LoginResult(status=LoginStatus.SUCCESS, message="ok")

    controller = MainWindowController(login_runner=login_runner)

    result = controller.test_login(" 366369 ", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    assert calls == [("366369", "secret-password")]


def test_login_status_display_mapping():
    assert login_result_display(
        LoginResult(status=LoginStatus.SUCCESS, message="ok")
    ) == ("登录成功，校园网认证已可用。", "success")
    already_online_text, already_online_variant = login_result_display(
        LoginResult(status=LoginStatus.ALREADY_ONLINE, message="online")
    )
    assert already_online_variant == "warning"
    assert "未重新提交" in already_online_text
    assert "不能证明新密码正确" in already_online_text
    assert login_result_display(
        LoginResult(status=LoginStatus.NOT_CAMPUS_NETWORK, message="not campus")
    ) == ("未检测到武汉理工校园网环境，请先连接校园网。", "warning")
    assert login_result_display(
        LoginResult(status=LoginStatus.INVALID_CREDENTIALS, message="bad")
    ) == ("账号或密码可能错误，请检查后重试。", "error")
    assert login_result_display(
        LoginResult(status=LoginStatus.TIMEOUT, message="timeout")
    ) == ("校园网认证服务异常或请求超时，请稍后再试。", "warning")
