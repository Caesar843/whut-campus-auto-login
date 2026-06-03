from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from desktop_app.main_window import MainWindowController
from desktop_app.tray.controller import TrayController
from license_client.license_state import LicenseDecision, LicenseStatus


def _decision(allowed: bool) -> LicenseDecision:
    status = LicenseStatus.TRIAL_ACTIVE if allowed else LicenseStatus.TRIAL_EXPIRED
    return LicenseDecision(
        status=status,
        allowed=allowed,
        reason=status.value,
        message_for_ui="授权允许" if allowed else "授权已过期",
    )


def test_main_window_login_is_blocked_before_runner_when_license_denies():
    calls = []
    controller = MainWindowController(
        login_runner=lambda username, password: calls.append((username, password))
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        license_check_func=lambda: _decision(False),
    )

    result = controller.test_login("202400001234", "secret-password")

    assert calls == []
    assert result.status == LoginStatus.UNKNOWN_ERROR
    assert result.error_code == "LICENSE_BLOCKED"
    assert "授权已过期" in result.message


def test_main_window_login_calls_runner_when_license_allows():
    calls = []
    controller = MainWindowController(
        login_runner=lambda username, password: calls.append((username, password))
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        license_check_func=lambda: _decision(True),
    )

    result = controller.test_login(" 202400001234 ", "secret-password")

    assert calls == [("202400001234", "secret-password")]
    assert result.status == LoginStatus.SUCCESS


def test_tray_test_login_is_blocked_before_login_func_when_license_denies():
    calls = []
    controller = TrayController(
        login_func=lambda: calls.append("login")
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        license_check_func=lambda: _decision(False),
    )

    action_result = controller.test_login()

    assert calls == []
    assert action_result.status.value == "login_failed"
    assert action_result.result.error_code == "LICENSE_BLOCKED"


def test_tray_startup_auto_login_uses_license_guard():
    calls = []
    controller = TrayController(
        login_func=lambda: calls.append("login")
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        license_check_func=lambda: _decision(False),
    )

    action_result = controller.startup_auto_login()

    assert calls == []
    assert action_result.action == "startup_auto_login"
    assert action_result.result.error_code == "LICENSE_BLOCKED"


def test_tray_relogin_checks_license_before_logout():
    calls = []
    controller = TrayController(
        login_func=lambda: calls.append("login")
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        logout_func=lambda: calls.append("logout")
        or LoginResult(status=LoginStatus.LOGOUT_SUCCESS, message="out"),
        license_check_func=lambda: _decision(False),
    )

    action_result = controller.relogin()

    assert calls == []
    assert action_result.action == "relogin"
    assert action_result.result.error_code == "LICENSE_BLOCKED"
