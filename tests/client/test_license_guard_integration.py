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


FAKE_ACCOUNT = "2024" + "00001234"
FAKE_PASSWORD = "secret-" + "password"


def _decision(allowed: bool) -> LicenseDecision:
    status = LicenseStatus.TRIAL_ACTIVE if allowed else LicenseStatus.TRIAL_EXPIRED
    return LicenseDecision(
        status=status,
        allowed=allowed,
        reason=status.value,
        message_for_ui="授权允许" if allowed else "授权已过期",
    )


def _bootstrap_decision() -> LicenseDecision:
    return LicenseDecision(
        status=LicenseStatus.BOOTSTRAP_ALLOWED,
        allowed=True,
        reason="bootstrap_allowed",
        message_for_ui="bootstrap",
        bootstrap_required=True,
    )


class FakeLogStore:
    def __init__(self):
        self.entries = []

    def write(self, **kwargs):
        self.entries.append(kwargs)
        return True


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


def test_main_window_bootstrap_login_syncs_license_after_success():
    login_calls = []
    sync_calls = []

    controller = MainWindowController(
        login_runner=lambda username, password: login_calls.append((username, password))
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        license_check_func=lambda: _bootstrap_decision(),
        license_bootstrap_sync_func=lambda **kwargs: sync_calls.append(kwargs)
        or _decision(True),
    )

    result = controller.test_login("202400001234", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    assert login_calls == [("202400001234", "secret-password")]
    assert len(sync_calls) == 1
    assert sync_calls[0]["bootstrap_decision"].bootstrap_required is True
    assert set(sync_calls[0]) == {"bootstrap_decision"}


def test_main_window_bootstrap_login_failure_does_not_sync_license():
    sync_calls = []
    controller = MainWindowController(
        login_runner=lambda username, password: LoginResult(
            status=LoginStatus.TIMEOUT,
            message="timeout",
        ),
        license_check_func=lambda: _bootstrap_decision(),
        license_bootstrap_sync_func=lambda **kwargs: sync_calls.append(kwargs)
        or _decision(True),
    )

    result = controller.test_login("202400001234", "secret-password")

    assert result.status == LoginStatus.TIMEOUT
    assert sync_calls == []


def test_main_window_logs_license_guard_allowed_blocked_and_bootstrap():
    log_store = FakeLogStore()
    blocked = MainWindowController(
        login_runner=lambda username, password: LoginResult(
            status=LoginStatus.SUCCESS,
            message="ok",
        ),
        license_check_func=lambda: _decision(False),
        log_store=log_store,
    )

    blocked.test_login(FAKE_ACCOUNT, FAKE_PASSWORD)

    assert log_store.entries[-1]["event"] == "license_guard_blocked"
    assert log_store.entries[-1]["action"] == "manual_login"

    allowed = MainWindowController(
        login_runner=lambda username, password: LoginResult(
            status=LoginStatus.SUCCESS,
            message="ok",
        ),
        license_check_func=lambda: _bootstrap_decision(),
        license_bootstrap_sync_func=lambda **kwargs: _decision(True),
        log_store=log_store,
    )

    allowed.test_login(FAKE_ACCOUNT, FAKE_PASSWORD)

    events = [entry["event"] for entry in log_store.entries]
    assert "license_guard_allowed" in events
    assert "bootstrap_allowed" in events


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


def test_tray_test_login_bootstrap_syncs_license_after_success():
    calls = []
    sync_calls = []
    controller = TrayController(
        login_func=lambda: calls.append("login")
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        license_check_func=lambda: _bootstrap_decision(),
        license_bootstrap_sync_func=lambda **kwargs: sync_calls.append(kwargs)
        or _decision(True),
    )

    action_result = controller.test_login()

    assert calls == ["login"]
    assert action_result.status.value == "logged_in"
    assert len(sync_calls) == 1
    assert sync_calls[0]["bootstrap_decision"].bootstrap_required is True


def test_tray_startup_auto_login_bootstrap_syncs_license_after_success():
    calls = []
    sync_calls = []
    controller = TrayController(
        login_func=lambda: calls.append("login")
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        license_check_func=lambda: _bootstrap_decision(),
        license_bootstrap_sync_func=lambda **kwargs: sync_calls.append(kwargs)
        or _decision(True),
    )

    action_result = controller.startup_auto_login()

    assert calls == ["login"]
    assert action_result.action == "startup_auto_login"
    assert action_result.status.value == "logged_in"
    assert len(sync_calls) == 1


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


def test_tray_relogin_bootstrap_syncs_license_after_successful_login():
    calls = []
    sync_calls = []
    controller = TrayController(
        login_func=lambda: calls.append("login")
        or LoginResult(status=LoginStatus.SUCCESS, message="ok"),
        logout_func=lambda: calls.append("logout")
        or LoginResult(status=LoginStatus.LOGOUT_SUCCESS, message="out"),
        license_check_func=lambda: _bootstrap_decision(),
        license_bootstrap_sync_func=lambda **kwargs: sync_calls.append(kwargs)
        or _decision(True),
    )

    action_result = controller.relogin()

    assert calls == ["logout", "login"]
    assert action_result.action == "relogin"
    assert action_result.status.value == "logged_in"
    assert len(sync_calls) == 1
