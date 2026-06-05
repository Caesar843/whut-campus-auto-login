from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from desktop_app.tray.controller import TrayController, TrayStatus
from license_client.license_state import LicenseDecision, LicenseStatus as LicenseStateStatus


def _result(status):
    return LoginResult(status=status, message=f"{status.value} message")


def _allow_license():
    return LicenseDecision(
        status=LicenseStateStatus.TRIAL_ACTIVE,
        allowed=True,
        reason="trial_active",
        message_for_ui="授权允许",
    )


def _deny_license(status, reason, *, retryable=False):
    return LicenseDecision(
        status=status,
        allowed=False,
        reason=reason,
        message_for_ui="license blocked",
        retryable=retryable,
    )


def test_status_text_starts_unknown_and_can_update():
    observed = []
    controller = TrayController(on_status_changed=observed.append)

    assert controller.status == TrayStatus.UNKNOWN
    assert controller.status_text == "未知"
    assert controller.status_menu_text == "状态：未知"

    controller.set_status(TrayStatus.NOT_LOGGED_IN)

    assert controller.status == TrayStatus.NOT_LOGGED_IN
    assert controller.status_text == "未登录"
    assert controller.status_menu_text == "状态：未登录"
    assert observed == [TrayStatus.NOT_LOGGED_IN]


def test_test_login_calls_injected_login_function_and_marks_logged_in():
    calls = []

    def login():
        calls.append("login")
        return _result(LoginStatus.SUCCESS)

    controller = TrayController(login_func=login, license_check_func=_allow_license)

    action_result = controller.test_login()

    assert calls == ["login"]
    assert action_result.result.status == LoginStatus.SUCCESS
    assert controller.status == TrayStatus.LOGGED_IN
    assert controller.status_text == "已登录"


def test_startup_auto_login_calls_injected_login_function_and_marks_logged_in():
    calls = []
    exit_calls = []

    def login():
        calls.append("login")
        return _result(LoginStatus.SUCCESS)

    controller = TrayController(
        login_func=login,
        exit_func=lambda: exit_calls.append("exit"),
        license_check_func=_allow_license,
    )

    action_result = controller.startup_auto_login()

    assert calls == ["login"]
    assert exit_calls == []
    assert action_result.action == "startup_auto_login"
    assert action_result.result.status == LoginStatus.SUCCESS
    assert controller.status == TrayStatus.LOGGED_IN


def test_startup_auto_login_failure_keeps_controller_running():
    calls = []
    exit_calls = []

    def login():
        calls.append("login")
        return LoginResult(
            status=LoginStatus.TIMEOUT,
            message="timeout",
            failed_stage="account_status",
        )

    controller = TrayController(
        login_func=login,
        exit_func=lambda: exit_calls.append("exit"),
        license_check_func=_allow_license,
    )

    action_result = controller.startup_auto_login()

    assert calls == ["login"]
    assert exit_calls == []
    assert action_result.action == "startup_auto_login"
    assert action_result.result.status == LoginStatus.TIMEOUT
    assert action_result.retryable is True
    assert action_result.failure_reason == LoginStatus.TIMEOUT.value
    assert action_result.failed_stage == "account_status"
    assert controller.status == TrayStatus.LOGIN_FAILED


def test_manual_login_failure_is_not_retryable():
    controller = TrayController(
        login_func=lambda: _result(LoginStatus.TIMEOUT),
        license_check_func=_allow_license,
    )

    action_result = controller.test_login()

    assert action_result.retryable is False


def test_startup_license_bootstrap_portal_not_ready_is_retryable():
    controller = TrayController(
        license_check_func=lambda: _deny_license(
            LicenseStateStatus.SERVER_UNREACHABLE,
            "bootstrap_portal_not_ready",
            retryable=True,
        ),
    )

    action_result = controller.startup_auto_login()

    assert action_result.retryable is True
    assert action_result.failure_reason == "bootstrap_portal_not_ready"
    assert action_result.failed_stage == "portal_probe"


def test_startup_device_mismatch_is_retryable_without_allowing_login():
    calls = []
    controller = TrayController(
        login_func=lambda: calls.append("login") or _result(LoginStatus.SUCCESS),
        license_check_func=lambda: _deny_license(
            LicenseStateStatus.TOKEN_INVALID,
            "device_mismatch",
        ),
    )

    action_result = controller.startup_auto_login()

    assert calls == []
    assert action_result.retryable is True
    assert action_result.failure_reason == "device_mismatch"


def test_startup_expired_invalid_revoked_and_missing_config_failures_stop_retrying():
    decisions = [
        _deny_license(LicenseStateStatus.TRIAL_EXPIRED, "expired"),
        _deny_license(LicenseStateStatus.PAID_EXPIRED, "expired"),
        _deny_license(LicenseStateStatus.TOKEN_INVALID, "signature_invalid"),
        _deny_license(LicenseStateStatus.REVOKED, "revoked"),
        _deny_license(
            LicenseStateStatus.SERVER_UNREACHABLE,
            "missing_saved_login_config",
        ),
    ]
    for decision in decisions:
        controller = TrayController(license_check_func=lambda item=decision: item)
        assert controller.startup_auto_login().retryable is False

    controller = TrayController(
        login_func=lambda: LoginResult(
            status=LoginStatus.UNKNOWN_ERROR,
            message="Saved login config is incomplete.",
        ),
        license_check_func=_allow_license,
    )
    assert controller.startup_auto_login().retryable is False


def test_startup_known_permanent_login_failures_stop_retrying():
    for status in (
        LoginStatus.INVALID_CREDENTIALS,
        LoginStatus.AUTH_FAILED,
        LoginStatus.INVALID_PORTAL_PARAMETER,
        LoginStatus.UNKNOWN_ERROR,
    ):
        controller = TrayController(
            login_func=lambda item=status: _result(item),
            license_check_func=_allow_license,
        )

        assert controller.startup_auto_login().retryable is False


def test_recent_startup_result_is_safe_and_tracks_retry_state():
    sensitive = "202400001234 secret-password signed-token PRIVATE KEY"
    controller = TrayController(
        login_func=lambda: LoginResult(
            status=LoginStatus.TIMEOUT,
            message=sensitive,
            failed_stage="account_status",
        ),
        license_check_func=_allow_license,
    )

    action_result = controller.startup_auto_login(retry_count=2)
    recent = controller.last_startup_auto_login_result

    assert recent.action == "startup_auto_login"
    assert recent.status == "failed"
    assert recent.failed_stage == "account_status"
    assert recent.retry_count == 2
    assert recent.timestamp
    assert sensitive not in str(recent)
    for forbidden in ("202400001234", "secret-password", "signed-token", "PRIVATE KEY"):
        assert forbidden not in str(recent)

    controller.mark_startup_retrying(action_result)
    assert controller.last_startup_auto_login_result.status == "retrying"
    assert "account_status" in controller.status_menu_text

    controller.mark_startup_stopped(action_result)
    assert controller.last_startup_auto_login_result.status == "stopped"
    assert "account_status" in controller.status_menu_text


def test_manual_success_overrides_preserved_startup_failure_in_tray_status():
    results = iter(
        [
            LoginResult(
                status=LoginStatus.TIMEOUT,
                message="timeout",
                failed_stage="account_status",
            ),
            _result(LoginStatus.SUCCESS),
        ]
    )
    controller = TrayController(
        login_func=lambda: next(results),
        license_check_func=_allow_license,
    )
    startup_result = controller.startup_auto_login()
    controller.mark_startup_stopped(startup_result)

    controller.test_login()

    assert controller.last_startup_auto_login_result.status == "stopped"
    assert controller.status == TrayStatus.LOGGED_IN
    assert controller.status_menu_text == f"状态：{controller.status_text}"


def test_startup_auto_login_exception_marks_failed_without_exit():
    exit_calls = []

    def login():
        raise RuntimeError("startup login exploded")

    controller = TrayController(
        login_func=login,
        exit_func=lambda: exit_calls.append("exit"),
        license_check_func=_allow_license,
    )

    action_result = controller.startup_auto_login()

    assert exit_calls == []
    assert action_result.result is None
    assert "startup login exploded" in action_result.message
    assert controller.status == TrayStatus.LOGIN_FAILED


def test_logout_calls_injected_logout_function_and_marks_logged_out():
    calls = []

    def logout():
        calls.append("logout")
        return _result(LoginStatus.LOGOUT_SUCCESS)

    controller = TrayController(logout_func=logout)

    action_result = controller.logout()

    assert calls == ["logout"]
    assert action_result.result.status == LoginStatus.LOGOUT_SUCCESS
    assert controller.status == TrayStatus.LOGGED_OUT
    assert controller.status_text == "已登出"


def test_logout_still_online_after_accepted_request_marks_pending_confirmation():
    def logout():
        return LoginResult(
            status=LoginStatus.LOGOUT_FAILED,
            message="校园网注销请求已受理，但复查状态仍为在线。",
            failed_stage="post_logout_status",
            error_code="LOGOUT_STILL_ONLINE",
        )

    controller = TrayController(logout_func=logout)

    action_result = controller.logout()

    assert action_result.result.status == LoginStatus.LOGOUT_FAILED
    assert controller.status == TrayStatus.LOGOUT_PENDING
    assert controller.status_text == "登出待确认"


def test_logout_unknown_after_accepted_request_marks_pending_confirmation():
    def logout():
        return LoginResult(
            status=LoginStatus.LOGOUT_UNKNOWN_RESPONSE,
            message="Logout was accepted, but post-logout status could not be verified.",
            failed_stage="post_logout_status",
            error_code="LOGOUT_UNKNOWN_RESPONSE",
            response_summary={"logout": {"code": 0, "msg": "登出成功"}},
        )

    controller = TrayController(logout_func=logout)

    action_result = controller.logout()

    assert action_result.result.status == LoginStatus.LOGOUT_UNKNOWN_RESPONSE
    assert controller.status == TrayStatus.LOGOUT_PENDING
    assert controller.status_text == "登出待确认"


def test_logout_not_online_is_treated_as_logged_out():
    def logout():
        return _result(LoginStatus.LOGOUT_NOT_ONLINE)

    controller = TrayController(logout_func=logout)

    controller.logout()

    assert controller.status == TrayStatus.LOGGED_OUT


def test_relogin_calls_logout_then_login_in_order():
    calls = []

    def login():
        calls.append("login")
        return _result(LoginStatus.ALREADY_ONLINE)

    def logout():
        calls.append("logout")
        return _result(LoginStatus.LOGOUT_SUCCESS)

    controller = TrayController(
        login_func=login,
        logout_func=logout,
        license_check_func=_allow_license,
    )

    action_result = controller.relogin()

    assert calls == ["logout", "login"]
    assert action_result.result.status == LoginStatus.ALREADY_ONLINE
    assert controller.status == TrayStatus.LOGGED_IN


def test_relogin_does_not_login_when_logout_is_still_pending():
    calls = []

    def login():
        calls.append("login")
        return _result(LoginStatus.SUCCESS)

    def logout():
        calls.append("logout")
        return LoginResult(
            status=LoginStatus.LOGOUT_FAILED,
            message="校园网注销请求已受理，但复查状态仍为在线。",
            failed_stage="post_logout_status",
            error_code="LOGOUT_STILL_ONLINE",
        )

    controller = TrayController(
        login_func=login,
        logout_func=logout,
        license_check_func=_allow_license,
    )

    action_result = controller.relogin()

    assert calls == ["logout"]
    assert action_result.result.status == LoginStatus.LOGOUT_FAILED
    assert controller.status == TrayStatus.LOGOUT_PENDING


def test_login_exception_is_caught_and_marks_login_failed():
    def login():
        raise RuntimeError("login exploded")

    controller = TrayController(login_func=login, license_check_func=_allow_license)

    action_result = controller.test_login()

    assert action_result.result is None
    assert "login exploded" in action_result.message
    assert controller.status == TrayStatus.LOGIN_FAILED


def test_logout_exception_is_caught_and_marks_logout_failed():
    def logout():
        raise RuntimeError("logout exploded")

    controller = TrayController(logout_func=logout)

    action_result = controller.logout()

    assert action_result.result is None
    assert "logout exploded" in action_result.message
    assert controller.status == TrayStatus.LOGOUT_FAILED


def test_exit_action_invokes_callback():
    calls = []
    controller = TrayController(exit_func=lambda: calls.append("exit"))

    controller.request_exit()

    assert calls == ["exit"]
