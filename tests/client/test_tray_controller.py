from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from desktop_app.tray.controller import TrayController, TrayStatus


def _result(status):
    return LoginResult(status=status, message=f"{status.value} message")


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

    controller = TrayController(login_func=login)

    action_result = controller.test_login()

    assert calls == ["login"]
    assert action_result.result.status == LoginStatus.SUCCESS
    assert controller.status == TrayStatus.LOGGED_IN
    assert controller.status_text == "已登录"


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

    controller = TrayController(login_func=login, logout_func=logout)

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

    controller = TrayController(login_func=login, logout_func=logout)

    action_result = controller.relogin()

    assert calls == ["logout"]
    assert action_result.result.status == LoginStatus.LOGOUT_FAILED
    assert controller.status == TrayStatus.LOGOUT_PENDING


def test_login_exception_is_caught_and_marks_login_failed():
    def login():
        raise RuntimeError("login exploded")

    controller = TrayController(login_func=login)

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
