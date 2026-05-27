import logging
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from campus_login.adapters.whut import WhutCampusLoginAdapter
from campus_login.core.client import logout_with_adapter
from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from campus_login.saved_login import login_with_saved_config


LOGGER = logging.getLogger(__name__)


class TrayStatus(str, Enum):
    UNKNOWN = "unknown"
    NOT_LOGGED_IN = "not_logged_in"
    LOGGING_IN = "logging_in"
    LOGGED_IN = "logged_in"
    LOGIN_FAILED = "login_failed"
    LOGGING_OUT = "logging_out"
    LOGGED_OUT = "logged_out"
    LOGOUT_PENDING = "logout_pending"
    LOGOUT_FAILED = "logout_failed"


STATUS_TEXT = {
    TrayStatus.UNKNOWN: "未知",
    TrayStatus.NOT_LOGGED_IN: "未登录",
    TrayStatus.LOGGING_IN: "登录中",
    TrayStatus.LOGGED_IN: "已登录",
    TrayStatus.LOGIN_FAILED: "登录失败",
    TrayStatus.LOGGING_OUT: "登出中",
    TrayStatus.LOGGED_OUT: "已登出",
    TrayStatus.LOGOUT_PENDING: "登出待确认",
    TrayStatus.LOGOUT_FAILED: "登出失败",
}


LoginFunc = Callable[[], LoginResult]
LogoutFunc = Callable[[], LoginResult]
ExitFunc = Callable[[], None]
StatusChangedFunc = Callable[[TrayStatus], None]


@dataclass(frozen=True)
class TrayActionResult:
    action: str
    status: TrayStatus
    message: str
    result: Optional[LoginResult] = None


class TrayController:
    def __init__(
        self,
        *,
        login_func: Optional[LoginFunc] = None,
        logout_func: Optional[LogoutFunc] = None,
        exit_func: Optional[ExitFunc] = None,
        on_status_changed: Optional[StatusChangedFunc] = None,
    ):
        self._login_func = login_func or login_with_saved_config
        self._logout_func = logout_current_session
        if logout_func is not None:
            self._logout_func = logout_func
        self._exit_func = exit_func or (lambda: None)
        self._on_status_changed = on_status_changed
        self.status = TrayStatus.UNKNOWN

    @property
    def status_text(self) -> str:
        return STATUS_TEXT[self.status]

    @property
    def status_menu_text(self) -> str:
        return f"状态：{self.status_text}"

    def set_status(self, status: TrayStatus) -> None:
        self.status = status
        if self._on_status_changed:
            self._on_status_changed(status)

    def test_login(self) -> TrayActionResult:
        return self._run_login_action("test_login")

    def startup_auto_login(self) -> TrayActionResult:
        return self._run_login_action("startup_auto_login")

    def _run_login_action(self, action: str) -> TrayActionResult:
        self.set_status(TrayStatus.LOGGING_IN)
        try:
            result = self._login_func()
        except Exception as exc:
            LOGGER.exception("Tray login action failed.")
            self.set_status(TrayStatus.LOGIN_FAILED)
            return TrayActionResult(
                action=action,
                status=self.status,
                message=_safe_exception_message(exc),
            )

        next_status = TrayStatus.LOGGED_IN if result.ok else TrayStatus.LOGIN_FAILED
        self.set_status(next_status)
        return TrayActionResult(
            action=action,
            status=self.status,
            message=result.message,
            result=result,
        )

    def logout(self) -> TrayActionResult:
        self.set_status(TrayStatus.LOGGING_OUT)
        try:
            result = self._logout_func()
        except Exception as exc:
            LOGGER.exception("Tray logout action failed.")
            self.set_status(TrayStatus.LOGOUT_FAILED)
            return TrayActionResult(
                action="logout",
                status=self.status,
                message=_safe_exception_message(exc),
            )

        next_status = _status_from_logout_result(result)
        self.set_status(next_status)
        return TrayActionResult(
            action="logout",
            status=self.status,
            message=result.message,
            result=result,
        )

    def relogin(self) -> TrayActionResult:
        logout_result = self.logout()
        if logout_result.status != TrayStatus.LOGGED_OUT:
            return TrayActionResult(
                action="relogin",
                status=logout_result.status,
                message=logout_result.message,
                result=logout_result.result,
            )
        login_result = self.test_login()
        return TrayActionResult(
            action="relogin",
            status=login_result.status,
            message=login_result.message,
            result=login_result.result,
        )

    def request_exit(self) -> None:
        self._exit_func()


def logout_current_session(timeout: float = 5.0) -> LoginResult:
    adapter = WhutCampusLoginAdapter(timeout=timeout)
    return logout_with_adapter(adapter)


def _status_from_logout_result(result: LoginResult) -> TrayStatus:
    if result.status in {LoginStatus.LOGOUT_SUCCESS, LoginStatus.LOGOUT_NOT_ONLINE}:
        return TrayStatus.LOGGED_OUT
    if _is_logout_pending_confirmation(result):
        return TrayStatus.LOGOUT_PENDING
    return TrayStatus.LOGOUT_FAILED


def _is_logout_pending_confirmation(result: LoginResult) -> bool:
    if result.failed_stage != "post_logout_status":
        return False
    if result.status == LoginStatus.LOGOUT_FAILED:
        return result.error_code == "LOGOUT_STILL_ONLINE"
    if result.status == LoginStatus.LOGOUT_UNKNOWN_RESPONSE:
        logout_summary = result.response_summary.get("logout")
        return isinstance(logout_summary, dict) and logout_summary.get("code") == 0
    return False


def _safe_exception_message(exc: Exception) -> str:
    return str(exc)[:240] or exc.__class__.__name__
