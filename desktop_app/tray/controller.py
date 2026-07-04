import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

from campus_login.adapters.whut import WhutCampusLoginAdapter
from campus_login.core.client import logout_with_adapter
from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from campus_login.saved_login import login_with_saved_config
from desktop_app.runtime_logs import (
    RuntimeLogStore,
    get_default_log_store,
    safe_exception_message,
)
from license_client.license_guard import (
    LicenseBootstrapSyncFunc,
    LicenseCheckFunc,
    check_license_before_login,
    license_blocked_result,
    try_initialize_license_after_bootstrap_login,
)


LOGGER = logging.getLogger(__name__)


class TrayStatus(str, Enum):
    UNKNOWN = "unknown"
    NOT_LOGGED_IN = "not_logged_in"
    LOGGING_IN = "logging_in"
    LOGGED_IN = "logged_in"
    LOGIN_FAILED = "login_failed"
    RETRYING = "retrying"
    STOPPED = "stopped"
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
    retryable: bool = False
    failure_reason: Optional[str] = None
    failed_stage: Optional[str] = None
    retry_count: int = 0


@dataclass(frozen=True)
class RecentAutoLoginResult:
    action: str
    status: str
    failed_stage: Optional[str]
    message: str
    retry_count: int
    timestamp: str


class TrayController:
    def __init__(
        self,
        *,
        login_func: Optional[LoginFunc] = None,
        logout_func: Optional[LogoutFunc] = None,
        exit_func: Optional[ExitFunc] = None,
        on_status_changed: Optional[StatusChangedFunc] = None,
        license_check_func: Optional[LicenseCheckFunc] = None,
        license_bootstrap_sync_func: Optional[LicenseBootstrapSyncFunc] = None,
        log_store: Optional[RuntimeLogStore] = None,
    ):
        self._login_func = login_func or login_with_saved_config
        self._logout_func = logout_current_session
        if logout_func is not None:
            self._logout_func = logout_func
        self._exit_func = exit_func or (lambda: None)
        self._on_status_changed = on_status_changed
        self._license_check = license_check_func or check_license_before_login
        self._license_bootstrap_sync = (
            license_bootstrap_sync_func or try_initialize_license_after_bootstrap_login
        )
        self._log_store = log_store or get_default_log_store()
        self.status = TrayStatus.UNKNOWN
        self.last_startup_auto_login_result: Optional[RecentAutoLoginResult] = None

    @property
    def status_text(self) -> str:
        if self.status == TrayStatus.RETRYING:
            return "等待自动重试"
        if self.status == TrayStatus.STOPPED:
            return "自动登录已停止"
        return STATUS_TEXT[self.status]

    @property
    def status_menu_text(self) -> str:
        recent = self.last_startup_auto_login_result
        visible_recent_statuses = {
            "failed": TrayStatus.LOGIN_FAILED,
            "retrying": TrayStatus.RETRYING,
            "stopped": TrayStatus.STOPPED,
        }
        if recent and visible_recent_statuses.get(recent.status) == self.status:
            labels = {
                "failed": "自动登录失败",
                "retrying": "等待自动重试",
                "stopped": "自动登录已停止",
            }
            stage = f"（{recent.failed_stage}）" if recent.failed_stage else ""
            return f"状态：{labels[recent.status]}{stage}"
        return f"状态：{self.status_text}"

    def set_status(self, status: TrayStatus) -> None:
        self.status = status
        if self._on_status_changed:
            self._on_status_changed(status)

    def test_login(self) -> TrayActionResult:
        return self._run_login_action("test_login")

    def startup_auto_login(self, retry_count: int = 1) -> TrayActionResult:
        action_result = self._run_login_action(
            "startup_auto_login",
            retry_count=retry_count,
        )
        status = "success" if action_result.status == TrayStatus.LOGGED_IN else "failed"
        self._record_startup_result(action_result, status)
        return action_result

    def _run_login_action(self, action: str, *, retry_count: int = 0) -> TrayActionResult:
        self.set_status(TrayStatus.LOGGING_IN)
        try:
            license_decision = self._license_check()
        except Exception as exc:
            return self._license_check_error_result(action, exc, retry_count=retry_count)
        if not license_decision.allowed:
            self.set_status(TrayStatus.LOGIN_FAILED)
            blocked_result = license_blocked_result(license_decision)
            self._write_license_decision_log(
                event="license_guard_blocked",
                action=_log_action(action),
                decision=license_decision,
                retry_count=retry_count,
            )
            if license_decision.reason == "bootstrap_portal_not_ready":
                self._write_license_decision_log(
                    event="bootstrap_portal_not_ready",
                    action=_log_action(action),
                    decision=license_decision,
                    retry_count=retry_count,
                )
            return TrayActionResult(
                action=action,
                status=self.status,
                message=blocked_result.message,
                result=blocked_result,
                retryable=_is_retryable_license_failure(action, license_decision),
                failure_reason=license_decision.reason,
                failed_stage=_license_failure_stage(license_decision.reason),
                retry_count=retry_count,
            )
        self._write_license_decision_log(
            event="license_guard_allowed",
            action=_log_action(action),
            decision=license_decision,
            retry_count=retry_count,
        )
        if license_decision.bootstrap_required:
            self._write_license_decision_log(
                event="bootstrap_allowed",
                action=_log_action(action),
                decision=license_decision,
                retry_count=retry_count,
            )
        self._write_log(
            event=_login_attempt_event(action),
            action=_log_action(action),
            status="started",
            retry_count=retry_count,
            safe_message="Campus login attempt started.",
        )
        try:
            result = self._login_func()
        except Exception as exc:
            LOGGER.exception("Tray login action failed.")
            self.set_status(TrayStatus.LOGIN_FAILED)
            self._write_log(
                event=_login_result_event(action, success=False),
                action=_log_action(action),
                status="failed",
                failure_reason="login_exception",
                retry_count=retry_count,
                safe_message=_safe_exception_message(exc),
            )
            return TrayActionResult(
                action=action,
                status=self.status,
                message=_safe_exception_message(exc),
                failure_reason="login_exception",
                retry_count=retry_count,
            )

        next_status = TrayStatus.LOGGED_IN if result.ok else TrayStatus.LOGIN_FAILED
        self.set_status(next_status)
        if result.ok and license_decision.bootstrap_required:
            try:
                self._license_bootstrap_sync(bootstrap_decision=license_decision)
            except Exception as exc:
                LOGGER.warning("Tray license bootstrap sync failed: %s", exc.__class__.__name__)
                self._write_log(
                    event="license_bootstrap_sync_failed",
                    action=_log_action(action),
                    status="failed",
                    failed_stage="license_bootstrap_sync",
                    failure_reason="license_bootstrap_sync_error",
                    retry_count=retry_count,
                    safe_message=_safe_exception_message(exc),
                )
        self._write_login_result_log(result, action=action, retry_count=retry_count)
        return TrayActionResult(
            action=action,
            status=self.status,
            message=result.message,
            result=result,
            retryable=_is_retryable_login_result(action, result),
            failure_reason=None if result.ok else (result.error_code or result.status.value),
            failed_stage=result.failed_stage,
            retry_count=retry_count,
        )

    def mark_startup_retrying(self, result: TrayActionResult) -> None:
        self._record_startup_result(result, "retrying")
        self._write_log(
            event="startup_auto_login_retrying",
            action="startup_auto_login",
            status="retrying",
            failed_stage=result.failed_stage,
            failure_reason=result.failure_reason,
            retry_count=result.retry_count,
            safe_message=result.message,
        )
        self.set_status(TrayStatus.RETRYING)

    def mark_startup_stopped(self, result: TrayActionResult) -> None:
        self._record_startup_result(result, "stopped")
        self._write_log(
            event="startup_auto_login_stopped",
            action="startup_auto_login",
            status="stopped",
            failed_stage=result.failed_stage,
            failure_reason=result.failure_reason,
            retry_count=result.retry_count,
            safe_message=result.message,
        )
        self.set_status(TrayStatus.STOPPED)

    def _record_startup_result(self, result: TrayActionResult, status: str) -> None:
        self.last_startup_auto_login_result = RecentAutoLoginResult(
            action="startup_auto_login",
            status=status,
            failed_stage=_safe_failed_stage(result.failed_stage),
            message=_safe_startup_message(result),
            retry_count=max(int(result.retry_count), 0),
            timestamp=_utc_now(),
        )

    def logout(self) -> TrayActionResult:
        self._write_log(
            event="logout_attempt",
            action="logout",
            status="started",
            safe_message="Campus logout attempt started.",
        )
        self.set_status(TrayStatus.LOGGING_OUT)
        try:
            result = self._logout_func()
        except Exception as exc:
            LOGGER.exception("Tray logout action failed.")
            self.set_status(TrayStatus.LOGOUT_FAILED)
            self._write_log(
                event="logout_failed",
                action="logout",
                status="failed",
                failure_reason="logout_exception",
                safe_message=_safe_exception_message(exc),
            )
            return TrayActionResult(
                action="logout",
                status=self.status,
                message=_safe_exception_message(exc),
            )

        next_status = _status_from_logout_result(result)
        self.set_status(next_status)
        self._write_logout_result_log(result)
        return TrayActionResult(
            action="logout",
            status=self.status,
            message=result.message,
            result=result,
        )

    def relogin(self) -> TrayActionResult:
        try:
            license_decision = self._license_check()
        except Exception as exc:
            return self._license_check_error_result("relogin", exc)
        if not license_decision.allowed:
            self.set_status(TrayStatus.LOGIN_FAILED)
            blocked_result = license_blocked_result(license_decision)
            self._write_license_decision_log(
                event="license_guard_blocked",
                action="relogin",
                decision=license_decision,
            )
            return TrayActionResult(
                action="relogin",
                status=self.status,
                message=blocked_result.message,
                result=blocked_result,
            )
        self._write_license_decision_log(
            event="license_guard_allowed",
            action="relogin",
            decision=license_decision,
        )
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

    def _license_check_error_result(
        self,
        action: str,
        exc: Exception,
        *,
        retry_count: int = 0,
    ) -> TrayActionResult:
        LOGGER.exception("Tray license check failed.")
        self.set_status(TrayStatus.LOGIN_FAILED)
        safe_message = _safe_exception_message(exc)
        self._write_log(
            event="license_guard_blocked",
            action=_log_action(action),
            status="blocked",
            failed_stage="license_check",
            failure_reason="license_check_error",
            retry_count=retry_count,
            safe_message=safe_message,
        )
        return TrayActionResult(
            action=action,
            status=self.status,
            message=safe_message,
            failure_reason="license_check_error",
            failed_stage="license_check",
            retry_count=retry_count,
        )

    def _write_license_decision_log(
        self,
        *,
        event: str,
        action: str,
        decision,
        retry_count: int = 0,
    ) -> None:
        self._write_log(
            event=event,
            action=action,
            status="allowed" if decision.allowed else "blocked",
            failed_stage=None if decision.allowed else _license_failure_stage(decision.reason),
            failure_reason=None if decision.allowed else decision.reason,
            retry_count=retry_count,
            safe_message=decision.message_for_ui or decision.reason,
        )

    def _write_login_result_log(
        self,
        result: LoginResult,
        *,
        action: str,
        retry_count: int,
    ) -> None:
        response_code, response_msg = _response_summary(result)
        self._write_log(
            event=_login_result_event(action, success=result.ok),
            action=_log_action(action),
            status="success" if result.ok else "failed",
            failed_stage=result.failed_stage,
            failure_reason=None if result.ok else (result.error_code or result.status.value),
            retry_count=retry_count,
            safe_message=result.message,
            http_status=result.http_status,
            response_code=response_code,
            response_msg=response_msg,
        )
        if not result.ok and result.failed_stage:
            self._write_log(
                event="campus_login_failed_stage",
                action=_log_action(action),
                status="failed",
                failed_stage=result.failed_stage,
                failure_reason=result.error_code or result.status.value,
                retry_count=retry_count,
                safe_message=result.message,
                response_msg=response_msg,
            )

    def _write_logout_result_log(self, result: LoginResult) -> None:
        response_code, response_msg = _response_summary(result)
        success = result.status in {LoginStatus.LOGOUT_SUCCESS, LoginStatus.LOGOUT_NOT_ONLINE}
        self._write_log(
            event="logout_success" if success else "logout_failed",
            action="logout",
            status="success" if success else "failed",
            failed_stage=result.failed_stage,
            failure_reason=None if success else (result.error_code or result.status.value),
            safe_message=result.message,
            http_status=result.http_status,
            response_code=response_code,
            response_msg=response_msg,
        )

    def _write_log(self, **kwargs) -> None:
        try:
            self._log_store.write(**kwargs)
        except Exception:
            LOGGER.exception("Runtime log write failed.")

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


def _log_action(action: str) -> str:
    if action == "startup_auto_login":
        return "startup_auto_login"
    if action == "relogin":
        return "relogin"
    return "manual_login"


def _login_attempt_event(action: str) -> str:
    if action == "startup_auto_login":
        return "startup_auto_login_attempt"
    return "manual_login_attempt"


def _login_result_event(action: str, *, success: bool) -> str:
    if action == "startup_auto_login":
        return "startup_auto_login_success" if success else "startup_auto_login_failed"
    return "manual_login_success" if success else "manual_login_failed"


def _response_summary(result: LoginResult) -> tuple[object, str]:
    summary = result.response_summary or {}
    if not isinstance(summary, dict):
        return None, ""
    if "logout" in summary and isinstance(summary["logout"], dict):
        summary = summary["logout"]
    return (
        summary.get("code"),
        str(summary.get("msg") or summary.get("message") or summary.get("error") or ""),
    )


def _safe_exception_message(exc: Exception) -> str:
    return safe_exception_message(exc)


_RETRYABLE_STARTUP_LOGIN_STATUSES = {
    LoginStatus.NOT_CAMPUS_NETWORK,
    LoginStatus.TIMEOUT,
    LoginStatus.AUTH_SERVICE_UNAVAILABLE,
    LoginStatus.IP_NOT_ONLINE,
}

_SAFE_FAILED_STAGES = {
    "account_login",
    "account_status",
    "api_base_probe",
    "csrf_token",
    "license_check",
    "login_page",
    "portal_context_or_ip_online_check",
    "portal_context_validation",
    "portal_probe",
}

_SAFE_STARTUP_MESSAGES = {
    LoginStatus.NOT_CAMPUS_NETWORK.value: "未检测到校园网门户。",
    LoginStatus.TIMEOUT.value: "校园网请求超时。",
    LoginStatus.AUTH_SERVICE_UNAVAILABLE.value: "校园网认证服务暂不可用。",
    LoginStatus.IP_NOT_ONLINE.value: "校园网门户尚未识别当前设备 IP。",
    "IP_NOT_ONLINE": "校园网门户尚未识别当前设备 IP。",
    "bootstrap_portal_not_ready": "校园网门户尚未就绪。",
    "device_mismatch": "设备指纹暂时不匹配。",
    "expired": "本地授权已过期。",
    "revoked": "本地授权已撤销。",
    "missing_saved_login_config": "未保存校园网账号密码配置。",
    "signature_invalid": "本地授权凭证无效。",
    "missing_public_key": "授权公钥缺失。",
}


def _is_retryable_license_failure(action: str, decision) -> bool:
    if action != "startup_auto_login":
        return False
    return bool(decision.retryable or decision.reason == "device_mismatch")


def _license_failure_stage(reason: str) -> str:
    if reason == "bootstrap_portal_not_ready":
        return "portal_probe"
    return "license_check"


def _is_retryable_login_result(action: str, result: LoginResult) -> bool:
    return action == "startup_auto_login" and result.status in _RETRYABLE_STARTUP_LOGIN_STATUSES


def _safe_failed_stage(value: Optional[str]) -> Optional[str]:
    return value if value in _SAFE_FAILED_STAGES else None


def _safe_startup_message(result: TrayActionResult) -> str:
    if result.status == TrayStatus.LOGGED_IN:
        return "自动登录成功。"
    return _SAFE_STARTUP_MESSAGES.get(result.failure_reason or "", "自动登录失败。")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
