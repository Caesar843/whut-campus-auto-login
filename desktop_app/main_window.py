from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from campus_login.adapters.whut import WhutCampusLoginAdapter
from campus_login.core.client import login_with_adapter
from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from campus_login.local_config import (
    LocalConfigError,
    clear_login_config,
    load_login_config,
    save_login_config,
)
from desktop_app.autostart.windows_startup import (
    AutostartError,
    disable_autostart,
    enable_autostart,
    is_autostart_enabled,
)
from desktop_app.log_window import RuntimeLogWindow
from desktop_app.runtime_logs import (
    RuntimeLogStore,
    get_default_log_store,
    safe_exception_message,
)
from desktop_app.widgets import AccountLineEdit, PasswordLineEdit, StatusLabel
from license_client.license_guard import (
    LicenseBootstrapSyncFunc,
    LicenseCheckFunc,
    LicenseInitializeFunc,
    check_license_before_login,
    get_current_license_state,
    initialize_license,
    license_blocked_result,
    try_initialize_license_after_bootstrap_login,
)
from license_client.license_state import (
    LicenseDecision,
    TOKEN_PERSIST_FAILED_MESSAGE,
    TOKEN_PERSIST_FAILED_WARNING,
    free_decision,
)


LOGGER = logging.getLogger(__name__)
WINDOW_TITLE = "武汉理工校园网助手"
LICENSE_PLACEHOLDER = "授权状态：免费版，永久免费使用"


LoginRunner = Callable[[str, str], LoginResult]


@dataclass(frozen=True)
class MainWindowState:
    username: str = ""
    password: str = ""
    auto_login_enabled: bool = True
    autostart_enabled: bool = False
    config_exists: bool = False
    credential_exists: bool = False
    license_message: str = LICENSE_PLACEHOLDER
    license_variant: str = "neutral"
    license_sync_pending: bool = False


class MainWindowController:
    def __init__(
        self,
        *,
        load_config_func: Callable[[], object] = load_login_config,
        save_config_func: Callable[..., object] = save_login_config,
        clear_config_func: Callable[[], object] = clear_login_config,
        is_autostart_enabled_func: Callable[[], bool] = is_autostart_enabled,
        enable_autostart_func: Callable[[], bool] = enable_autostart,
        disable_autostart_func: Callable[[], bool] = disable_autostart,
        login_runner: Optional[LoginRunner] = None,
        license_check_func: Optional[LicenseCheckFunc] = None,
        license_bootstrap_sync_func: Optional[LicenseBootstrapSyncFunc] = None,
        license_initialize_func: Optional[LicenseInitializeFunc] = None,
        license_state_func: Optional[Callable[[], LicenseDecision]] = None,
        log_store: Optional[RuntimeLogStore] = None,
    ):
        self._load_config = load_config_func
        self._save_config = save_config_func
        self._clear_config = clear_config_func
        self._is_autostart_enabled = is_autostart_enabled_func
        self._enable_autostart = enable_autostart_func
        self._disable_autostart = disable_autostart_func
        self._login_runner = login_runner or _default_login_runner
        self._license_check = license_check_func
        self._license_bootstrap_sync = (
            license_bootstrap_sync_func or try_initialize_license_after_bootstrap_login
        )
        self._license_initialize = license_initialize_func or initialize_license
        self._license_state = license_state_func or get_current_license_state
        self._log_store = log_store or get_default_log_store()

    @property
    def log_store(self) -> RuntimeLogStore:
        return self._log_store

    def load_state(self) -> MainWindowState:
        config = self._load_config()
        license_decision = self._license_state()
        return MainWindowState(
            username=str(getattr(config, "username", "") or ""),
            password=str(getattr(config, "password", "") or ""),
            auto_login_enabled=bool(getattr(config, "auto_login_enabled", True)),
            autostart_enabled=bool(self._is_autostart_enabled()),
            config_exists=bool(getattr(config, "config_exists", False)),
            credential_exists=bool(getattr(config, "credential_exists", False)),
            license_message=license_decision.message_for_ui or LICENSE_PLACEHOLDER,
            license_variant=_license_variant(license_decision),
            license_sync_pending=_license_sync_pending(license_decision),
        )

    def initialize_license(self) -> LicenseDecision:
        return self._license_initialize()

    def save(self, username: str, password: str, autostart_enabled: bool) -> str:
        clean_username = str(username or "").strip()
        if not clean_username:
            raise LocalConfigError("请输入校园网账号。")
        if not password:
            raise LocalConfigError("请输入校园网密码。")

        saved_config = self._save_config(
            clean_username,
            password,
            auto_login_enabled=bool(autostart_enabled),
        )
        saved_username = str(getattr(saved_config, "username", "") or "").strip()
        saved_password = getattr(saved_config, "password", None)
        if saved_username != clean_username or saved_password != password:
            raise LocalConfigError("配置保存后校验失败，请重新保存。")
        if autostart_enabled:
            self._enable_autostart()
        else:
            self._disable_autostart()
        return "配置已保存，密码已写入本机安全凭据。"

    def clear(self) -> str:
        self._clear_config()
        return "本机登录配置已清除。"

    def test_login(self, username: str, password: str) -> LoginResult:
        clean_username = str(username or "").strip()
        if not clean_username or not password:
            self._write_log(
                event="manual_login_failed",
                action="manual_login",
                status="failed",
                failure_reason="missing_credentials",
                safe_message="Please enter campus account and password before testing login.",
            )
            return LoginResult(
                status=LoginStatus.UNKNOWN_ERROR,
                message="请先输入校园网账号和密码。",
            )
        self._write_log(
            event="manual_login_attempt",
            action="manual_login",
            status="started",
            safe_message="Manual campus login test started.",
            password=password,
        )
        license_decision = self._check_license_before_login()
        if not license_decision.allowed:
            self._write_license_decision_log(
                event="license_guard_blocked",
                action="manual_login",
                decision=license_decision,
            )
            return license_blocked_result(license_decision)
        self._write_license_decision_log(
            event="license_guard_allowed",
            action="manual_login",
            decision=license_decision,
        )
        if license_decision.bootstrap_required:
            self._write_license_decision_log(
                event="bootstrap_allowed",
                action="manual_login",
                decision=license_decision,
                emit_persistence_warning=False,
            )
        result = self._login_runner(clean_username, password)
        self._write_login_result_log(
            result,
            action="manual_login",
            success_event="manual_login_success",
            failed_event="manual_login_failed",
            password=password,
        )
        if result.ok and _usage_sync_required(license_decision):
            try:
                sync_decision = self._license_bootstrap_sync(
                    bootstrap_decision=license_decision
                )
                self._write_license_persistence_warning_log(
                    action="manual_login",
                    decision=sync_decision,
                )
            except Exception as exc:
                LOGGER.warning("License bootstrap sync failed: %s", exc.__class__.__name__)
                self._write_log(
                    event="license_bootstrap_sync_failed",
                    action="manual_login",
                    status="failed",
                    failed_stage="license_bootstrap_sync",
                    failure_reason="license_bootstrap_sync_error",
                    safe_message=_safe_message(exc),
                )
        return result

    def _check_license_before_login(self) -> LicenseDecision:
        if self._license_check is not None:
            return self._license_check()
        return check_license_before_login()

    def _write_license_decision_log(
        self,
        *,
        event: str,
        action: str,
        decision: LicenseDecision,
        emit_persistence_warning: bool = True,
    ) -> None:
        self._write_log(
            event=event,
            action=action,
            status="allowed" if decision.allowed else "blocked",
            failure_reason=None if decision.allowed else decision.reason,
            safe_message=decision.message_for_ui or decision.reason,
        )
        if emit_persistence_warning:
            self._write_license_persistence_warning_log(action=action, decision=decision)

    def _write_license_persistence_warning_log(
        self,
        *,
        action: str,
        decision: LicenseDecision,
    ) -> None:
        warning_code = getattr(decision, "warning_code", None)
        if not warning_code:
            return
        self._write_log(
            event="license_persistence_warning",
            action=action,
            status="warning",
            failure_reason=warning_code,
            safe_message=_license_warning_message(decision),
        )

    def _write_login_result_log(
        self,
        result: LoginResult,
        *,
        action: str,
        success_event: str,
        failed_event: str,
        password: str,
    ) -> None:
        response_code, response_msg = _response_summary(result)
        event = success_event if result.ok else failed_event
        self._write_log(
            event=event,
            action=action,
            status="success" if result.ok else "failed",
            failed_stage=result.failed_stage,
            failure_reason=None if result.ok else (result.error_code or result.status.value),
            safe_message=result.message,
            http_status=result.http_status,
            response_code=response_code,
            response_msg=response_msg,
            password=password,
        )
        if not result.ok and result.failed_stage:
            self._write_log(
                event="campus_login_failed_stage",
                action=action,
                status="failed",
                failed_stage=result.failed_stage,
                failure_reason=result.error_code or result.status.value,
                safe_message=result.message,
                response_msg=response_msg,
                password=password,
            )

    def _write_log(self, **kwargs) -> None:
        try:
            self._log_store.write(**kwargs)
        except Exception:
            LOGGER.exception("Runtime log write failed.")


class _LoginWorker(QObject):
    finished = Signal(object)

    def __init__(self, controller: MainWindowController, username: str, password: str):
        super().__init__()
        self._controller = controller
        self._username = username
        self._password = password

    @Slot()
    def run(self) -> None:
        try:
            result = self._controller.test_login(self._username, self._password)
        except Exception as exc:
            LOGGER.exception("Main window login test failed.")
            result = LoginResult(
                status=LoginStatus.UNKNOWN_ERROR,
                message=safe_exception_message(exc),
            )
        self.finished.emit(result)


class _LicenseInitializeWorker(QObject):
    finished = Signal(int, object, object)

    def __init__(self, generation: int, controller: MainWindowController):
        super().__init__()
        self._generation = generation
        self._controller = controller

    @Slot()
    def run(self) -> None:
        try:
            self.finished.emit(self._generation, self._controller.initialize_license(), None)
        except Exception as exc:
            LOGGER.exception("License initialization failed.")
            self.finished.emit(self._generation, None, exc)


class MainWindow(QMainWindow):
    def __init__(
        self,
        *,
        controller: Optional[MainWindowController] = None,
        auto_initialize_license: Optional[bool] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        controller_provided = controller is not None
        self._controller = controller or MainWindowController()
        self._thread: Optional[QThread] = None
        self._worker: Optional[_LoginWorker] = None
        self._license_thread: Optional[QThread] = None
        self._license_worker: Optional[_LicenseInitializeWorker] = None
        self._license_generation = 0
        self._auto_initialize_license = (
            (not controller_provided)
            if auto_initialize_license is None
            else bool(auto_initialize_license)
        )
        self._auto_initialize_attempted = False
        self._log_window: Optional[RuntimeLogWindow] = None
        self._build_ui()
        self.load_state()

    def load_state(self) -> None:
        try:
            state = self._controller.load_state()
        except Exception as exc:
            self._set_status("读取本地配置失败：" + _safe_message(exc), "error")
            return

        self.username_input.setText(state.username)
        self.password_input.setText(state.password)
        self.autostart_checkbox.setChecked(state.autostart_enabled)
        if state.config_exists:
            self._set_status("已读取本机配置，密码仅来自本机安全凭据。", "success")
        else:
            self._set_status("尚未保存配置，请输入校园网账号和密码。", "neutral")
        self.license_label.setText(state.license_message)
        self.license_label.set_variant(state.license_variant)
        if self._should_auto_initialize_license(state):
            self._start_license_initialization(auto=True)

    def closeEvent(self, event) -> None:
        self._license_generation += 1
        if self.isVisible():
            self.hide()
            event.ignore()
            return
        super().closeEvent(event)

    def _build_ui(self) -> None:
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumWidth(500)
        self.setMinimumHeight(640)

        root = QWidget(self)
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(16)

        title = QLabel("武汉理工校园网助手")
        title.setObjectName("title")
        subtitle = QLabel("保存一次账号密码，之后在已连接校园网环境时自动完成认证登录。")
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 18, 18, 18)
        card_layout.setSpacing(12)

        card_layout.addWidget(_field_label("校园网账号"))
        self.username_input = AccountLineEdit()
        self.username_input.setObjectName("accountInput")
        card_layout.addWidget(self.username_input)

        card_layout.addWidget(_field_label("校园网密码"))
        self.password_input = PasswordLineEdit()
        self.password_input.setObjectName("passwordInput")
        card_layout.addWidget(self.password_input)

        self.autostart_checkbox = QCheckBox("开机后自动启动并尝试登录校园网")
        self.autostart_checkbox.setMinimumHeight(34)
        card_layout.addWidget(self.autostart_checkbox)

        self.status_label = StatusLabel()
        self.status_label.setMinimumHeight(58)
        card_layout.addWidget(self.status_label)

        self.license_label = StatusLabel(LICENSE_PLACEHOLDER)
        card_layout.addWidget(self.license_label)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.save_button = QPushButton("保存配置")
        self.test_button = QPushButton("测试登录")
        self.clear_button = QPushButton("清除配置")
        for button in (self.save_button, self.test_button, self.clear_button):
            button.setMinimumHeight(40)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            actions.addWidget(button)
        card_layout.addLayout(actions)
        self.runtime_logs_button = QPushButton("查看运行日志")
        self.runtime_logs_button.setObjectName("runtimeLogsButton")
        self.runtime_logs_button.setMinimumHeight(38)
        self.runtime_logs_button.setCursor(Qt.CursorShape.PointingHandCursor)
        card_layout.addWidget(self.runtime_logs_button)
        layout.addWidget(card)

        notice = QLabel(
            "说明：本工具会在电脑已连接武汉理工校园网环境后，自动完成校园网认证登录。\n"
            "它不会自动选择 Wi-Fi、绕过验证码或突破校园网设备限制。\n"
            "校园网账号密码仅保存在本机，不会上传服务器。\n\n"
            "免费说明：本工具完全免费，无试用期、无内购、无需激活码。\n"
            "为统计使用人数，本工具只会向服务器上报本机设备指纹与最近使用时间，"
            "不会上报校园网账号和密码。"
        )
        notice.setObjectName("notice")
        notice.setWordWrap(True)
        self.notice_label = notice
        layout.addWidget(self.notice_label)
        layout.addStretch(1)

        self.save_button.clicked.connect(self._save_config)
        self.test_button.clicked.connect(self._start_test_login)
        self.clear_button.clicked.connect(self._confirm_clear_config)
        self.runtime_logs_button.clicked.connect(self._show_runtime_logs)

        self.setCentralWidget(root)
        self.setStyleSheet(_style_sheet())

    @Slot()
    def _save_config(self) -> None:
        try:
            message = self._controller.save(
                self.username_input.text(),
                self.password_input.text(),
                self.autostart_checkbox.isChecked(),
            )
        except (LocalConfigError, AutostartError) as exc:
            self._set_status(_safe_message(exc), "error")
            return
        except Exception as exc:
            LOGGER.exception("Failed to save main window config.")
            self._set_status("保存配置失败：" + _safe_message(exc), "error")
            return
        self._set_status(message, "success")

    @Slot()
    def _start_test_login(self) -> None:
        if self._thread is not None:
            return
        self._set_busy(True)
        self._set_status("登录中，请稍候...", "neutral")

        thread = QThread(self)
        worker = _LoginWorker(
            self._controller,
            self.username_input.text(),
            self.password_input.text(),
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._finish_test_login)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._release_worker)
        self._thread = thread
        self._worker = worker
        thread.start()

    def _should_auto_initialize_license(self, state: MainWindowState) -> bool:
        if not self._auto_initialize_license or self._auto_initialize_attempted:
            return False
        # 免费版：启动时后台上报一次设备使用情况，用于服务端统计使用人数。
        return bool(state.license_sync_pending)

    def _start_license_initialization(self, *, auto: bool = False) -> None:
        if self._license_thread is not None:
            return
        if auto:
            self._auto_initialize_attempted = True
        self._license_generation += 1
        generation = self._license_generation
        self.license_label.setText("正在上报设备使用情况…")
        self.license_label.set_variant("neutral")

        thread = QThread(self)
        worker = _LicenseInitializeWorker(generation, self._controller)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._finish_license_initialization)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._release_license_worker)
        self._license_thread = thread
        self._license_worker = worker
        thread.start()

    @Slot(int, object, object)
    def _finish_license_initialization(
        self,
        generation: int,
        decision: object,
        error: object,
    ) -> None:
        if generation != self._license_generation:
            return
        if error is not None:
            # 使用统计上报失败不影响免费版功能，仅记录日志。
            LOGGER.warning(
                "Device usage report failed: %s",
                getattr(error, "__class__", type(error)).__name__,
            )
            self._apply_license_label(free_decision(reason="free_mode_usage_report_failed"))
            return
        if not isinstance(decision, LicenseDecision):
            LOGGER.warning("Device usage report returned an invalid decision object.")
            self._apply_license_label(free_decision(reason="free_mode_usage_report_invalid"))
            return
        self._apply_license_label(decision)

    def _apply_license_label(self, decision: LicenseDecision) -> None:
        self.license_label.setText(decision.message_for_ui or LICENSE_PLACEHOLDER)
        self.license_label.set_variant(_license_variant(decision))

    @Slot()
    def _release_license_worker(self) -> None:
        self._license_thread = None
        self._license_worker = None

    @Slot(object)
    def _finish_test_login(self, result: LoginResult) -> None:
        text, variant = login_result_display(result)
        self._set_status(text, variant)
        self._set_busy(False)

    @Slot()
    def _release_worker(self) -> None:
        self._thread = None
        self._worker = None

    @Slot()
    def _confirm_clear_config(self) -> None:
        answer = QMessageBox.question(
            self,
            "清除配置",
            "确定要清除本机保存的校园网账号和密码吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            message = self._controller.clear()
        except Exception as exc:
            LOGGER.exception("Failed to clear main window config.")
            self._set_status("清除配置失败：" + _safe_message(exc), "error")
            return
        self.username_input.clear()
        self.password_input.clear()
        self.load_state()
        self._set_status(message, "success")

    @Slot()
    def _show_runtime_logs(self) -> None:
        if self._log_window is None:
            self._log_window = RuntimeLogWindow(log_store=self._controller.log_store)
        self._log_window.refresh_logs()
        self._log_window.show_for_owner(self)

    @Slot()
    def _set_status(self, text: str, variant: str) -> None:
        self.status_label.setText(text)
        self.status_label.set_variant(variant)

    def _set_busy(self, busy: bool) -> None:
        self.save_button.setEnabled(not busy)
        self.test_button.setEnabled(not busy)
        self.clear_button.setEnabled(not busy)
        self.test_button.setText("登录中" if busy else "测试登录")


def create_main_window(
    *,
    controller: Optional[MainWindowController] = None,
) -> MainWindow:
    return MainWindow(controller=controller)


def login_result_display(result: LoginResult) -> tuple[str, str]:
    status = result.status
    if status == LoginStatus.SUCCESS:
        return "登录成功，校园网认证已可用。", "success"
    if status == LoginStatus.ALREADY_ONLINE:
        return (
            "当前设备已在线，未重新提交本次账号密码；这不能证明新密码正确。"
            "如需验证新密码，请先从托盘登出校园网后再测试。",
            "warning",
        )
    if status == LoginStatus.NOT_CAMPUS_NETWORK:
        return "未检测到武汉理工校园网环境，请先连接校园网。", "warning"
    if status == LoginStatus.INVALID_CREDENTIALS:
        return "账号或密码可能错误，请检查后重试。", "error"
    if status in {LoginStatus.AUTH_SERVICE_UNAVAILABLE, LoginStatus.TIMEOUT}:
        return "校园网认证服务异常或请求超时，请稍后再试。", "warning"
    return f"登录失败：{result.message}", "error"


def _response_summary(result: LoginResult) -> tuple[object, str]:
    summary = result.response_summary or {}
    if not isinstance(summary, dict):
        return None, ""
    return (
        summary.get("code"),
        str(summary.get("msg") or summary.get("message") or summary.get("error") or ""),
    )


def _default_login_runner(username: str, password: str) -> LoginResult:
    return login_with_adapter(
        WhutCampusLoginAdapter(timeout=5.0),
        username,
        password,
    )


def _field_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("fieldLabel")
    return label


def _safe_message(exc: Exception) -> str:
    return safe_exception_message(exc)


def _license_warning_message(decision: LicenseDecision) -> str:
    if getattr(decision, "warning_code", None) == TOKEN_PERSIST_FAILED_WARNING:
        return TOKEN_PERSIST_FAILED_MESSAGE
    return decision.message_for_ui or str(getattr(decision, "warning_code", "") or "")


def _license_variant(decision: LicenseDecision) -> str:
    if decision.allowed:
        return "success"
    if decision.status.value in {"uninitialized", "server_unreachable", "config_only"}:
        return "warning"
    return "error"


def _license_sync_pending(decision: LicenseDecision) -> bool:
    """是否需要上报设备使用情况（免费版使用统计）。"""
    return _usage_sync_required(decision)


def _usage_sync_required(decision: LicenseDecision) -> bool:
    return bool(
        decision.bootstrap_required or getattr(decision, "usage_sync_required", False)
    )


def _style_sheet() -> str:
    return """
    QWidget#root {
        background: #F8FAFC;
        color: #020617;
        font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
        font-size: 14px;
    }
    QLabel#title {
        color: #0F172A;
        font-size: 24px;
        font-weight: 700;
        letter-spacing: 0;
    }
    QLabel#subtitle {
        color: #475569;
        font-size: 14px;
        line-height: 1.6;
    }
    QFrame#card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
    }
    QLabel#fieldLabel {
        color: #334155;
        font-weight: 600;
        font-size: 13px;
    }
    QLineEdit {
        background: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-radius: 8px;
        padding: 8px 10px;
        color: #0F172A;
        selection-background-color: #BAE6FD;
    }
    QLineEdit:focus {
        border: 1px solid #0369A1;
    }
    QCheckBox {
        color: #334155;
        spacing: 8px;
    }
    QPushButton {
        background: #0F172A;
        border: 1px solid #0F172A;
        border-radius: 8px;
        color: #FFFFFF;
        font-weight: 600;
        padding: 8px 12px;
    }
    QPushButton:hover {
        background: #0369A1;
        border-color: #0369A1;
    }
    QPushButton:disabled {
        background: #CBD5E1;
        border-color: #CBD5E1;
        color: #64748B;
    }
    QLabel#notice {
        color: #475569;
        background: #EFF6FF;
        border: 1px solid #BFDBFE;
        border-radius: 8px;
        padding: 12px;
        line-height: 1.6;
    }
    """
