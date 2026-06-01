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
from desktop_app.widgets import AccountLineEdit, PasswordLineEdit, StatusLabel


LOGGER = logging.getLogger(__name__)
WINDOW_TITLE = "武汉理工校园网助手"
LICENSE_PLACEHOLDER = "授权状态：未接入授权 / 本地配置阶段"


LoginRunner = Callable[[str, str], LoginResult]


@dataclass(frozen=True)
class MainWindowState:
    username: str = ""
    password: str = ""
    auto_login_enabled: bool = True
    autostart_enabled: bool = False
    config_exists: bool = False
    credential_exists: bool = False


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
    ):
        self._load_config = load_config_func
        self._save_config = save_config_func
        self._clear_config = clear_config_func
        self._is_autostart_enabled = is_autostart_enabled_func
        self._enable_autostart = enable_autostart_func
        self._disable_autostart = disable_autostart_func
        self._login_runner = login_runner or _default_login_runner

    def load_state(self) -> MainWindowState:
        config = self._load_config()
        return MainWindowState(
            username=str(getattr(config, "username", "") or ""),
            password=str(getattr(config, "password", "") or ""),
            auto_login_enabled=bool(getattr(config, "auto_login_enabled", True)),
            autostart_enabled=bool(self._is_autostart_enabled()),
            config_exists=bool(getattr(config, "config_exists", False)),
            credential_exists=bool(getattr(config, "credential_exists", False)),
        )

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
            return LoginResult(
                status=LoginStatus.UNKNOWN_ERROR,
                message="请先输入校园网账号和密码。",
            )
        return self._login_runner(clean_username, password)


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
                message=str(exc)[:240] or exc.__class__.__name__,
            )
        self.finished.emit(result)


class MainWindow(QMainWindow):
    def __init__(
        self,
        *,
        controller: Optional[MainWindowController] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._controller = controller or MainWindowController()
        self._thread: Optional[QThread] = None
        self._worker: Optional[_LoginWorker] = None
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

    def closeEvent(self, event) -> None:
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
        layout.addWidget(card)

        notice = QLabel(
            "说明：本工具会在电脑已连接武汉理工校园网环境后，自动完成校园网认证登录。\n"
            "它不会自动选择 Wi-Fi、绕过验证码或突破校园网设备限制。\n"
            "校园网账号密码仅保存在本机，不会上传服务器。\n\n"
            "付费说明：免费试用 7 天。试用结束后，8.88 元 / 年。"
            "支付成功后会自动激活正式版，无需输入激活码。"
        )
        notice.setObjectName("notice")
        notice.setWordWrap(True)
        layout.addWidget(notice)
        layout.addStretch(1)

        self.save_button.clicked.connect(self._save_config)
        self.test_button.clicked.connect(self._start_test_login)
        self.clear_button.clicked.connect(self._confirm_clear_config)

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
        self._set_status(message, "success")
        self.license_label.setText(LICENSE_PLACEHOLDER)

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
    return str(exc)[:240] or exc.__class__.__name__


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
