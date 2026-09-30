import os
from pathlib import Path
import sys
import threading
import time


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication, QMessageBox, QLineEdit

from desktop_app.log_window import RuntimeLogWindow
from desktop_app.main_window import LICENSE_PLACEHOLDER, MainWindow, MainWindowController
from desktop_app.widgets import AccountLineEdit, PasswordLineEdit
from license_client.license_state import (
    FREE_LICENSE_MESSAGE,
    LicenseDecision,
    LicenseStatus,
    free_decision,
)


def _app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(["test-main-window"])
    return app


class FakeConfig:
    username = "366369"
    password = "secret-password"
    auto_login_enabled = True
    config_exists = True
    credential_exists = True


class FakeLogStore:
    def read_recent(self, limit=80):
        return []

    def build_diagnostic_text(self, limit=30):
        return "诊断信息"

    def clear(self):
        return True


def _controller_for_license(status):
    return MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
        license_state_func=lambda: LicenseDecision(
            status=status,
            allowed=status in {LicenseStatus.TRIAL_ACTIVE, LicenseStatus.PAID_ACTIVE},
            reason=status.value,
            message_for_ui=status.value,
        ),
    )


def _free_controller(**kwargs):
    defaults = {
        "load_config_func": lambda: FakeConfig(),
        "is_autostart_enabled_func": lambda: True,
        "license_state_func": lambda: free_decision(usage_sync_required=True),
    }
    defaults.update(kwargs)
    return MainWindowController(**defaults)


def test_password_field_is_hidden_by_default_and_toggles_visibility():
    _app()
    field = PasswordLineEdit()
    field.setText("secret-password")
    field.setCursorPosition(4)

    assert field.echoMode() == QLineEdit.EchoMode.Password
    assert field.password_visible is False

    field.toggle_password_visible()

    assert field.echoMode() == QLineEdit.EchoMode.Normal
    assert field.password_visible is True
    assert field.cursorPosition() == 4

    field.toggle_password_visible()

    assert field.echoMode() == QLineEdit.EchoMode.Password
    assert field.password_visible is False
    assert field.cursorPosition() == 4


def test_account_field_has_placeholder_and_leading_action():
    _app()
    field = AccountLineEdit()

    assert "校园网账号" in field.placeholderText()
    assert field.actions()


def test_main_window_has_runtime_log_entry_button_and_free_version_copy():
    _app()
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
    )

    window = MainWindow(controller=controller)

    assert window.runtime_logs_button.text() == "查看运行日志"
    notice = window.notice_label.text()
    assert "免费" in notice
    assert "无需激活码" in notice
    assert "校园网账号密码" in notice
    # 免费版只声明"无试用期、无内购、无需激活码"，不再出现价格与购买入口
    assert "无试用期" in notice
    for forbidden in ("9.9", "购买", "付费", "支付", "续费", "元/年"):
        assert forbidden not in notice


def test_main_window_reuses_independent_runtime_log_window():
    _app()
    log_store = FakeLogStore()
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
        log_store=log_store,
    )
    window = MainWindow(controller=controller)

    window._show_runtime_logs()
    first = window._log_window
    window._show_runtime_logs()

    assert window._log_window is first
    assert isinstance(first, RuntimeLogWindow)
    assert first.isWindow() is True
    assert first.parent() is None
    assert window.findChildren(RuntimeLogWindow) == []


def test_clear_config_resets_license_label_text_and_variant(monkeypatch):
    _app()
    calls = []
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        clear_config_func=lambda: calls.append("clear"),
        is_autostart_enabled_func=lambda: True,
        license_state_func=lambda: LicenseDecision(
            status=LicenseStatus.UNINITIALIZED,
            allowed=False,
            reason="missing_signed_license_token",
            message_for_ui="授权尚未初始化，或当前无法连接授权服务。",
        ),
    )
    window = MainWindow(controller=controller)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )

    for variant, old_color in (
        ("success", "#166534"),
        ("warning", "#92400E"),
        ("error", "#991B1B"),
    ):
        window.license_label.setText(f"{variant} license")
        window.license_label.set_variant(variant)

        window._confirm_clear_config()

        style = window.license_label.styleSheet()
        assert "授权尚未初始化" in window.license_label.text()
        assert "#92400E" in style
        assert "#FDE68A" in style
        if variant != "warning":
            assert old_color not in style

    assert calls == ["clear", "clear", "clear"]


def test_clear_config_failure_does_not_reset_license_label(monkeypatch):
    _app()

    def fail_clear():
        raise RuntimeError("clear failed")

    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        clear_config_func=fail_clear,
        is_autostart_enabled_func=lambda: True,
    )
    window = MainWindow(controller=controller)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    window.license_label.setText("free license")
    window.license_label.set_variant("success")

    window._confirm_clear_config()

    assert window.license_label.text() == "free license"
    assert "#166534" in window.license_label.styleSheet()
    assert "clear failed" in window.status_label.text()


def test_main_window_initializes_fields_from_controller():
    _app()
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
        license_state_func=lambda: LicenseDecision(
            status=LicenseStatus.UNINITIALIZED,
            allowed=False,
            reason="missing_signed_license_token",
            message_for_ui="授权尚未初始化，或当前无法连接授权服务。",
        ),
    )

    window = MainWindow(controller=controller)

    assert window.username_input.text() == "366369"
    assert window.password_input.text() == "secret-password"
    assert window.password_input.echoMode() == QLineEdit.EchoMode.Password
    assert window.autostart_checkbox.isChecked() is True
    assert "未初始化" in window.license_label.text()


# ---------------------------------------------------------------------------
# 免费版：主界面没有任何支付入口
# ---------------------------------------------------------------------------


def test_main_window_has_no_payment_entry_points():
    _app()
    window = MainWindow(controller=_free_controller())

    for attribute in (
        "payment_button",
        "_payment_window",
        "_show_payment_window",
        "_release_payment_window",
        "_apply_payment_activation",
        "_payment_button_text",
        "_payment_button_enabled",
        "_payment_button_action",
    ):
        assert not hasattr(window, attribute), attribute

    labels = [child.text() for child in window.findChildren(type(window.license_label))]
    joined = " ".join(labels)
    for forbidden in ("购买", "续费", "支付", "激活码"):
        assert forbidden not in joined


def test_main_window_hides_free_license_label():
    _app()
    window = MainWindow(controller=_free_controller())

    # 免费版正常状态不显示授权说明文字
    assert window.license_label.text() == FREE_LICENSE_MESSAGE == ""
    assert window.license_label.isHidden()


def test_license_placeholder_is_empty():
    assert LICENSE_PLACEHOLDER == ""


def test_license_label_never_blocks_for_legacy_states():
    _app()
    for status in (
        LicenseStatus.TRIAL_EXPIRED,
        LicenseStatus.PAID_EXPIRED,
        LicenseStatus.REVOKED,
        LicenseStatus.TOKEN_INVALID,
        LicenseStatus.SERVER_UNREACHABLE,
        LicenseStatus.UNINITIALIZED,
    ):
        window = MainWindow(controller=_controller_for_license(status))
        # 免费版界面不再出现任何"购买/初始化授权"按钮，只展示状态文本
        assert not hasattr(window, "payment_button")
        assert window.license_label.text()


def test_usage_report_in_progress_marks_label_and_releases_thread():
    app = _app()
    release = threading.Event()
    init_calls = []

    def initialize():
        init_calls.append("init")
        release.wait(2)
        return free_decision()

    window = MainWindow(
        controller=_free_controller(license_initialize_func=initialize)
    )

    window._start_license_initialization()
    deadline = time.monotonic() + 1
    while not init_calls and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)

    # 进行中再次调用不会重复上报
    window._start_license_initialization()

    assert init_calls == ["init"]
    assert window.license_label.text() == "正在上报设备使用情况…"
    assert window.save_button.isEnabled() is True
    assert window.test_button.isEnabled() is True

    release.set()
    deadline = time.monotonic() + 3
    while window._license_thread is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)

    assert window._license_thread is None
    assert window._license_worker is None
    assert window.license_label.text() == FREE_LICENSE_MESSAGE


def test_usage_report_success_applies_free_label():
    _app()
    window = MainWindow(controller=_free_controller())

    window._finish_license_initialization(0, free_decision(), None)

    assert window.license_label.text() == FREE_LICENSE_MESSAGE
    assert "#166534" in window.license_label.styleSheet()


def test_usage_report_failure_keeps_free_label_and_no_retry_ui():
    _app()

    def initialize():
        raise RuntimeError("server unreachable")

    window = MainWindow(
        controller=_free_controller(license_initialize_func=initialize)
    )

    window._finish_license_initialization(0, None, RuntimeError("server unreachable"))

    assert window.license_label.text() == FREE_LICENSE_MESSAGE
    assert not hasattr(window, "payment_button")


def test_usage_report_invalid_decision_keeps_free_label():
    _app()
    window = MainWindow(controller=_free_controller())

    window._finish_license_initialization(0, "not-a-decision", None)

    assert window.license_label.text() == FREE_LICENSE_MESSAGE


def test_late_usage_report_response_is_ignored():
    _app()
    window = MainWindow(controller=_free_controller())
    old_generation = window._license_generation
    window.close()

    window._finish_license_initialization(
        old_generation,
        LicenseDecision(
            status=LicenseStatus.TRIAL_ACTIVE,
            allowed=True,
            reason="trial_active",
            message_for_ui="trial_active",
        ),
        None,
    )

    assert window.license_label.text() == FREE_LICENSE_MESSAGE


def test_auto_usage_report_runs_once_on_startup():
    _app()
    calls = []
    controller = _free_controller(
        license_initialize_func=lambda: calls.append("init") or free_decision()
    )
    window = MainWindow(controller=controller, auto_initialize_license=False)

    assert calls == []
    window.load_state()
    assert calls == []
    window.close()


def test_main_window_never_imports_payment_module():
    import desktop_app.main_window as main_window_module

    text = Path(main_window_module.__file__).read_text(encoding="utf-8")
    for forbidden in ("payment", "Payment", "PAYMENT", "wechat"):
        assert forbidden not in text, forbidden