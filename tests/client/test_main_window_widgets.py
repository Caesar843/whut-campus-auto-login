import os
from pathlib import Path
import sys


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication, QMessageBox, QLineEdit

from desktop_app.log_window import RuntimeLogWindow
from desktop_app.main_window import LICENSE_PLACEHOLDER, MainWindow, MainWindowController
from desktop_app.widgets import AccountLineEdit, PasswordLineEdit


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


def test_main_window_has_runtime_log_entry_button_and_preserves_pricing_copy():
    _app()
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
    )

    window = MainWindow(controller=controller)

    assert window.runtime_logs_button.text() == "查看运行日志"
    assert "免费试用 14 天" in window.notice_label.text()
    assert "9.9 元" in window.notice_label.text()
    assert ("8" + ".88") not in window.notice_label.text()
    assert ("免费试用 " + "7 天") not in window.notice_label.text()


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
        assert window.license_label.text() == LICENSE_PLACEHOLDER
        assert "#334155" in style
        assert "#E2E8F0" in style
        assert "#F8FAFC" in style
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
    window.license_label.setText("paid active")
    window.license_label.set_variant("success")

    window._confirm_clear_config()

    assert window.license_label.text() == "paid active"
    assert "#166534" in window.license_label.styleSheet()
    assert "clear failed" in window.status_label.text()


def test_main_window_initializes_fields_from_controller():
    _app()
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
    )

    window = MainWindow(controller=controller)

    assert window.username_input.text() == "366369"
    assert window.password_input.text() == "secret-password"
    assert window.password_input.echoMode() == QLineEdit.EchoMode.Password
    assert window.autostart_checkbox.isChecked() is True
    assert "未初始化" in window.license_label.text()
