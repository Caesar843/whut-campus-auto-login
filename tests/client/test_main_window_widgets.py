import os
from pathlib import Path
import sys


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication, QLineEdit

from desktop_app.main_window import MainWindow, MainWindowController
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
