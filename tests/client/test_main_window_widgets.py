import os
from pathlib import Path
import sys
import threading
import time


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication, QMessageBox, QLineEdit, QWidget

from desktop_app.log_window import RuntimeLogWindow
from desktop_app.main_window import LICENSE_PLACEHOLDER, MainWindow, MainWindowController
from desktop_app.widgets import AccountLineEdit, PasswordLineEdit
from license_client.license_state import LicenseDecision, LicenseStatus


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


class _FakeSignal:
    def connect(self, callback):
        self.callback = callback


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


def _is_child_of(widget, ancestor):
    parent = widget.parent()
    while parent is not None:
        if parent is ancestor:
            return True
        parent = parent.parent()
    return False


def _layout_contains_widget(layout, widget):
    for index in range(layout.count()):
        item = layout.itemAt(index)
        if item.widget() is widget:
            return True
        child_layout = item.layout()
        if child_layout is not None and _layout_contains_widget(child_layout, widget):
            return True
        child_widget = item.widget()
        if child_widget is not None and child_widget.layout() is not None:
            if _layout_contains_widget(child_widget.layout(), widget):
                return True
    return False


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


def test_main_window_payment_button_text_tracks_license_state():
    _app()
    cases = [
        (LicenseStatus.TRIAL_ACTIVE, "购买一年授权", True),
        (LicenseStatus.TRIAL_EXPIRED, "立即购买授权", True),
        (LicenseStatus.PAID_ACTIVE, "续费一年", True),
        (LicenseStatus.PAID_EXPIRED, "续费授权", True),
        (LicenseStatus.UNINITIALIZED, "初始化授权", True),
        (LicenseStatus.SERVER_UNREACHABLE, "重试初始化", True),
        (LicenseStatus.REVOKED, "授权已撤销", False),
        (LicenseStatus.TOKEN_INVALID, "暂无法购买", False),
    ]

    for status, text, enabled in cases:
        window = MainWindow(controller=_controller_for_license(status))

        assert window.payment_button.text() == text
        assert window.payment_button.isEnabled() is enabled


def test_main_window_payment_button_is_visible_in_real_layout():
    app = _app()
    window = MainWindow(controller=_controller_for_license(LicenseStatus.UNINITIALIZED))

    assert window.payment_button.parent() is not None
    assert _is_child_of(window.payment_button, window)
    assert _layout_contains_widget(window.centralWidget().layout(), window.payment_button)

    window.show()
    app.processEvents()

    assert window.payment_button.text() == "初始化授权"
    assert window.payment_button.isVisible() is True
    assert window.payment_button.isVisibleTo(window) is True
    window.close()


def test_main_window_payment_button_stays_visible_when_license_load_fails():
    app = _app()

    def fail_license():
        raise RuntimeError("license load failed")

    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
        license_state_func=fail_license,
    )
    window = MainWindow(controller=controller)

    window.show()
    app.processEvents()

    assert window.payment_button.text() == "暂无法购买"
    assert window.payment_button.isEnabled() is False
    assert window.payment_button.isVisibleTo(window) is True
    window.close()


def test_uninitialized_payment_button_runs_license_initialization_without_payment(monkeypatch):
    _app()
    init_calls = []
    payment_windows = []

    class FakePaymentWindow(QWidget):
        activated = _FakeSignal()
        finished = _FakeSignal()

        def __init__(self, parent=None):
            super().__init__(parent)
            payment_windows.append(self)

    monkeypatch.setattr("desktop_app.payment_window.PaymentWindow", FakePaymentWindow)
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
        license_state_func=lambda: LicenseDecision(
            status=LicenseStatus.UNINITIALIZED,
            allowed=False,
            reason="missing_signed_license_token",
            message_for_ui="uninitialized",
        ),
        license_initialize_func=lambda: init_calls.append("init")
        or LicenseDecision(
            status=LicenseStatus.TRIAL_ACTIVE,
            allowed=True,
            reason="trial_active",
            message_for_ui="trial_active",
        ),
    )
    window = MainWindow(controller=controller)

    window._start_license_initialization = lambda auto=False: window._finish_license_initialization(
        window._license_generation,
        controller.initialize_license(),
        None,
    )
    window.payment_button.click()

    assert init_calls == ["init"]
    assert payment_windows == []


def test_license_initialization_in_progress_disables_button_and_releases_thread():
    app = _app()
    release = threading.Event()
    init_calls = []
    current = {
        "decision": LicenseDecision(
            status=LicenseStatus.UNINITIALIZED,
            allowed=False,
            reason="missing_signed_license_token",
            message_for_ui="uninitialized",
        )
    }
    active = LicenseDecision(
        status=LicenseStatus.TRIAL_ACTIVE,
        allowed=True,
        reason="trial_active",
        message_for_ui="trial_active",
    )

    def initialize():
        init_calls.append("init")
        release.wait(2)
        current["decision"] = active
        return active

    window = MainWindow(
        controller=MainWindowController(
            load_config_func=lambda: FakeConfig(),
            is_autostart_enabled_func=lambda: True,
            license_state_func=lambda: current["decision"],
            license_initialize_func=initialize,
        )
    )

    window._start_license_initialization()
    deadline = time.monotonic() + 1
    while not init_calls and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)

    window.payment_button.click()

    assert init_calls == ["init"]
    assert window.payment_button.text() == "正在初始化授权…"
    assert window.payment_button.isEnabled() is False
    assert window.save_button.isEnabled() is True
    assert window.test_button.isEnabled() is True

    release.set()
    deadline = time.monotonic() + 2
    while window._license_thread is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)

    assert window._license_thread is None
    assert window._license_worker is None
    assert window.payment_button.text() == "购买一年授权"


def test_license_initialization_success_refreshes_payment_button():
    _app()
    current = {
        "decision": LicenseDecision(
            status=LicenseStatus.UNINITIALIZED,
            allowed=False,
            reason="missing_signed_license_token",
            message_for_ui="uninitialized",
        )
    }
    active = LicenseDecision(
            status=LicenseStatus.TRIAL_ACTIVE,
            allowed=True,
            reason="trial_active",
            message_for_ui="trial_active",
    )

    def initialize():
        current["decision"] = active
        return active

    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
        license_state_func=lambda: current["decision"],
        license_initialize_func=initialize,
    )
    window = MainWindow(controller=controller)

    window._finish_license_initialization(0, controller.initialize_license(), None)

    assert window.payment_button.text() == "购买一年授权"
    assert window.payment_button.isEnabled() is True


def test_license_initialization_failure_can_retry_without_payment_window(monkeypatch):
    _app()
    created = []
    init_calls = []

    class FakePaymentWindow(QWidget):
        activated = _FakeSignal()
        finished = _FakeSignal()

        def __init__(self, parent=None):
            super().__init__(parent)
            created.append(self)

    monkeypatch.setattr("desktop_app.payment_window.PaymentWindow", FakePaymentWindow)
    controller = MainWindowController(
        load_config_func=lambda: FakeConfig(),
        is_autostart_enabled_func=lambda: True,
        license_state_func=lambda: LicenseDecision(
            status=LicenseStatus.UNINITIALIZED,
            allowed=False,
            reason="missing_signed_license_token",
            message_for_ui="uninitialized",
        ),
        license_initialize_func=lambda: init_calls.append("init")
        or LicenseDecision(
            status=LicenseStatus.SERVER_UNREACHABLE,
            allowed=False,
            reason="network_unreachable",
            message_for_ui="network failed",
        ),
    )
    window = MainWindow(controller=controller)

    window._finish_license_initialization(0, controller.initialize_license(), None)

    assert init_calls == ["init"]
    assert created == []
    assert window.payment_button.text() == "重试初始化"
    assert window.payment_button.isEnabled() is True


def test_license_initialization_late_response_is_ignored():
    _app()
    window = MainWindow(controller=_controller_for_license(LicenseStatus.UNINITIALIZED))
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

    assert window.payment_button.text() == "初始化授权"


def test_main_window_reuses_single_payment_window(monkeypatch):
    _app()
    created = []

    class FakePaymentWindow(QWidget):
        activated = _FakeSignal()
        finished = _FakeSignal()

        def __init__(self, parent=None):
            super().__init__(parent)
            created.append(self)
            self.show_calls = 0

        def show(self):
            self.show_calls += 1

        def raise_(self):
            pass

        def activateWindow(self):
            pass

    monkeypatch.setattr("desktop_app.payment_window.PaymentWindow", FakePaymentWindow)
    window = MainWindow(controller=_controller_for_license(LicenseStatus.TRIAL_ACTIVE))

    window.payment_button.click()
    first = window._payment_window
    window.payment_button.click()

    assert len(created) == 1
    assert window._payment_window is first
    assert first.show_calls == 2


def test_payment_activation_keeps_paid_state_when_old_license_init_finishes(monkeypatch):
    _app()
    paid = LicenseDecision(
        status=LicenseStatus.PAID_ACTIVE,
        allowed=True,
        reason="paid_active",
        message_for_ui="paid-after-refresh",
    )

    class Signal:
        def __init__(self):
            self._callbacks = []

        def connect(self, callback):
            self._callbacks.append(callback)

        def emit(self, *args):
            for callback in list(self._callbacks):
                callback(*args)

    class FakePaymentWindow(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.activated = Signal()
            self.finished = Signal()

        def show(self):
            pass

        def raise_(self):
            pass

        def activateWindow(self):
            pass

    monkeypatch.setattr("desktop_app.payment_window.PaymentWindow", FakePaymentWindow)
    window = MainWindow(
        controller=MainWindowController(
            load_config_func=lambda: FakeConfig(),
            is_autostart_enabled_func=lambda: True,
            license_state_func=lambda: paid,
        )
    )
    window._license_generation += 1
    pending_generation = window._license_generation

    window.payment_button.click()
    payment_window = window._payment_window
    payment_window.activated.emit(paid)
    payment_window.finished.emit()
    window._finish_license_initialization(
        pending_generation,
        LicenseDecision(
            status=LicenseStatus.TOKEN_INVALID,
            allowed=False,
            reason="signature_invalid",
            message_for_ui="old-invalid",
        ),
        None,
    )

    assert window.license_label.text() == "paid-after-refresh"
    assert window._payment_window is None


def test_expired_license_payment_button_click_opens_payment_window(monkeypatch):
    _app()

    class FakePaymentWindow(QWidget):
        activated = _FakeSignal()
        finished = _FakeSignal()

        def __init__(self, parent=None):
            super().__init__(parent)

        def show(self):
            pass

        def raise_(self):
            pass

        def activateWindow(self):
            pass

    monkeypatch.setattr("desktop_app.payment_window.PaymentWindow", FakePaymentWindow)
    for status in (LicenseStatus.TRIAL_EXPIRED, LicenseStatus.PAID_EXPIRED):
        window = MainWindow(controller=_controller_for_license(status))

        assert window.payment_button.isEnabled() is True
        window.payment_button.click()

        assert isinstance(window._payment_window, FakePaymentWindow)
