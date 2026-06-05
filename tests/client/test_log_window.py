import os
from pathlib import Path
import sys


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication

from desktop_app.log_window import RuntimeLogWindow


def _app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(["test-log-window"])
    return app


class FakeLogStore:
    def __init__(self):
        self.copied = False
        self.cleared = False
        self.empty = False
        self.read_limits = []
        self.diagnostic_limits = []

    def read_recent(self, limit=80):
        self.read_limits.append(limit)
        if self.empty:
            return []
        return [
            {
                "timestamp": "2026-06-05T18:21:03",
                "event": "manual_login_failed",
                "action": "test_login",
                "status": "failed",
                "safe_message": "校园网登录失败",
                "failed_stage": "account_login",
                "failure_reason": "invalid_credentials",
                "retry_count": 0,
            },
            {
                "timestamp": "2026-06-05T18:21:09",
                "event": "logout_success",
                "action": "logout",
                "status": "success",
                "safe_message": "校园网登出成功",
                "retry_count": 0,
            },
        ]

    def build_diagnostic_text(self, limit=30):
        self.copied = True
        self.diagnostic_limits.append(limit)
        return "武汉理工校园网助手诊断信息\n最近 30 条\n账号：36****69"

    def clear(self):
        self.cleared = True
        self.empty = True
        return True


def test_log_window_displays_entries_and_refreshes_with_limit_80():
    _app()
    store = FakeLogStore()
    window = RuntimeLogWindow(log_store=store)

    text = window.log_text.toPlainText()

    assert "校园网登录失败" in text
    assert "manual_login_failed" in text
    assert "{" not in text
    assert store.read_limits[-1] == 80


def test_log_window_copies_latest_30_diagnostic_entries():
    app = _app()
    store = FakeLogStore()
    window = RuntimeLogWindow(log_store=store)

    window.copy_diagnostic_info()

    assert store.copied is True
    assert store.diagnostic_limits == [30]
    assert "最近 30 条" in app.clipboard().text()
    assert "36****69" in app.clipboard().text()


def test_log_window_clear_refreshes_to_empty_state_without_closing(monkeypatch):
    _app()
    store = FakeLogStore()
    window = RuntimeLogWindow(log_store=store)

    monkeypatch.setattr(
        "desktop_app.log_window.QMessageBox.question",
        lambda *args, **kwargs: window._yes_button(),
    )

    window.confirm_clear_logs()

    assert store.cleared is True
    assert window.log_text.toPlainText() == "暂无运行日志。"
    assert window.isVisible() is False


def test_log_window_is_independent_top_level_window_with_target_size():
    _app()
    window = RuntimeLogWindow(log_store=FakeLogStore())

    assert window.isWindow() is True
    assert window.parent() is None
    assert window.width() == 900
    assert window.height() == 620
    assert window.minimumWidth() == 760
    assert window.minimumHeight() == 480
