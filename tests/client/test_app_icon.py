import importlib
import os
import sys
from pathlib import Path

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QWidget

from desktop_app.tray import runtime
from desktop_app.tray.controller import TrayStatus


APP_ICON_RESOURCE = "assets/windows/whut_campus_auto_login.ico"


class _LogStore:
    def cleanup(self):
        return True

    def write(self, **_kwargs):
        return True


class _Controller:
    status = TrayStatus.UNKNOWN
    status_menu_text = "状态：未知"

    def test_login(self):
        return None

    def logout(self):
        return None

    def relogin(self):
        return None

    def startup_auto_login(self, retry_count=1):
        return None

    def request_exit(self):
        return None


def _app():
    app = QApplication.instance() or QApplication(["test-app-icon"])
    app.setQuitOnLastWindowClosed(False)
    return app


def test_resource_path_uses_source_root_and_ignores_current_directory(tmp_path, monkeypatch):
    resources = importlib.import_module("desktop_app.resources")
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    monkeypatch.chdir(tmp_path)

    path = resources.resource_path(APP_ICON_RESOURCE)

    assert path == Path(__file__).resolve().parents[2] / APP_ICON_RESOURCE


def test_resource_path_uses_frozen_bundle_root(tmp_path, monkeypatch):
    resources = importlib.import_module("desktop_app.resources")
    icon = tmp_path / APP_ICON_RESOURCE
    icon.parent.mkdir(parents=True)
    icon.write_bytes(b"icon")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    assert resources.resource_path(APP_ICON_RESOURCE) == icon


def test_resource_path_reports_missing_resource(tmp_path, monkeypatch):
    resources = importlib.import_module("desktop_app.resources")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    with pytest.raises(FileNotFoundError, match="Application resource is missing"):
        resources.resource_path(APP_ICON_RESOURCE)


def test_missing_runtime_icon_uses_safe_qt_fallback(monkeypatch):
    app = _app()

    def missing(_relative_path):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(runtime, "resource_path", missing)

    assert not runtime._load_icon(app).isNull()


def test_application_window_and_tray_share_official_icon():
    app = _app()
    app.setWindowIcon(QIcon())
    tray_runtime = runtime.TrayRuntime(
        app,
        controller=_Controller(),
        main_window_factory=QWidget,
        log_store=_LogStore(),
    )

    window = tray_runtime.show_main_window()
    icon_keys = {
        app.windowIcon().cacheKey(),
        window.windowIcon().cacheKey(),
        tray_runtime._tray.icon().cacheKey(),
    }

    assert 0 not in icon_keys
    assert len(icon_keys) == 1
    window.hide()
    tray_runtime._tray.hide()
