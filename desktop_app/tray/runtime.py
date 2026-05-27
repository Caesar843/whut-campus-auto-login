import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QStyle, QSystemTrayIcon

from desktop_app.tray.controller import (
    TrayActionResult,
    TrayController,
    TrayStatus,
)


APP_NAME = "武汉理工校园网助手"


class _ActionWorker(QObject):
    finished = Signal(object)

    def __init__(self, action: Callable[[], TrayActionResult]):
        super().__init__()
        self._action = action

    @Slot()
    def run(self) -> None:
        try:
            result = self._action()
        except Exception as exc:
            result = TrayActionResult(
                action="worker",
                status=TrayStatus.UNKNOWN,
                message=str(exc)[:240] or exc.__class__.__name__,
            )
        self.finished.emit(result)


class TrayRuntime(QObject):
    status_changed = Signal(object)

    def __init__(
        self,
        app: QApplication,
        *,
        controller: Optional[TrayController] = None,
    ):
        super().__init__()
        self._app = app
        self._threads = []
        self._workers = []
        self._controller = controller or TrayController(
            exit_func=app.quit,
            on_status_changed=self.status_changed.emit,
        )
        self._tray = QSystemTrayIcon(_load_icon(app), self)
        self._menu = QMenu()
        self._status_action: Optional[QAction] = None
        self._busy_actions = []
        self.status_changed.connect(self._refresh_status)
        self._build_menu()

    def show(self) -> None:
        self._tray.setToolTip(self._tooltip_text())
        self._tray.setContextMenu(self._menu)
        self._tray.show()

    def _build_menu(self) -> None:
        title_action = self._menu.addAction(APP_NAME)
        title_action.setEnabled(False)
        self._menu.addSeparator()

        self._status_action = self._menu.addAction(self._controller.status_menu_text)
        self._status_action.setEnabled(False)
        self._menu.addSeparator()

        test_login_action = self._menu.addAction("测试登录")
        logout_action = self._menu.addAction("登出校园网")
        relogin_action = self._menu.addAction("重新登录")
        self._busy_actions = [test_login_action, logout_action, relogin_action]

        test_login_action.triggered.connect(
            lambda: self._start_action(self._controller.test_login)
        )
        logout_action.triggered.connect(
            lambda: self._start_action(self._controller.logout)
        )
        relogin_action.triggered.connect(
            lambda: self._start_action(self._controller.relogin)
        )

        self._menu.addSeparator()
        exit_action = self._menu.addAction("退出")
        exit_action.triggered.connect(self._controller.request_exit)

    def _start_action(self, action: Callable[[], TrayActionResult]) -> None:
        self._set_busy_actions_enabled(False)
        thread = QThread(self)
        worker = _ActionWorker(action)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.finished.connect(self._on_action_finished)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        worker.finished.connect(
            lambda _result, item=worker: self._remove_worker(item)
        )
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda item=thread: self._remove_thread(item))

        self._threads.append(thread)
        self._workers.append(worker)
        thread.start()

    @Slot(object)
    def _on_action_finished(self, _result: TrayActionResult) -> None:
        self._refresh_status(self._controller.status)
        self._set_busy_actions_enabled(True)

    @Slot(object)
    def _refresh_status(self, _status: object) -> None:
        if self._status_action:
            self._status_action.setText(self._controller.status_menu_text)
        self._tray.setToolTip(self._tooltip_text())

    def _tooltip_text(self) -> str:
        return f"{APP_NAME}\n{self._controller.status_menu_text}"

    def _set_busy_actions_enabled(self, enabled: bool) -> None:
        for action in self._busy_actions:
            action.setEnabled(enabled)

    def _remove_thread(self, thread: QThread) -> None:
        if thread in self._threads:
            self._threads.remove(thread)

    def _remove_worker(self, worker: _ActionWorker) -> None:
        if worker in self._workers:
            self._workers.remove(worker)


def run_tray_app(
    argv: Optional[Sequence[str]] = None,
    *,
    controller: Optional[TrayController] = None,
) -> int:
    app = QApplication.instance()
    if app is None:
        app = QApplication([APP_NAME, *list(argv or [])])
    app.setQuitOnLastWindowClosed(False)

    runtime = TrayRuntime(app, controller=controller)
    runtime.show()
    app._whut_tray_runtime = runtime
    return int(app.exec())


def _load_icon(app: QApplication) -> QIcon:
    resources_dir = Path(__file__).resolve().parents[1] / "resources"
    for name in ("app.ico", "icon.ico", "app.png", "icon.png"):
        icon_path = resources_dir / name
        if icon_path.exists():
            icon = QIcon(str(icon_path))
            if not icon.isNull():
                return icon
    return app.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)


if __name__ == "__main__":
    raise SystemExit(run_tray_app(sys.argv[1:]))
