from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

from PySide6.QtCore import QObject, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QStyle, QSystemTrayIcon, QWidget

from desktop_app.main_window import create_main_window
from desktop_app.tray.controller import (
    TrayActionResult,
    TrayController,
    TrayStatus,
)


APP_NAME = "武汉理工校园网助手"
STARTUP_TRAY_ARG = "--startup-tray"
STARTUP_INITIAL_DELAY_MS = 5_000
STARTUP_RETRY_INTERVAL_MS = 12_000
STARTUP_MAX_ATTEMPTS = 12
STARTUP_DEVICE_MISMATCH_MAX_ATTEMPTS = 3
MainWindowFactory = Callable[[], QWidget]
ActionFinishedCallback = Callable[[TrayActionResult], None]
ScheduleOnce = Callable[[int, Callable[[], None]], None]
StartAttempt = Callable[[int, ActionFinishedCallback], bool]


class StartupAutoLoginRetryCoordinator:
    def __init__(
        self,
        *,
        controller: TrayController,
        start_attempt: StartAttempt,
        schedule_once: ScheduleOnce,
        initial_delay_ms: int = STARTUP_INITIAL_DELAY_MS,
        retry_interval_ms: int = STARTUP_RETRY_INTERVAL_MS,
        max_attempts: int = STARTUP_MAX_ATTEMPTS,
        device_mismatch_max_attempts: int = STARTUP_DEVICE_MISMATCH_MAX_ATTEMPTS,
    ):
        self._controller = controller
        self._start_attempt = start_attempt
        self._schedule_once = schedule_once
        self._initial_delay_ms = initial_delay_ms
        self._retry_interval_ms = retry_interval_ms
        self._max_attempts = max_attempts
        self._device_mismatch_max_attempts = device_mismatch_max_attempts
        self._active = False
        self._attempt_running = False
        self._attempt_count = 0
        self._device_mismatch_count = 0
        self._generation = 0

    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> None:
        if self._active or self._attempt_running:
            return
        self._active = True
        self._attempt_count = 0
        self._device_mismatch_count = 0
        self._schedule(self._initial_delay_ms)

    def cancel(self) -> None:
        self._active = False
        self._generation += 1

    def _schedule(self, delay_ms: int) -> None:
        generation = self._generation
        self._schedule_once(
            delay_ms,
            lambda: self._run_scheduled_attempt(generation),
        )

    def _run_scheduled_attempt(self, generation: int) -> None:
        if generation != self._generation or not self._active or self._attempt_running:
            return
        if self._attempt_count >= self._max_attempts:
            return

        self._attempt_count += 1
        self._attempt_running = True
        started = self._start_attempt(
            self._attempt_count,
            lambda result: self._on_attempt_finished(result, generation),
        )
        if not started:
            self._attempt_running = False
            result = TrayActionResult(
                action="startup_auto_login",
                status=TrayStatus.LOGIN_FAILED,
                message="Startup auto login action could not start.",
                retryable=True,
                failure_reason="action_busy",
                retry_count=self._attempt_count,
            )
            if self._attempt_count >= self._max_attempts:
                self._stop(result)
                return
            self._controller.mark_startup_retrying(result)
            self._schedule(self._retry_interval_ms)

    def _on_attempt_finished(self, result: TrayActionResult, generation: int) -> None:
        self._attempt_running = False
        if generation != self._generation or not self._active:
            return
        if result.status == TrayStatus.LOGGED_IN:
            self.cancel()
            return
        if not result.retryable:
            self._stop(result)
            return

        if result.failure_reason == "device_mismatch":
            self._device_mismatch_count += 1
            if self._device_mismatch_count >= self._device_mismatch_max_attempts:
                self._stop(result)
                return

        if self._attempt_count >= self._max_attempts:
            self._stop(result)
            return

        self._controller.mark_startup_retrying(result)
        self._schedule(self._retry_interval_ms)

    def _stop(self, result: TrayActionResult) -> None:
        self.cancel()
        self._controller.mark_startup_stopped(result)


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
        main_window_factory: Optional[MainWindowFactory] = None,
    ):
        super().__init__()
        self._app = app
        self._threads = []
        self._workers = []
        self._action_running = False
        self._main_window_factory = main_window_factory or create_main_window
        self._main_window: Optional[QWidget] = None
        self._controller = controller or TrayController(
            exit_func=app.quit,
            on_status_changed=self.status_changed.emit,
        )
        self._startup_retry = StartupAutoLoginRetryCoordinator(
            controller=self._controller,
            start_attempt=self._start_startup_attempt,
            schedule_once=QTimer.singleShot,
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

    def show_main_window(self) -> QWidget:
        if self._main_window is None:
            self._main_window = self._main_window_factory()
        self._main_window.show()
        self._main_window.raise_()
        self._main_window.activateWindow()
        return self._main_window

    @property
    def controller(self) -> TrayController:
        return self._controller

    def start_action(self, action: Callable[[], TrayActionResult]) -> bool:
        return self._start_manual_action(action)

    def start_startup_auto_login(self) -> None:
        self._startup_retry.start()

    def _build_menu(self) -> None:
        title_action = self._menu.addAction(APP_NAME)
        title_action.setEnabled(False)
        self._menu.addSeparator()

        self._status_action = self._menu.addAction(self._controller.status_menu_text)
        self._status_action.setEnabled(False)
        self._menu.addSeparator()

        open_window_action = self._menu.addAction("打开主界面")
        open_window_action.triggered.connect(self.show_main_window)
        self._menu.addSeparator()

        test_login_action = self._menu.addAction("测试登录")
        logout_action = self._menu.addAction("登出校园网")
        relogin_action = self._menu.addAction("重新登录")
        self._busy_actions = [test_login_action, logout_action, relogin_action]

        test_login_action.triggered.connect(
            lambda: self._start_manual_action(self._controller.test_login)
        )
        logout_action.triggered.connect(
            lambda: self._start_manual_action(self._controller.logout)
        )
        relogin_action.triggered.connect(
            lambda: self._start_manual_action(self._controller.relogin)
        )

        self._menu.addSeparator()
        exit_action = self._menu.addAction("退出")
        exit_action.triggered.connect(self._controller.request_exit)

    def _start_manual_action(self, action: Callable[[], TrayActionResult]) -> bool:
        self._startup_retry.cancel()
        return self._start_action(action)

    def _start_startup_attempt(
        self,
        attempt_count: int,
        on_finished: ActionFinishedCallback,
    ) -> bool:
        return self._start_action(
            lambda: self._controller.startup_auto_login(retry_count=attempt_count),
            on_finished=on_finished,
        )

    def _start_action(
        self,
        action: Callable[[], TrayActionResult],
        *,
        on_finished: Optional[ActionFinishedCallback] = None,
    ) -> bool:
        if self._action_running:
            return False
        self._action_running = True
        self._set_busy_actions_enabled(False)
        thread = QThread(self)
        worker = _ActionWorker(action)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.finished.connect(
            lambda result, callback=on_finished: self._on_action_finished(result, callback)
        )
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
        return True

    def _on_action_finished(
        self,
        result: TrayActionResult,
        on_finished: Optional[ActionFinishedCallback] = None,
    ) -> None:
        self._action_running = False
        self._refresh_status(self._controller.status)
        self._set_busy_actions_enabled(True)
        if on_finished:
            on_finished(result)

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
    main_window_factory: Optional[MainWindowFactory] = None,
) -> int:
    clean_argv = _qt_argv(argv)
    app = QApplication.instance()
    if app is None:
        app = QApplication([APP_NAME, *clean_argv])
    app.setQuitOnLastWindowClosed(False)

    runtime = TrayRuntime(
        app,
        controller=controller,
        main_window_factory=main_window_factory,
    )
    runtime.show()
    if should_show_main_window(argv):
        runtime.show_main_window()
    schedule_startup_auto_login_if_requested(
        argv,
        start_startup_auto_login=runtime.start_startup_auto_login,
    )
    app._whut_tray_runtime = runtime
    return int(app.exec())


def should_show_main_window(argv: Optional[Sequence[str]]) -> bool:
    return STARTUP_TRAY_ARG not in set(argv or [])


def schedule_startup_auto_login_if_requested(
    argv: Optional[Sequence[str]],
    *,
    start_startup_auto_login: Callable[[], None],
) -> None:
    if STARTUP_TRAY_ARG in set(argv or []):
        start_startup_auto_login()


def _qt_argv(argv: Optional[Sequence[str]]) -> list[str]:
    return [item for item in list(argv or []) if item != STARTUP_TRAY_ARG]


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
