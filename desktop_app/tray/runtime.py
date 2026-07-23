from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import sys
import time
from typing import Callable, Optional, Sequence

from PySide6.QtCore import QAbstractNativeEventFilter, QObject, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QStyle, QSystemTrayIcon, QWidget

from desktop_app.log_window import RuntimeLogWindow
from desktop_app.main_window import create_main_window
from desktop_app.resources import resource_path
from desktop_app.runtime_logs import (
    RuntimeLogStore,
    get_default_log_store,
    safe_exception_message,
)
from desktop_app.tray.controller import (
    TrayActionResult,
    TrayController,
    TrayStatus,
)


APP_NAME = "武汉理工校园网助手"
APP_ICON_RESOURCE = "assets/windows/whut_campus_auto_login.ico"
LOGGER = logging.getLogger(__name__)
STARTUP_TRAY_ARG = "--startup-tray"
STARTUP_INITIAL_DELAY_MS = 5_000
STARTUP_RETRY_INTERVAL_MS = 12_000
STARTUP_MAX_ATTEMPTS = 12
STARTUP_DEVICE_MISMATCH_MAX_ATTEMPTS = 3
WM_POWERBROADCAST = 0x0218
PBT_APMRESUMEAUTOMATIC = 18
PBT_APMRESUMESUSPEND = 7
RESUME_NETWORK_RESTORE_DELAY_MS = 10_000
RESUME_EVENT_DEBOUNCE_SECONDS = 10.0
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


class ResumeAutoLoginScheduler:
    def __init__(
        self,
        *,
        start_startup_auto_login: Callable[[], None],
        schedule_once: ScheduleOnce,
        clock: Callable[[], float] = time.monotonic,
        delay_ms: int = RESUME_NETWORK_RESTORE_DELAY_MS,
        debounce_seconds: float = RESUME_EVENT_DEBOUNCE_SECONDS,
    ):
        self._start_startup_auto_login = start_startup_auto_login
        self._schedule_once = schedule_once
        self._clock = clock
        self._delay_ms = delay_ms
        self._debounce_seconds = debounce_seconds
        self._last_resume_event_at: Optional[float] = None
        self._generation = 0

    def handle_resume_event(self) -> bool:
        now = self._clock()
        if (
            self._last_resume_event_at is not None
            and now - self._last_resume_event_at < self._debounce_seconds
        ):
            return False
        self._last_resume_event_at = now
        generation = self._generation
        self._schedule_once(
            self._delay_ms,
            lambda: self._start_if_current(generation),
        )
        return True

    def cancel(self) -> None:
        self._generation += 1

    def _start_if_current(self, generation: int) -> None:
        if generation == self._generation:
            self._start_startup_auto_login()


class WindowsPowerResumeEventFilter(QAbstractNativeEventFilter):
    def __init__(self, on_resume: Callable[[], None]):
        super().__init__()
        self._on_resume = on_resume

    def nativeEventFilter(self, _event_type, message):
        try:
            win_message = ctypes.wintypes.MSG.from_address(int(message))
        except (TypeError, ValueError):
            return False, 0

        if is_windows_resume_power_message(win_message.message, win_message.wParam):
            self._on_resume()
        return False, 0


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
                message=safe_exception_message(exc),
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
        log_store: Optional[RuntimeLogStore] = None,
    ):
        super().__init__()
        self._app = app
        self._threads = []
        self._workers = []
        self._action_running = False
        self._log_store = log_store or get_default_log_store()
        self._log_store.cleanup()
        self._log_store.write(
            event="app_start",
            action="tray_start",
            status="started",
            safe_message="Application started.",
        )
        self._main_window_factory = main_window_factory or create_main_window
        self._main_window: Optional[QWidget] = None
        self._log_window: Optional[RuntimeLogWindow] = None
        self._controller = controller or TrayController(
            exit_func=app.quit,
            on_status_changed=self.status_changed.emit,
            log_store=self._log_store,
        )
        self._startup_retry = StartupAutoLoginRetryCoordinator(
            controller=self._controller,
            start_attempt=self._start_startup_attempt,
            schedule_once=QTimer.singleShot,
        )
        self._resume_scheduler = ResumeAutoLoginScheduler(
            start_startup_auto_login=self.start_startup_auto_login,
            schedule_once=QTimer.singleShot,
        )
        self._power_event_filter = install_windows_resume_event_filter(
            app,
            on_resume=self._resume_scheduler.handle_resume_event,
        )
        self._app_icon = _load_icon(app)
        app.setWindowIcon(self._app_icon)
        self._tray = QSystemTrayIcon(self._app_icon, self)
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
            self._main_window.setWindowIcon(self._app_icon)
        self._main_window.show()
        self._main_window.raise_()
        self._main_window.activateWindow()
        return self._main_window

    def show_runtime_logs(self) -> RuntimeLogWindow:
        if self._log_window is None:
            self._log_window = RuntimeLogWindow(log_store=self._log_store)
        self._log_window.refresh_logs()
        self._log_window.show()
        self._log_window.raise_()
        self._log_window.activateWindow()
        return self._log_window

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
        runtime_logs_action = self._menu.addAction("查看运行日志")
        runtime_logs_action.triggered.connect(self.show_runtime_logs)
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
        self._resume_scheduler.cancel()
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
    log_store: Optional[RuntimeLogStore] = None,
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
        log_store=log_store,
    )
    runtime.show()
    if should_show_main_window(argv):
        runtime.show_main_window()
    schedule_startup_auto_login_if_requested(
        argv,
        start_startup_auto_login=runtime.start_startup_auto_login,
        log_store=runtime._log_store,
    )
    app._whut_tray_runtime = runtime
    return int(app.exec())


def should_show_main_window(argv: Optional[Sequence[str]]) -> bool:
    return STARTUP_TRAY_ARG not in set(argv or [])


def schedule_startup_auto_login_if_requested(
    argv: Optional[Sequence[str]],
    *,
    start_startup_auto_login: Callable[[], None],
    log_store: Optional[RuntimeLogStore] = None,
) -> None:
    if STARTUP_TRAY_ARG in set(argv or []):
        if log_store is not None:
            log_store.write(
                event="startup_auto_login_scheduled",
                action="startup_auto_login",
                status="scheduled",
                safe_message="Startup auto login scheduled.",
            )
        start_startup_auto_login()


def is_windows_resume_power_message(message: int, w_param: int) -> bool:
    return message == WM_POWERBROADCAST and w_param in {
        PBT_APMRESUMEAUTOMATIC,
        PBT_APMRESUMESUSPEND,
    }


def install_windows_resume_event_filter(
    app: QApplication,
    *,
    on_resume: Callable[[], None],
    platform: str = sys.platform,
) -> Optional[WindowsPowerResumeEventFilter]:
    if platform != "win32":
        return None
    event_filter = WindowsPowerResumeEventFilter(on_resume)
    app.installNativeEventFilter(event_filter)
    return event_filter


def _qt_argv(argv: Optional[Sequence[str]]) -> list[str]:
    return [item for item in list(argv or []) if item != STARTUP_TRAY_ARG]


def _load_icon(app: QApplication) -> QIcon:
    try:
        icon = QIcon(str(resource_path(APP_ICON_RESOURCE)))
        if not icon.isNull():
            return icon
        LOGGER.warning("Official application icon could not be loaded.")
    except FileNotFoundError:
        LOGGER.warning("Official application icon resource is missing.")
    return app.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)


if __name__ == "__main__":
    raise SystemExit(run_tray_app(sys.argv[1:]))
