from pathlib import Path
import sys
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from desktop_app.tray import runtime
from desktop_app.tray.controller import TrayActionResult, TrayStatus


class FakeController:
    def __init__(self):
        self.retrying = []
        self.stopped = []

    def mark_startup_retrying(self, result):
        self.retrying.append(result)

    def mark_startup_stopped(self, result):
        self.stopped.append(result)


class FakeScheduler:
    def __init__(self):
        self.pending = []

    def __call__(self, delay_ms, callback):
        self.pending.append((delay_ms, callback))

    def run_next(self):
        _delay, callback = self.pending.pop(0)
        callback()


class FakeAttemptStarter:
    def __init__(self):
        self.attempts = []
        self.callbacks = []

    def __call__(self, attempt_count, callback):
        self.attempts.append(attempt_count)
        self.callbacks.append(callback)
        return True

    def finish(self, result):
        self.callbacks.pop(0)(result)


class RejectingAttemptStarter:
    def __init__(self):
        self.attempts = []

    def __call__(self, attempt_count, callback):
        self.attempts.append(attempt_count)
        return False


def action_result(*, status=TrayStatus.LOGIN_FAILED, retryable=False, reason=None):
    return TrayActionResult(
        action="startup_auto_login",
        status=status,
        message="safe message",
        retryable=retryable,
        failure_reason=reason,
        retry_count=1,
    )


def make_coordinator(*, max_attempts=12, device_mismatch_max_attempts=3):
    controller = FakeController()
    scheduler = FakeScheduler()
    starter = FakeAttemptStarter()
    coordinator = runtime.StartupAutoLoginRetryCoordinator(
        controller=controller,
        start_attempt=starter,
        schedule_once=scheduler,
        max_attempts=max_attempts,
        device_mismatch_max_attempts=device_mismatch_max_attempts,
    )
    return coordinator, controller, scheduler, starter


def test_startup_tray_argument_starts_retry_coordinator():
    calls = []

    runtime.schedule_startup_auto_login_if_requested(
        ["--startup-tray"],
        start_startup_auto_login=lambda: calls.append("start"),
    )

    assert calls == ["start"]


def test_plain_tray_start_does_not_start_retry_coordinator():
    calls = []

    runtime.schedule_startup_auto_login_if_requested(
        [],
        start_startup_auto_login=lambda: calls.append("start"),
    )

    assert calls == []


def test_startup_retry_waits_then_retries_after_retryable_failure():
    coordinator, controller, scheduler, starter = make_coordinator()

    coordinator.start()

    assert scheduler.pending[0][0] == runtime.STARTUP_INITIAL_DELAY_MS
    scheduler.run_next()
    assert starter.attempts == [1]

    starter.finish(action_result(retryable=True, reason="timeout"))

    assert len(controller.retrying) == 1
    assert scheduler.pending[0][0] == runtime.STARTUP_RETRY_INTERVAL_MS
    scheduler.run_next()
    assert starter.attempts == [1, 2]


def test_startup_retry_stops_after_success_or_already_online():
    for result in (
        action_result(status=TrayStatus.LOGGED_IN),
        action_result(status=TrayStatus.LOGGED_IN, reason="already_online"),
    ):
        coordinator, controller, scheduler, starter = make_coordinator()
        coordinator.start()
        scheduler.run_next()

        starter.finish(result)

        assert coordinator.active is False
        assert scheduler.pending == []
        assert controller.retrying == []
        assert controller.stopped == []


def test_startup_retry_stops_after_non_retryable_failure():
    coordinator, controller, scheduler, starter = make_coordinator()
    coordinator.start()
    scheduler.run_next()

    starter.finish(action_result(reason="expired"))

    assert coordinator.active is False
    assert scheduler.pending == []
    assert len(controller.stopped) == 1


def test_startup_retry_stops_at_max_attempts():
    coordinator, controller, scheduler, starter = make_coordinator(max_attempts=2)
    coordinator.start()
    scheduler.run_next()
    starter.finish(action_result(retryable=True, reason="timeout"))
    scheduler.run_next()

    starter.finish(action_result(retryable=True, reason="timeout"))

    assert starter.attempts == [1, 2]
    assert coordinator.active is False
    assert scheduler.pending == []
    assert len(controller.stopped) == 1


def test_device_mismatch_stops_after_limited_attempts():
    coordinator, controller, scheduler, starter = make_coordinator(
        device_mismatch_max_attempts=3
    )
    coordinator.start()

    for attempt in range(3):
        scheduler.run_next()
        starter.finish(action_result(retryable=True, reason="device_mismatch"))
        if attempt < 2:
            assert coordinator.active is True

    assert starter.attempts == [1, 2, 3]
    assert coordinator.active is False
    assert len(controller.stopped) == 1


def test_startup_retry_does_not_start_concurrent_attempts():
    coordinator, _controller, scheduler, starter = make_coordinator()
    coordinator.start()
    _delay, callback = scheduler.pending.pop(0)

    callback()
    callback()

    assert starter.attempts == [1]


def test_repeated_start_does_not_schedule_duplicate_startup_flows():
    coordinator, _controller, scheduler, _starter = make_coordinator()

    coordinator.start()
    coordinator.start()

    assert len(scheduler.pending) == 1


def test_startup_retry_stops_when_action_cannot_start_repeatedly():
    controller = FakeController()
    scheduler = FakeScheduler()
    starter = RejectingAttemptStarter()
    coordinator = runtime.StartupAutoLoginRetryCoordinator(
        controller=controller,
        start_attempt=starter,
        schedule_once=scheduler,
        max_attempts=2,
    )
    coordinator.start()

    scheduler.run_next()
    scheduler.run_next()

    assert starter.attempts == [1, 2]
    assert coordinator.active is False
    assert scheduler.pending == []
    assert len(controller.stopped) == 1


def test_cancel_ignores_pending_startup_retry():
    coordinator, _controller, scheduler, starter = make_coordinator()
    coordinator.start()

    coordinator.cancel()
    scheduler.run_next()

    assert starter.attempts == []
    assert coordinator.active is False


def test_manual_action_cancels_pending_startup_retry():
    calls = []
    fake_runtime = SimpleNamespace(
        _startup_retry=SimpleNamespace(cancel=lambda: calls.append("cancel")),
        _start_action=lambda action: calls.append(action) or True,
    )
    action = lambda: None

    started = runtime.TrayRuntime._start_manual_action(fake_runtime, action)

    assert started is True
    assert calls == ["cancel", action]


def test_plain_start_shows_main_window_but_startup_tray_does_not():
    assert runtime.should_show_main_window([]) is True
    assert runtime.should_show_main_window(["--startup-tray"]) is False
