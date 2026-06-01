from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from desktop_app.tray import runtime


class FakeController:
    def startup_auto_login(self):
        return "auto-login-result"


class FakeRuntime:
    def __init__(self):
        self.controller = FakeController()
        self.scheduled = []

    def start_action(self, action):
        self.scheduled.append(action)


def test_startup_tray_argument_schedules_one_startup_auto_login():
    tray_runtime = FakeRuntime()

    runtime.schedule_startup_auto_login_if_requested(
        ["--startup-tray"],
        start_action=tray_runtime.start_action,
        controller=tray_runtime.controller,
    )

    assert tray_runtime.scheduled == [tray_runtime.controller.startup_auto_login]


def test_plain_tray_start_does_not_schedule_startup_auto_login():
    tray_runtime = FakeRuntime()

    runtime.schedule_startup_auto_login_if_requested(
        [],
        start_action=tray_runtime.start_action,
        controller=tray_runtime.controller,
    )

    assert tray_runtime.scheduled == []


def test_plain_start_shows_main_window_but_startup_tray_does_not():
    assert runtime.should_show_main_window([]) is True
    assert runtime.should_show_main_window(["--startup-tray"]) is False
