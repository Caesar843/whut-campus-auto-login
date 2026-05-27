import base64
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from desktop_app.autostart import windows_startup


class FakeShortcutBackend:
    def __init__(self):
        self.saved = {}
        self.read_failures = set()

    def create(self, shortcut_path, spec):
        shortcut_path.parent.mkdir(parents=True, exist_ok=True)
        shortcut_path.write_text("shortcut", encoding="utf-8")
        self.saved[shortcut_path] = spec

    def read(self, shortcut_path):
        if shortcut_path in self.read_failures:
            raise windows_startup.AutostartError("unreadable shortcut")
        return self.saved[shortcut_path]


def _win_env(tmp_path):
    appdata = tmp_path / "AppData" / "Roaming"
    return {"APPDATA": str(appdata)}


def test_startup_folder_uses_current_user_appdata(tmp_path):
    folder = windows_startup.get_startup_folder(
        env=_win_env(tmp_path),
        platform="win32",
    )

    assert folder == (
        tmp_path
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )


def test_enable_autostart_creates_shortcut_in_startup_folder(tmp_path):
    backend = FakeShortcutBackend()
    env = _win_env(tmp_path)

    enabled = windows_startup.enable_autostart(
        env=env,
        platform="win32",
        create_shortcut=backend.create,
        read_shortcut=backend.read,
    )

    shortcut_path = windows_startup.get_shortcut_path(env=env, platform="win32")
    assert enabled is True
    assert shortcut_path.exists()
    assert shortcut_path.name == "whut-campus-auto-login.lnk"
    saved = backend.saved[shortcut_path]
    assert saved.arguments.endswith('desktop_app\\tray_app.py" --startup-tray')
    assert saved.working_directory == windows_startup.PROJECT_ROOT


def test_repeated_enable_updates_single_shortcut_file(tmp_path):
    backend = FakeShortcutBackend()
    env = _win_env(tmp_path)

    assert windows_startup.enable_autostart(
        env=env,
        platform="win32",
        create_shortcut=backend.create,
        read_shortcut=backend.read,
    )
    assert windows_startup.enable_autostart(
        env=env,
        platform="win32",
        create_shortcut=backend.create,
        read_shortcut=backend.read,
    )

    startup_folder = windows_startup.get_startup_folder(env=env, platform="win32")
    assert list(startup_folder.glob("*.lnk")) == [
        startup_folder / "whut-campus-auto-login.lnk"
    ]


def test_development_shortcut_prefers_path_pythonw_over_current_interpreter(monkeypatch):
    pythonw_path = Path("C:/Users/lenovo/AppData/Local/Programs/Python/Python313/pythonw.exe")

    def fake_which(command):
        if command == "pythonw":
            return str(pythonw_path)
        return None

    monkeypatch.setattr(windows_startup.sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        windows_startup.sys,
        "executable",
        "C:/Users/CodexSandboxOffline/AppData/Local/Programs/Python/Python313/python.exe",
    )
    monkeypatch.setattr(windows_startup.shutil, "which", fake_which)

    spec = windows_startup.build_shortcut_spec()

    assert spec.target == pythonw_path
    assert spec.arguments.endswith('desktop_app\\tray_app.py" --startup-tray')


def test_disable_autostart_removes_shortcut_and_is_idempotent(tmp_path):
    backend = FakeShortcutBackend()
    env = _win_env(tmp_path)

    windows_startup.enable_autostart(
        env=env,
        platform="win32",
        create_shortcut=backend.create,
        read_shortcut=backend.read,
    )
    shortcut_path = windows_startup.get_shortcut_path(env=env, platform="win32")

    assert windows_startup.disable_autostart(env=env, platform="win32") is True
    assert not shortcut_path.exists()
    assert windows_startup.disable_autostart(env=env, platform="win32") is True


def test_is_autostart_enabled_validates_shortcut_target(tmp_path):
    backend = FakeShortcutBackend()
    env = _win_env(tmp_path)

    windows_startup.enable_autostart(
        env=env,
        platform="win32",
        create_shortcut=backend.create,
        read_shortcut=backend.read,
    )

    assert (
        windows_startup.is_autostart_enabled(
            env=env,
            platform="win32",
            read_shortcut=backend.read,
        )
        is True
    )

    shortcut_path = windows_startup.get_shortcut_path(env=env, platform="win32")
    backend.saved[shortcut_path] = windows_startup.ShortcutSpec(
        target=Path("C:/Other/python.exe"),
        arguments="other.py",
        working_directory=Path("C:/Other"),
    )

    assert (
        windows_startup.is_autostart_enabled(
            env=env,
            platform="win32",
            read_shortcut=backend.read,
        )
        is False
    )


def test_is_autostart_enabled_falls_back_to_existing_file_if_shortcut_unreadable(tmp_path):
    backend = FakeShortcutBackend()
    env = _win_env(tmp_path)

    windows_startup.enable_autostart(
        env=env,
        platform="win32",
        create_shortcut=backend.create,
        read_shortcut=backend.read,
    )
    shortcut_path = windows_startup.get_shortcut_path(env=env, platform="win32")
    backend.read_failures.add(shortcut_path)

    assert (
        windows_startup.is_autostart_enabled(
            env=env,
            platform="win32",
            read_shortcut=backend.read,
        )
        is True
    )


@pytest.mark.parametrize(
    "operation",
    [
        windows_startup.enable_autostart,
        windows_startup.disable_autostart,
        windows_startup.is_autostart_enabled,
    ],
)
def test_non_windows_platform_returns_false_without_crashing(tmp_path, operation):
    assert operation(env={}, platform="linux") is False


def test_powershell_runner_uses_binary_capture_and_decodes_locale_output(monkeypatch):
    def fake_run(command, **kwargs):
        assert kwargs["capture_output"] is True
        assert kwargs["check"] is False
        assert kwargs.get("text") is not True
        assert "encoding" not in kwargs
        return SimpleNamespace(
            returncode=0,
            stdout="完成".encode("gbk"),
            stderr=b"",
        )

    monkeypatch.setattr(windows_startup.subprocess, "run", fake_run)

    assert windows_startup._run_powershell("Write-Output ok") == "完成"


def test_powershell_runner_raises_autostart_error_when_stderr_is_missing(monkeypatch):
    def fake_run(command, **kwargs):
        return SimpleNamespace(returncode=1, stdout=b"", stderr=None)

    monkeypatch.setattr(windows_startup.subprocess, "run", fake_run)

    with pytest.raises(windows_startup.AutostartError, match="PowerShell command failed"):
        windows_startup._run_powershell("bad script")


def test_powershell_runner_embeds_path_arguments_in_encoded_command(monkeypatch):
    raw_path = r"C:\Path With Spaces\whut's-login.lnk"

    def fake_run(command, **kwargs):
        assert "-EncodedCommand" in command
        assert raw_path not in command
        encoded = command[command.index("-EncodedCommand") + 1]
        decoded = base64.b64decode(encoded).decode("utf-16le")
        assert "$__arg0 = 'C:\\Path With Spaces\\whut''s-login.lnk'" in decoded
        assert "Write-Output $__arg0" in decoded
        return SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(windows_startup.subprocess, "run", fake_run)

    assert windows_startup._run_powershell("Write-Output $args[0]", raw_path) == "ok"
