import base64
import locale
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional


SHORTCUT_NAME = "whut-campus-auto-login.lnk"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ENTRY_SCRIPT = PROJECT_ROOT / "desktop_app" / "tray_app.py"
POWERSHELL_TIMEOUT_SECONDS = 10


class AutostartError(RuntimeError):
    """Raised when Windows startup shortcut operations fail."""


@dataclass(frozen=True)
class ShortcutSpec:
    target: Path
    arguments: str
    working_directory: Path


CreateShortcut = Callable[[Path, ShortcutSpec], None]
ReadShortcut = Callable[[Path], ShortcutSpec]


def enable_autostart(
    *,
    env: Optional[Mapping[str, str]] = None,
    platform: Optional[str] = None,
    create_shortcut: Optional[CreateShortcut] = None,
    read_shortcut: Optional[ReadShortcut] = None,
) -> bool:
    """Create or update the current user's Startup folder shortcut."""

    if not _is_windows(platform):
        return False

    shortcut_path = get_shortcut_path(env=env, platform=platform)
    spec = build_shortcut_spec()
    reader = read_shortcut or _read_shortcut_with_powershell
    creator = create_shortcut or _create_shortcut_with_powershell

    try:
        if shortcut_path.exists() and _shortcut_matches(shortcut_path, spec, reader):
            return True
        shortcut_path.parent.mkdir(parents=True, exist_ok=True)
        creator(shortcut_path, spec)
    except Exception as exc:
        raise AutostartError("Failed to enable Windows startup shortcut.") from exc
    return True


def disable_autostart(
    *,
    env: Optional[Mapping[str, str]] = None,
    platform: Optional[str] = None,
) -> bool:
    """Remove the current user's Startup folder shortcut if it exists."""

    if not _is_windows(platform):
        return False

    try:
        get_shortcut_path(env=env, platform=platform).unlink(missing_ok=True)
    except OSError as exc:
        raise AutostartError("Failed to disable Windows startup shortcut.") from exc
    return True


def is_autostart_enabled(
    *,
    env: Optional[Mapping[str, str]] = None,
    platform: Optional[str] = None,
    read_shortcut: Optional[ReadShortcut] = None,
) -> bool:
    """Return whether the current user's Startup folder has this app shortcut."""

    if not _is_windows(platform):
        return False

    shortcut_path = get_shortcut_path(env=env, platform=platform)
    if not shortcut_path.exists():
        return False

    reader = read_shortcut or _read_shortcut_with_powershell
    try:
        return _shortcut_matches(shortcut_path, build_shortcut_spec(), reader)
    except AutostartError:
        return True
    except Exception:
        return True


def get_startup_folder(
    *,
    env: Optional[Mapping[str, str]] = None,
    platform: Optional[str] = None,
) -> Path:
    if not _is_windows(platform):
        raise AutostartError("Windows Startup folder is only available on Windows.")

    source_env = os.environ if env is None else env
    appdata = source_env.get("APPDATA")
    if not appdata:
        raise AutostartError("APPDATA is not set; cannot locate Startup folder.")
    return (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )


def get_shortcut_path(
    *,
    env: Optional[Mapping[str, str]] = None,
    platform: Optional[str] = None,
) -> Path:
    return get_startup_folder(env=env, platform=platform) / SHORTCUT_NAME


def build_shortcut_spec() -> ShortcutSpec:
    executable = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False):
        return ShortcutSpec(
            target=executable,
            arguments="--startup-tray",
            working_directory=executable.parent,
        )
    executable = _development_python_executable()
    return ShortcutSpec(
        target=executable,
        arguments=f'"{SOURCE_ENTRY_SCRIPT}" --startup-tray',
        working_directory=PROJECT_ROOT,
    )


def _development_python_executable() -> Path:
    for command in ("pythonw", "python"):
        executable = shutil.which(command)
        if executable:
            return Path(executable).resolve()
    return Path(sys.executable).resolve()


def _is_windows(platform: Optional[str]) -> bool:
    return (platform or sys.platform) == "win32"


def _shortcut_matches(
    shortcut_path: Path,
    expected: ShortcutSpec,
    read_shortcut: ReadShortcut,
) -> bool:
    try:
        actual = read_shortcut(shortcut_path)
    except Exception as exc:
        raise AutostartError("Failed to read Windows startup shortcut.") from exc

    return (
        _same_path(actual.target, expected.target)
        and actual.arguments.strip() == expected.arguments.strip()
        and _same_path(actual.working_directory, expected.working_directory)
    )


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _create_shortcut_with_powershell(shortcut_path: Path, spec: ShortcutSpec) -> None:
    script = """
$shortcutPath = $args[0]
$targetPath = $args[1]
$arguments = $args[2]
$workingDirectory = $args[3]
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetPath
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = $workingDirectory
$shortcut.Save()
"""
    _run_powershell(
        script,
        str(shortcut_path),
        str(spec.target),
        spec.arguments,
        str(spec.working_directory),
    )


def _read_shortcut_with_powershell(shortcut_path: Path) -> ShortcutSpec:
    script = """
$shortcutPath = $args[0]
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Output $shortcut.TargetPath
Write-Output $shortcut.Arguments
Write-Output $shortcut.WorkingDirectory
"""
    output = _run_powershell(script, str(shortcut_path))
    lines = output.splitlines()
    if len(lines) < 3:
        raise AutostartError("Shortcut metadata is incomplete.")
    return ShortcutSpec(
        target=Path(lines[0]),
        arguments=lines[1],
        working_directory=Path(lines[2]),
    )


def _run_powershell(script: str, *args: str) -> str:
    encoded_script = base64.b64encode(
        _prepare_powershell_script(script, args).encode("utf-16le")
    ).decode("ascii")
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded_script,
            ],
            check=False,
            capture_output=True,
            timeout=POWERSHELL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise AutostartError("PowerShell command timed out.") from exc
    stdout = _decode_process_output(completed.stdout)
    stderr = _decode_process_output(completed.stderr)
    if completed.returncode != 0:
        raise AutostartError(stderr or "PowerShell command failed.")
    return stdout


def _prepare_powershell_script(script: str, args: tuple[str, ...]) -> str:
    assignments = ["$ErrorActionPreference = 'Stop'"]
    for index, value in enumerate(args):
        assignments.append(f"$__arg{index} = {_quote_powershell_string(value)}")

    prepared_script = script
    for index in reversed(range(len(args))):
        prepared_script = prepared_script.replace(f"$args[{index}]", f"$__arg{index}")
    return "\n".join([*assignments, prepared_script])


def _quote_powershell_string(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _decode_process_output(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, bytes):
        return str(value).strip()

    encodings = ("utf-8", locale.getpreferredencoding(False), "gbk")
    for encoding in encodings:
        try:
            return value.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    return value.decode("utf-8", errors="replace").strip()
