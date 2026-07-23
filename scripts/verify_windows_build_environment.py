import json
import platform
import re
import sys
from importlib import metadata
from pathlib import Path
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "packaging" / "windows" / "build_baseline.json"
BOOTSTRAP_PACKAGES = {"pip", "setuptools", "wheel"}
BASELINE_KEYS = {
    "python_version",
    "pyinstaller_version",
    "packaging_mode",
    "lock_file",
}
LOCK_LINE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s]+)\Z")


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock_file(text: str) -> dict[str, str]:
    locked: dict[str, str] = {}
    lines = text.splitlines()
    if not lines:
        raise ValueError("lock file is empty")
    for line_number, line in enumerate(lines, 1):
        match = LOCK_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid lock line {line_number}")
        name, version = match.groups()
        if any(marker in version for marker in ("://", "/", "\\")):
            raise ValueError(f"invalid lock line {line_number}")
        normalized_name = normalize_package_name(name)
        if normalized_name in locked:
            raise ValueError(f"duplicate package in lock file: {normalized_name}")
        locked[normalized_name] = version
    return locked


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != BASELINE_KEYS:
        raise ValueError("build baseline has unexpected fields")
    if not all(isinstance(payload[key], str) and payload[key] for key in BASELINE_KEYS):
        raise ValueError("build baseline values must be non-empty strings")
    if payload["packaging_mode"] != "onedir":
        raise ValueError("build baseline packaging mode must be onedir")
    lock_file = payload["lock_file"]
    if Path(lock_file).name != lock_file:
        raise ValueError("build baseline lock file must be a file name")
    return payload


def installed_distributions() -> dict[str, str]:
    installed = {}
    for distribution in metadata.distributions():
        name = distribution.metadata.get("Name")
        if name:
            installed[normalize_package_name(name)] = distribution.version
    return installed


def environment_errors(
    baseline: Mapping[str, str],
    locked: Mapping[str, str],
    installed: Mapping[str, str],
    *,
    python_version: str,
    in_virtualenv: bool,
) -> list[str]:
    normalized_locked = {
        normalize_package_name(name): version for name, version in locked.items()
    }
    normalized_installed = {
        normalize_package_name(name): version for name, version in installed.items()
    }
    errors = []
    if python_version != baseline["python_version"]:
        errors.append(
            f"Python {python_version} does not match baseline {baseline['python_version']}."
        )
    if not in_virtualenv:
        errors.append("Python is not running in a virtual environment.")
    expected_pyinstaller = baseline["pyinstaller_version"]
    if normalized_locked.get("pyinstaller") != expected_pyinstaller:
        errors.append(
            "baseline pyinstaller "
            f"{expected_pyinstaller} does not match lock pyinstaller "
            f"{normalized_locked.get('pyinstaller', 'missing')}."
        )
    for name in sorted(normalized_locked):
        expected = normalized_locked[name]
        actual = normalized_installed.get(name)
        if actual is None:
            errors.append(f"missing package {name}=={expected}.")
        elif actual != expected:
            errors.append(f"package {name} is {actual}, expected {expected}.")
    for name in sorted(normalized_installed.keys() - normalized_locked.keys()):
        if name not in BOOTSTRAP_PACKAGES:
            errors.append(f"unlocked package {name}=={normalized_installed[name]}.")
    return errors


def main() -> int:
    try:
        baseline = load_baseline()
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        print("Build environment validation failed: build baseline is missing or invalid.")
        return 1
    try:
        lock_path = ROOT / baseline["lock_file"]
        locked = parse_lock_file(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("Build environment validation failed: build lock is missing or invalid.")
        return 1
    errors = environment_errors(
        baseline,
        locked,
        installed_distributions(),
        python_version=platform.python_version(),
        in_virtualenv=sys.prefix != sys.base_prefix,
    )
    if errors:
        for error in errors:
            print(f"Build environment validation failed: {error}")
        return 1
    print("Build environment matches the Windows release baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
