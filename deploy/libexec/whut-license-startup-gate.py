#!/usr/bin/python3
"""Read-only, root-owned deployment gate installed outside the repository."""

from __future__ import annotations

import ast
import errno
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Iterable


DEPLOY_ROOT = Path("/opt/whut-campus-auto-login")
APP_DIR = DEPLOY_ROOT
VENV_ROOT = DEPLOY_ROOT / ".venv"
VENV_PYTHON = VENV_ROOT / "bin/python"
APP_VERSION_FILE = DEPLOY_ROOT / "app_version.py"
ENVIRONMENT_FILE = Path("/etc/whut-campus-auto-login/license-server.env")
PUBLIC_KEY_FILE = Path("/etc/whut-campus-auto-login/license-public-key.b64")
UNIT_FILE = Path("/etc/systemd/system/whut-license-server.service")
WRAPPER_FILE = Path("/usr/local/sbin/whut-license-runtime-attestation-audit")
INSTALLED_GATE = Path("/usr/local/libexec/whut-license-startup-gate")
SYSTEM_PYTHON = Path("/usr/bin/python3")
GIT = Path("/usr/bin/git")
SERVICE_USER = "whutlogin"
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_PYTHON_ENV = {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONUSERBASE"}
_EXEC_START_PRE = (
    "ExecStartPre=+/usr/bin/python3 -I "
    "/usr/local/libexec/whut-license-startup-gate"
)
_EXEC_START = (
    "ExecStart=/opt/whut-campus-auto-login/.venv/bin/python -I -m uvicorn "
    "--app-dir /opt/whut-campus-auto-login license_server.app:app "
    "--host 127.0.0.1 --port 8787 --workers 1"
)


class GateError(Exception):
    pass


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        if argv:
            raise GateError("arguments_not_allowed")
        if not sys.platform.startswith("linux"):
            raise GateError("linux_required")
        if os.geteuid() != 0:
            raise GateError("root_required")
        checked = list(validate_gate_context())
        checked.extend(validate_deployment())
        expected_commit = read_expected_commit(ENVIRONMENT_FILE)
        read_app_version(APP_VERSION_FILE)
        validate_unit_contract(UNIT_FILE)
        validate_git_state(expected_commit)
        validate_service_cannot_write(checked)
    except GateError as exc:
        print(f"error={exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("error=gate_failed", file=sys.stderr)
        return 1
    print("result=PASS")
    return 0


def validate_gate_context() -> tuple[Path, ...]:
    if Path(__file__).resolve(strict=True) != INSTALLED_GATE:
        raise GateError("gate_path_invalid")
    checked: list[Path] = []
    for path, kind in (
        (INSTALLED_GATE, "executable"),
        (SYSTEM_PYTHON, "executable"),
        (GIT, "executable"),
        (ENVIRONMENT_FILE, "file"),
        (PUBLIC_KEY_FILE, "file"),
        (UNIT_FILE, "file"),
        (WRAPPER_FILE, "executable"),
    ):
        if kind == "executable":
            checked.extend(validate_executable_chain(path))
        else:
            checked.extend(validate_ancestor_chain(path.parent))
            checked.append(validate_path(path, kind=kind))
    validate_no_posix_acls(checked)
    return tuple(dict.fromkeys(checked))


def validate_deployment() -> tuple[Path, ...]:
    try:
        realpath = DEPLOY_ROOT.resolve(strict=True)
    except OSError as exc:
        raise GateError("app_dir_invalid") from exc
    if APP_DIR != DEPLOY_ROOT or DEPLOY_ROOT.is_symlink() or realpath != DEPLOY_ROOT:
        raise GateError("app_dir_invalid")
    checked = list(validate_ancestor_chain(DEPLOY_ROOT))
    checked.extend(walk_trusted_tree(DEPLOY_ROOT))
    checked.extend(validate_venv_python_chain())
    validate_no_posix_acls(checked)
    return tuple(dict.fromkeys(checked))


def validate_ancestor_chain(path: Path) -> tuple[Path, ...]:
    if not path.is_absolute():
        raise GateError("path_invalid")
    chain = []
    current = Path(path.anchor)
    chain.append(validate_path(current, kind="directory"))
    for part in path.parts[1:]:
        current = current / part
        chain.append(validate_path(current, kind="directory"))
    return tuple(chain)


def validate_path(path: Path, *, kind: str) -> Path:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise GateError("path_missing") from exc
    expected = {
        "directory": stat.S_ISDIR,
        "file": stat.S_ISREG,
        "executable": stat.S_ISREG,
    }.get(kind)
    if expected is None:
        raise GateError("path_kind_invalid")
    if (
        not expected(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or (kind == "executable" and not metadata.st_mode & 0o100)
    ):
        raise GateError("path_insecure")
    return Path(path)


def walk_trusted_tree(root: Path) -> tuple[Path, ...]:
    checked = []
    pending = [root]
    while pending:
        path = pending.pop()
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            if _is_venv_python_alias(path):
                checked.extend(validate_venv_python_alias(path))
                continue
            raise GateError("symlink_insecure")
        kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
        checked.append(validate_path(path, kind=kind))
        if kind == "directory":
            try:
                with os.scandir(path) as entries:
                    pending.extend(Path(entry.path) for entry in entries)
            except OSError as exc:
                raise GateError("tree_unreadable") from exc
    return tuple(checked)


def _is_venv_python_alias(path: Path) -> bool:
    return path.parent == VENV_ROOT / "bin" and path.name.startswith("python")


def validate_venv_python_alias(path: Path) -> tuple[Path, ...]:
    metadata = os.lstat(path)
    if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0:
        raise GateError("venv_python_insecure")
    return validate_executable_chain(path)


def validate_venv_python_chain() -> tuple[Path, ...]:
    return validate_executable_chain(VENV_PYTHON)


def validate_executable_chain(path: Path) -> tuple[Path, ...]:
    try:
        metadata = os.lstat(path)
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GateError("executable_chain_invalid") from exc
    if metadata.st_uid != 0 or (
        stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o022
    ):
        raise GateError("executable_chain_insecure")
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
        raise GateError("executable_chain_insecure")
    checked = list(validate_ancestor_chain(path.parent))
    if stat.S_ISREG(metadata.st_mode):
        checked.append(validate_path(path, kind="executable"))
    else:
        checked.append(path)
    checked.extend(validate_ancestor_chain(resolved.parent))
    checked.append(validate_path(resolved, kind="executable"))
    return tuple(dict.fromkeys(checked))


def validate_no_posix_acls(paths: Iterable[Path]) -> None:
    for path in dict.fromkeys(paths):
        try:
            metadata = os.lstat(path)
        except OSError as exc:
            raise GateError("acl_check_failed") from exc
        if stat.S_ISLNK(metadata.st_mode):
            continue
        try:
            value = os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
        except AttributeError as exc:
            raise GateError("acl_check_unavailable") from exc
        except OSError as exc:
            if exc.errno in {errno.ENODATA, errno.ENOATTR if hasattr(errno, "ENOATTR") else errno.ENODATA}:
                continue
            raise GateError("acl_check_failed") from exc
        if value:
            raise GateError("acl_present")


def validate_acl_text(value: str) -> None:
    for line in value.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 3 or "w" not in fields[-1]:
            continue
        if fields[0] != "user" or fields[1]:
            raise GateError("acl_write_grant")


def read_app_version(path: Path) -> str:
    source = read_small_text(path)
    try:
        module = ast.parse(source, filename=str(path), mode="exec")
    except SyntaxError as exc:
        raise GateError("app_version_invalid") from exc
    values = [
        statement.value.value
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "APP_VERSION"
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    ]
    if len(values) != 1 or _VERSION.fullmatch(values[0]) is None:
        raise GateError("app_version_invalid")
    return values[0]


def read_expected_commit(path: Path) -> str:
    values: dict[str, str] = {}
    for raw_line in read_small_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise GateError("environment_invalid")
        key, value = line.split("=", 1)
        if not key.isidentifier() or key in values:
            raise GateError("environment_invalid")
        if key in _PYTHON_ENV:
            raise GateError("python_environment_forbidden")
        values[key] = value
    commit = values.get("LICENSE_RUNTIME_SOURCE_COMMIT", "")
    if _COMMIT.fullmatch(commit) is None:
        raise GateError("source_commit_invalid")
    return commit


def read_small_text(path: Path) -> str:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
            raise GateError("file_invalid")
        return os.read(descriptor, 65537).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateError("file_invalid") from exc
    finally:
        os.close(descriptor)


def validate_unit_contract(path: Path) -> None:
    lines = read_small_text(path).splitlines()
    if (
        [line for line in lines if line.startswith("ExecStartPre=")]
        != [_EXEC_START_PRE]
        or [line for line in lines if line.startswith("ExecStart=")]
        != [_EXEC_START]
    ):
        raise GateError("unit_contract_invalid")
    if lines.count("EnvironmentFile=/etc/whut-campus-auto-login/license-server.env") != 1:
        raise GateError("unit_contract_invalid")
    if [line for line in lines if line.startswith("Environment=")] != [
        "Environment=WEB_CONCURRENCY=1"
    ]:
        raise GateError("unit_contract_invalid")


def git_output(*arguments: str) -> str:
    result = subprocess.run(
        [
            str(GIT),
            "--no-optional-locks",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(DEPLOY_ROOT),
            *arguments,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "HOME": "/nonexistent",
            "XDG_CONFIG_HOME": "/nonexistent",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    return result.stdout.strip()


def validate_git_state(expected_commit: str) -> None:
    if git_output("rev-parse", "HEAD") != expected_commit:
        raise GateError("source_commit_mismatch")
    if git_output("status", "--porcelain", "--untracked-files=all"):
        raise GateError("source_tree_dirty")


def validate_service_cannot_write(paths: Iterable[Path]) -> None:
    import pwd

    account = pwd.getpwnam(SERVICE_USER)
    checked = tuple(dict.fromkeys(paths))
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_fd)
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            writable = any(os.access(path, os.W_OK, effective_ids=True) for path in checked)
            os.write(write_fd, b"1" if writable else b"0")
        except BaseException:
            os.write(write_fd, b"E")
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    try:
        result = os.read(read_fd, 1)
    finally:
        os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    if status != 0 or result != b"0":
        raise GateError("service_write_boundary_failed")


if __name__ == "__main__":
    raise SystemExit(main())
