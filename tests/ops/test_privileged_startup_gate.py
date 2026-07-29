import errno
import importlib.util
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


GATE_PATH = Path("deploy/libexec/whut-license-startup-gate.py")


def _gate():
    spec = importlib.util.spec_from_file_location("privileged_gate", GATE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_gate_source_exists_and_has_no_deployment_imports():
    gate = _gate()

    assert gate.INSTALLED_GATE == Path(
        "/usr/local/libexec/whut-license-startup-gate"
    )
    assert gate.SYSTEM_PYTHON == Path("/usr/bin/python3")


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux absolute POSIX path semantics",
)
def test_root_controlled_chain_rejects_writable_parent(monkeypatch):
    gate = _gate()
    secure = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
    insecure = SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0)

    monkeypatch.setattr(
        gate.os,
        "lstat",
        lambda path: insecure if str(path) == "/opt" else secure,
    )
    with pytest.raises(gate.GateError, match="path_insecure"):
        gate.validate_ancestor_chain(Path("/opt/whut-campus-auto-login"))

def test_root_controlled_path_rejects_symlink(monkeypatch):
    gate = _gate()
    monkeypatch.setattr(
        gate.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
    )
    with pytest.raises(gate.GateError, match="path_insecure"):
        gate.validate_path(Path("/fixed"), kind="file")


@pytest.mark.parametrize(
    "target_mode",
    (
        stat.S_IFDIR | 0o755,
        stat.S_IFREG | 0o775,
        stat.S_IFREG | 0o757,
    ),
)
def test_resolved_interpreter_target_must_be_regular_and_not_writable(
    monkeypatch,
    target_mode,
):
    gate = _gate()
    monkeypatch.setattr(
        gate.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=target_mode, st_uid=0),
    )

    with pytest.raises(gate.GateError, match="path_insecure"):
        gate.validate_path(Path("/usr/bin/python3.12"), kind="executable")


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_walk_rejects_symlink_outside_allowed_venv_alias_location(
    tmp_path,
    monkeypatch,
):
    gate = _gate()
    target = tmp_path / "target"
    target.write_text("safe\n", encoding="utf-8")
    unexpected = tmp_path / "unexpected-link"
    unexpected.symlink_to(target.name)

    monkeypatch.setattr(
        gate,
        "validate_path",
        lambda path, *, kind: Path(path),
    )

    with pytest.raises(gate.GateError, match="symlink_insecure"):
        gate.walk_trusted_tree(tmp_path)


def test_acl_write_grant_is_rejected():
    gate = _gate()

    with pytest.raises(gate.GateError, match="acl_write_grant"):
        gate.validate_acl_text("user:1001:rw-\n")


def test_acl_check_skips_symlink_entry_without_querying_link_xattr(monkeypatch):
    gate = _gate()
    link = Path("/opt/whut-campus-auto-login/.venv/bin/python")
    queried = []

    monkeypatch.setattr(
        gate.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
    )

    def unsupported_link_xattr(path, attribute, *, follow_symlinks):
        queried.append((path, attribute, follow_symlinks))
        raise OSError(errno.ENOTSUP, "link ACL xattr unsupported")

    monkeypatch.setattr(
        gate.os,
        "getxattr",
        unsupported_link_xattr,
        raising=False,
    )

    gate.validate_no_posix_acls([link])

    assert queried == []


@pytest.mark.parametrize("error_number", (errno.ENOTSUP, errno.EACCES, errno.EIO))
def test_acl_check_fails_closed_for_regular_file_errors(monkeypatch, error_number):
    gate = _gate()
    target = Path("/usr/bin/python3.12")

    monkeypatch.setattr(
        gate.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0),
    )

    def failing_xattr(_path, _attribute, *, follow_symlinks):
        assert follow_symlinks is False
        raise OSError(error_number, "ACL query failed")

    monkeypatch.setattr(
        gate.os,
        "getxattr",
        failing_xattr,
        raising=False,
    )

    with pytest.raises(gate.GateError, match="acl_check_failed"):
        gate.validate_no_posix_acls([target])


def test_acl_check_rejects_acl_on_regular_target(monkeypatch):
    gate = _gate()
    target = Path("/usr/bin/python3.12")

    monkeypatch.setattr(
        gate.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0),
    )
    monkeypatch.setattr(
        gate.os,
        "getxattr",
        lambda *_args, **_kwargs: b"non-empty-posix-acl",
        raising=False,
    )

    with pytest.raises(gate.GateError, match="acl_present"):
        gate.validate_no_posix_acls([target])


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_walk_keeps_validated_venv_alias_target_chain(tmp_path, monkeypatch):
    gate = _gate()
    target = tmp_path / "python-target"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    alias = tmp_path / "python"
    alias.symlink_to(target.name)
    external_target = Path("/usr/bin/python3.12")

    monkeypatch.setattr(
        gate,
        "validate_path",
        lambda path, *, kind: Path(path),
    )
    monkeypatch.setattr(
        gate,
        "_is_venv_python_alias",
        lambda path: path == alias,
    )
    monkeypatch.setattr(
        gate,
        "validate_venv_python_alias",
        lambda path: (path, external_target),
    )

    checked = gate.walk_trusted_tree(tmp_path)

    assert alias in checked
    assert external_target in checked


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_walk_accepts_valid_venv_lib64_alias(tmp_path, monkeypatch):
    gate = _gate()
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    lib64 = tmp_path / "lib64"
    lib64.symlink_to("lib")

    real_lstat = gate.os.lstat

    class RootOwnedStat:
        def __init__(self, original):
            self._original = original
            self.st_uid = 0

        def __getattr__(self, name):
            return getattr(self._original, name)

    def fake_lstat(path):
        result = real_lstat(path)
        if Path(path) == lib64:
            return RootOwnedStat(result)
        return result

    monkeypatch.setattr(gate.os, "lstat", fake_lstat)
    monkeypatch.setattr(gate, "VENV_ROOT", tmp_path)
    monkeypatch.setattr(
        gate,
        "validate_path",
        lambda path, *, kind: Path(path),
    )
    monkeypatch.setattr(
        gate,
        "validate_ancestor_chain",
        lambda path: (path,),
    )

    checked = gate.walk_trusted_tree(tmp_path)

    assert lib64 in checked
    assert lib_dir in checked


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_lib64_alias_rejects_non_root_owner(tmp_path, monkeypatch):
    gate = _gate()
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    lib64 = tmp_path / "lib64"
    lib64.symlink_to("lib")

    real_lstat = gate.os.lstat

    class NonRootStat:
        def __init__(self, original):
            self._original = original
            self.st_uid = 1000

        def __getattr__(self, name):
            return getattr(self._original, name)

    def fake_lstat(path):
        result = real_lstat(path)
        if Path(path) == lib64:
            return NonRootStat(result)
        return result

    monkeypatch.setattr(gate.os, "lstat", fake_lstat)
    monkeypatch.setattr(gate, "VENV_ROOT", tmp_path)

    with pytest.raises(gate.GateError, match="venv_lib64_insecure"):
        gate.validate_venv_lib64_alias(lib64)



@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_lib64_alias_rejects_absolute_target(tmp_path, monkeypatch):
    gate = _gate()
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    lib64 = tmp_path / "lib64"
    lib64.symlink_to(str(lib_dir))

    monkeypatch.setattr(gate, "VENV_ROOT", tmp_path)

    with pytest.raises(gate.GateError, match="venv_lib64_insecure"):
        gate.validate_venv_lib64_alias(lib64)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_lib64_alias_rejects_parent_traversal(tmp_path, monkeypatch):
    gate = _gate()
    inner = tmp_path / "inner"
    inner.mkdir()
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    fake_venv = inner
    lib64 = inner / "lib64"
    lib64.symlink_to("../lib")

    monkeypatch.setattr(gate, "VENV_ROOT", fake_venv)

    with pytest.raises(gate.GateError, match="venv_lib64_insecure"):
        gate.validate_venv_lib64_alias(lib64)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_lib64_alias_rejects_wrong_target_name(tmp_path, monkeypatch):
    gate = _gate()
    other = tmp_path / "other"
    other.mkdir()
    lib64 = tmp_path / "lib64"
    lib64.symlink_to("other")

    monkeypatch.setattr(gate, "VENV_ROOT", tmp_path)

    with pytest.raises(gate.GateError, match="venv_lib64_insecure"):
        gate.validate_venv_lib64_alias(lib64)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
@pytest.mark.parametrize("link_kind", ("dangling", "loop"))
def test_lib64_alias_rejects_unresolvable(tmp_path, monkeypatch, link_kind):
    gate = _gate()
    lib64 = tmp_path / "lib64"
    if link_kind == "dangling":
        lib64.symlink_to("lib")
    else:
        lib64.symlink_to("lib64")

    monkeypatch.setattr(gate, "VENV_ROOT", tmp_path)

    with pytest.raises(gate.GateError, match="venv_lib64_insecure"):
        gate.validate_venv_lib64_alias(lib64)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_lib64_alias_rejected_outside_venv(tmp_path, monkeypatch):
    gate = _gate()
    lib_dir = tmp_path / "lib"
    lib_dir.mkdir()
    lib64 = tmp_path / "lib64"
    lib64.symlink_to("lib")

    monkeypatch.setattr(gate, "VENV_ROOT", tmp_path / "other-venv")

    monkeypatch.setattr(
        gate,
        "validate_path",
        lambda path, *, kind: Path(path),
    )

    with pytest.raises(gate.GateError, match="symlink_insecure"):
        gate.walk_trusted_tree(tmp_path)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
def test_lib64_alias_rejects_target_that_is_file(tmp_path, monkeypatch):
    gate = _gate()
    lib_file = tmp_path / "lib"
    lib_file.write_text("not a directory\n", encoding="utf-8")
    lib64 = tmp_path / "lib64"
    lib64.symlink_to("lib")

    monkeypatch.setattr(gate, "VENV_ROOT", tmp_path)

    with pytest.raises(gate.GateError, match="venv_lib64_insecure"):
        gate.validate_venv_lib64_alias(lib64)


def test_lib64_alias_rejects_group_writable_target(monkeypatch):
    gate = _gate()
    lib64 = Path("/opt/whut-campus-auto-login/.venv/lib64")

    def fake_lstat(path):
        path = Path(path)
        if path == lib64:
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0)

    monkeypatch.setattr(gate.os, "lstat", fake_lstat)
    monkeypatch.setattr(gate.os, "readlink", lambda _p: "lib")
    monkeypatch.setattr(
        gate.Path,
        "resolve",
        lambda self, *, strict=False: gate.VENV_ROOT / "lib",
    )
    monkeypatch.setattr(
        gate,
        "validate_ancestor_chain",
        lambda path: (path,),
    )

    with pytest.raises(gate.GateError, match="path_insecure"):
        gate.validate_venv_lib64_alias(lib64)


def test_lib64_alias_rejects_other_writable_target(monkeypatch):
    gate = _gate()
    lib64 = Path("/opt/whut-campus-auto-login/.venv/lib64")

    def fake_lstat(path):
        path = Path(path)
        if path == lib64:
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o757, st_uid=0)

    monkeypatch.setattr(gate.os, "lstat", fake_lstat)
    monkeypatch.setattr(gate.os, "readlink", lambda _p: "lib")
    monkeypatch.setattr(
        gate.Path,
        "resolve",
        lambda self, *, strict=False: gate.VENV_ROOT / "lib",
    )
    monkeypatch.setattr(
        gate,
        "validate_ancestor_chain",
        lambda path: (path,),
    )

    with pytest.raises(gate.GateError, match="path_insecure"):
        gate.validate_venv_lib64_alias(lib64)


def test_other_symlink_still_rejected_with_lib64_support(monkeypatch):
    gate = _gate()

    monkeypatch.setattr(
        gate.os,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
    )

    with pytest.raises(gate.GateError, match="path_insecure"):
        gate.validate_path(Path("/some/other/link"), kind="file")

@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux symbolic links",
)
@pytest.mark.parametrize("link_kind", ("dangling", "loop"))
def test_executable_chain_rejects_unresolvable_symlink(
    tmp_path,
    link_kind,
):
    gate = _gate()
    alias = tmp_path / "python"
    if link_kind == "dangling":
        alias.symlink_to("missing-python")
    else:
        alias.symlink_to(alias.name)

    with pytest.raises(gate.GateError, match="executable_chain_invalid"):
        gate.validate_executable_chain(alias)


def test_safe_app_version_uses_ast_without_importing_module(tmp_path):
    gate = _gate()
    version_file = tmp_path / "app_version.py"
    version_file.write_text(
        "raise RuntimeError('must not execute')\nAPP_VERSION = '1.2.3'\n",
        encoding="utf-8",
    )

    assert gate.read_app_version(version_file) == "1.2.3"


def test_git_command_is_read_only_sanitized_and_disables_hooks(monkeypatch):
    gate = _gate()
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout="a" * 40 + "\n")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    assert gate.git_output("rev-parse", "HEAD") == "a" * 40
    command, kwargs = calls[0]
    assert Path(command[0]).as_posix() == "/usr/bin/git"
    assert "--no-optional-locks" in command
    assert "core.hooksPath=/dev/null" in command
    assert "core.fsmonitor=false" in command
    assert kwargs["shell"] is False
    assert kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"


def test_unit_contract_rejects_duplicate_execstart_bypass(tmp_path):
    gate = _gate()
    unit = tmp_path / "whut-license-server.service"
    unit.write_text(
        "\n".join(
            (
                "EnvironmentFile=/etc/whut-campus-auto-login/license-server.env",
                gate._EXEC_START_PRE,
                gate._EXEC_START,
                "ExecStart=/bin/sh -c unsafe",
            )
        ),
        encoding="utf-8",
    )

    with pytest.raises(gate.GateError, match="unit_contract_invalid"):
        gate.validate_unit_contract(unit)


def test_gate_reports_stable_error_for_unexpected_io(monkeypatch, capsys):
    gate = _gate()
    monkeypatch.setattr(gate.sys, "platform", "linux")
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(gate, "validate_gate_context", lambda: (_ for _ in ()).throw(OSError("/secret/path")))

    assert gate.main([]) == 1
    captured = capsys.readouterr()
    assert captured.err == "error=gate_failed\n"


def test_unsafe_deployment_stops_before_version_or_git(monkeypatch):
    gate = _gate()
    calls = []
    monkeypatch.setattr(gate.sys, "platform", "linux")
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(gate, "validate_gate_context", lambda: ())
    monkeypatch.setattr(
        gate,
        "validate_deployment",
        lambda: (_ for _ in ()).throw(gate.GateError("path_insecure")),
    )
    monkeypatch.setattr(gate, "read_expected_commit", lambda _path: calls.append("env"))
    monkeypatch.setattr(gate, "validate_git_state", lambda _commit: calls.append("git"))

    assert gate.main([]) == 1
    assert calls == []


def test_trusted_gate_runs_checks_in_fixed_order(monkeypatch, capsys):
    gate = _gate()
    calls = []
    monkeypatch.setattr(gate.sys, "platform", "linux")
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(gate, "validate_gate_context", lambda: (Path("/gate"),))
    monkeypatch.setattr(gate, "validate_deployment", lambda: (Path("/deploy"),))
    monkeypatch.setattr(
        gate, "read_expected_commit", lambda _path: calls.append("env") or "a" * 40
    )
    monkeypatch.setattr(gate, "read_app_version", lambda _path: calls.append("version") or "1.2.3")
    monkeypatch.setattr(gate, "validate_unit_contract", lambda _path: calls.append("unit"))
    monkeypatch.setattr(gate, "validate_git_state", lambda _commit: calls.append("git"))
    monkeypatch.setattr(
        gate, "validate_service_cannot_write", lambda paths: calls.append(tuple(paths))
    )

    assert gate.main([]) == 0
    assert calls == ["env", "version", "unit", "git", (Path("/gate"), Path("/deploy"))]
    assert capsys.readouterr().out == "result=PASS\n"
