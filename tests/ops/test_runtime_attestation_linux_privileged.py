from __future__ import annotations

import asyncio
import base64
import importlib.util
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from license_server.signer import LicenseSigningIdentity


pytestmark = pytest.mark.linux_privileged_evidence

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_ROOT = Path("/opt/whut-campus-auto-login")
REAL_DEPLOY_ROOT = Path("/opt/whut-campus-auto-login.real")
ENV_DIR = Path("/etc/whut-campus-auto-login")
ENV_FILE = ENV_DIR / "license-server.env"
PUBLIC_KEY_FILE = ENV_DIR / "license-public-key.b64"
UNIT_FILE = Path("/etc/systemd/system/whut-license-server.service")
GATE_FILE = Path("/usr/local/libexec/whut-license-startup-gate")
WRAPPER_FILE = Path("/usr/local/sbin/whut-license-runtime-attestation-audit")
SYSTEM_PYTHON = Path("/usr/bin/python3")
SYSTEM_GIT = Path("/usr/bin/git")
RUNUSER = Path("/usr/sbin/runuser")
USERADD = Path("/usr/sbin/useradd")
SERVICE_USER = "whutlogin"
PRIVATE_KEY_B64 = base64.b64encode(bytes(range(32))).decode("ascii")
CHALLENGE = base64.urlsafe_b64encode(b"c" * 32).decode("ascii").rstrip("=")


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, **kwargs)


@pytest.fixture(scope="module", autouse=True)
def privileged_linux_environment():
    if os.environ.get("WHUT_RUN_PRIVILEGED_LINUX_EVIDENCE") != "1":
        pytest.skip("set WHUT_RUN_PRIVILEGED_LINUX_EVIDENCE=1 to opt in")
    if not sys.platform.startswith("linux"):
        pytest.fail("privileged Linux evidence requires Linux")
    if os.geteuid() != 0:
        pytest.fail("privileged Linux evidence requires root")
    required = (
        SYSTEM_PYTHON,
        SYSTEM_GIT,
        RUNUSER,
        USERADD,
        Path("/usr/bin/getfacl"),
        Path("/usr/bin/setfacl"),
        Path("/usr/bin/systemd-analyze"),
    )
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        pytest.fail(f"missing privileged evidence tools: {missing}")
    import pwd

    try:
        pwd.getpwnam(SERVICE_USER)
    except KeyError:
        _run(
            [
                str(USERADD),
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                SERVICE_USER,
            ]
        )


def _clean_fixture() -> None:
    if DEPLOY_ROOT.is_symlink():
        DEPLOY_ROOT.unlink()
    elif DEPLOY_ROOT.exists():
        shutil.rmtree(DEPLOY_ROOT)
    if REAL_DEPLOY_ROOT.exists():
        shutil.rmtree(REAL_DEPLOY_ROOT)
    for path in (ENV_DIR,):
        if path.exists():
            shutil.rmtree(path)
    for path in (UNIT_FILE, GATE_FILE, WRAPPER_FILE):
        if path.exists() or path.is_symlink():
            path.unlink()


@pytest.fixture(scope="module")
def trusted_deployment(privileged_linux_environment):
    protected = (DEPLOY_ROOT, ENV_DIR, UNIT_FILE, GATE_FILE, WRAPPER_FILE)
    existing = [str(path) for path in protected if path.exists() or path.is_symlink()]
    if existing:
        pytest.fail(f"refusing to replace existing fixed paths: {existing}")
    try:
        _run(
            [
                str(SYSTEM_GIT),
                "-c",
                f"safe.directory={REPO_ROOT}",
                "clone",
                "--no-hardlinks",
                str(REPO_ROOT),
                str(DEPLOY_ROOT),
            ],
            capture_output=True,
            text=True,
        )
        commit = _run(
            [str(SYSTEM_GIT), "-C", str(DEPLOY_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        _run([str(SYSTEM_PYTHON), "-m", "venv", str(DEPLOY_ROOT / ".venv")])
        lib64 = DEPLOY_ROOT / ".venv/lib64"
        if lib64.is_symlink() and os.readlink(lib64) == "lib":
            lib64.unlink()

        ENV_DIR.mkdir(mode=0o700, parents=True)
        GATE_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        WRAPPER_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        UNIT_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copy2(
            DEPLOY_ROOT / "deploy/libexec/whut-license-startup-gate.py",
            GATE_FILE,
        )
        shutil.copy2(
            DEPLOY_ROOT / "deploy/bin/whut-license-runtime-attestation-audit",
            WRAPPER_FILE,
        )
        shutil.copy2(
            DEPLOY_ROOT / "deploy/systemd/whut-license-server.service.example",
            UNIT_FILE,
        )
        ENV_FILE.write_text(
            f"LICENSE_RUNTIME_SOURCE_COMMIT={commit}\n",
            encoding="utf-8",
        )
        PUBLIC_KEY_FILE.write_text(
            base64.b64encode(bytes(range(32))).decode("ascii") + "\n",
            encoding="ascii",
        )
        os.chmod(ENV_DIR, 0o700)
        os.chmod(ENV_FILE, 0o600)
        os.chmod(PUBLIC_KEY_FILE, 0o644)
        os.chmod(UNIT_FILE, 0o644)
        os.chmod(GATE_FILE, 0o755)
        os.chmod(WRAPPER_FILE, 0o755)
        _run(["/usr/bin/chown", "-R", "root:root", str(DEPLOY_ROOT), str(ENV_DIR)])
        _run(
            [
                "/usr/bin/chown",
                "root:root",
                str(UNIT_FILE),
                str(GATE_FILE),
                str(WRAPPER_FILE),
            ]
        )
        _run(["/usr/bin/setfacl", "-Rb", str(DEPLOY_ROOT), str(ENV_DIR)])
        yield commit
    finally:
        _clean_fixture()


def _gate_result() -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(SYSTEM_PYTHON), "-I", str(GATE_FILE)],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )


def _assert_gate_fails() -> None:
    result = _gate_result()
    assert result.returncode != 0
    assert "result=PASS" not in result.stdout


@contextmanager
def _changed_mode(path: Path, mode: int):
    original = stat.S_IMODE(os.lstat(path).st_mode)
    os.chmod(path, mode)
    try:
        yield
    finally:
        os.chmod(path, original)


@contextmanager
def _changed_bytes(path: Path, value: bytes):
    original = path.read_bytes()
    original_mode = stat.S_IMODE(os.lstat(path).st_mode)
    path.write_bytes(value)
    os.chown(path, 0, 0)
    os.chmod(path, original_mode)
    try:
        yield
    finally:
        path.write_bytes(original)
        os.chown(path, 0, 0)
        os.chmod(path, original_mode)


def _load_installed_gate():
    spec = importlib.util.spec_from_file_location("installed_runtime_gate", GATE_FILE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_secure_deployment_gate_and_systemd_unit_pass(trusted_deployment):
    gate = _gate_result()
    assert gate.returncode == 0, gate.stderr
    assert gate.stdout == "result=PASS\n"

    verified = _run(
        ["/usr/bin/systemd-analyze", "verify", str(UNIT_FILE)],
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0


@pytest.mark.parametrize(
    ("relative_path", "mode"),
    (
        (Path("/opt"), 0o777),
        (DEPLOY_ROOT / "app_version.py", 0o666),
        (DEPLOY_ROOT / ".git/config", 0o666),
    ),
)
def test_gate_rejects_writable_parent_source_and_git_metadata(
    trusted_deployment,
    relative_path,
    mode,
):
    with _changed_mode(relative_path, mode):
        _assert_gate_fails()


def test_gate_rejects_real_acl_and_effective_uid_write(
    trusted_deployment,
):
    source = DEPLOY_ROOT / "app_version.py"
    _run(["/usr/bin/setfacl", "-m", f"u:{SERVICE_USER}:rw-", str(source)])
    try:
        _assert_gate_fails()
        gate = _load_installed_gate()
        with pytest.raises(gate.GateError, match="service_write_boundary_failed"):
            gate.validate_service_cannot_write([source])
    finally:
        _run(["/usr/bin/setfacl", "-b", str(source)])
        os.chmod(source, 0o644)


def test_gate_rejects_deployment_symlink(trusted_deployment):
    DEPLOY_ROOT.rename(REAL_DEPLOY_ROOT)
    DEPLOY_ROOT.symlink_to(REAL_DEPLOY_ROOT, target_is_directory=True)
    try:
        _assert_gate_fails()
    finally:
        DEPLOY_ROOT.unlink()
        REAL_DEPLOY_ROOT.rename(DEPLOY_ROOT)


def test_gate_rejects_insecure_venv_interpreter_chain(trusted_deployment):
    python_link = DEPLOY_ROOT / ".venv/bin/python"
    original_target = os.readlink(python_link)
    unsafe = Path("/tmp/whut-unsafe-python")
    unsafe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chown(unsafe, 0, 0)
    os.chmod(unsafe, 0o777)
    python_link.unlink()
    python_link.symlink_to(unsafe)
    try:
        _assert_gate_fails()
    finally:
        python_link.unlink()
        python_link.symlink_to(original_target)
        unsafe.unlink()


def test_gate_rejects_commit_mismatch_dirty_tree_and_tampered_unit(
    trusted_deployment,
):
    with _changed_bytes(
        ENV_FILE,
        b"LICENSE_RUNTIME_SOURCE_COMMIT=" + (b"0" * 40) + b"\n",
    ):
        _assert_gate_fails()

    untracked = DEPLOY_ROOT / "untracked-evidence"
    untracked.write_text("dirty\n", encoding="utf-8")
    try:
        _assert_gate_fails()
    finally:
        untracked.unlink()

    with _changed_bytes(
        UNIT_FILE,
        UNIT_FILE.read_bytes() + b"\nExecStart=/bin/false\n",
    ):
        _assert_gate_fails()


def test_gate_disables_git_fsmonitor_and_never_executes_source(
    trusted_deployment,
    tmp_path,
):
    marker = tmp_path / "executed"
    probe = tmp_path / "probe.sh"
    probe.write_text(
        f"#!/bin/sh\nprintf executed > {marker}\n",
        encoding="utf-8",
    )
    os.chmod(probe, 0o755)
    _run(
        [
            str(SYSTEM_GIT),
            "-C",
            str(DEPLOY_ROOT),
            "config",
            "core.fsmonitor",
            str(probe),
        ]
    )
    try:
        gate = _gate_result()
        assert gate.returncode == 0, gate.stderr
        assert not marker.exists()
    finally:
        _run(
            [
                str(SYSTEM_GIT),
                "-C",
                str(DEPLOY_ROOT),
                "config",
                "--unset",
                "core.fsmonitor",
            ]
        )

    malicious = (
        b"from pathlib import Path\n"
        + f"Path({str(marker)!r}).write_text('executed')\n".encode()
        + b"APP_VERSION = '0.1.0'\n"
    )
    with _changed_bytes(DEPLOY_ROOT / "app_version.py", malicious):
        _assert_gate_fails()
        assert not marker.exists()


def test_wrapper_rejects_arguments_and_environment_injection(
    trusted_deployment,
    tmp_path,
):
    rejected = subprocess.run(
        [str(WRAPPER_FILE), "unexpected"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert "arguments_not_allowed" in rejected.stderr

    marker = tmp_path / "sitecustomize-executed"
    injected = tmp_path / "injected"
    injected.mkdir()
    (injected / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [str(WRAPPER_FILE)],
        check=False,
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(injected),
            "PYTHONSTARTUP": str(injected / "sitecustomize.py"),
        },
    )
    assert result.returncode != 0
    assert not marker.exists()


def _request_frame(runtime, challenge: str) -> bytes:
    request = runtime.canonical_json_bytes(
        {"challenge_b64url": challenge, "protocol": runtime.PROTOCOL}
    )
    return runtime.encode_frame(request, maximum=runtime.MAX_REQUEST_BYTES)


def _exchange(runtime, socket_path: Path, frame: bytes):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(runtime.IO_TIMEOUT_SECONDS)
        client.connect(str(socket_path))
        peer = runtime.peer_credentials(client)
        client.sendall(frame)
        client.shutdown(socket.SHUT_WR)
        header = client.recv(4)
        if not header:
            return peer, b""
        length = struct.unpack(">I", header)[0]
        body = bytearray()
        while len(body) < length:
            chunk = client.recv(length - len(body))
            if not chunk:
                break
            body.extend(chunk)
        return peer, bytes(body)


async def _exchange_as_service_user(socket_path: Path, frame: bytes) -> bytes:
    encoded = base64.b64encode(frame).decode("ascii")
    code = (
        "import base64,socket,sys;"
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
        "s.connect(sys.argv[1]);"
        "s.sendall(base64.b64decode(sys.argv[2]));"
        "s.shutdown(socket.SHUT_WR);"
        "data=s.recv(4096);"
        "sys.stdout.write(base64.b64encode(data).decode())"
    )
    process = await asyncio.create_subprocess_exec(
        str(RUNUSER),
        "-u",
        SERVICE_USER,
        "--",
        str(SYSTEM_PYTHON),
        "-I",
        "-c",
        code,
        str(socket_path),
        encoded,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
    return base64.b64decode(stdout)


def test_real_unix_peer_credentials_root_nonroot_and_replay(
    privileged_linux_environment,
    tmp_path,
):
    import license_server.runtime_attestation as runtime

    async def scenario():
        socket_dir = tmp_path / "socket-dir"
        socket_dir.mkdir(mode=0o755)
        os.chmod(socket_dir, 0o755)
        socket_path = socket_dir / "attestation.sock"
        server = runtime.RuntimeAttestationServer(
            signing_identity=LicenseSigningIdentity(PRIVATE_KEY_B64),
            source_commit="a" * 40,
            socket_path=socket_path,
            expected_peer_uid=0,
            enforce_production_path=False,
        )
        await server.start()
        frame = _request_frame(runtime, CHALLENGE)
        try:
            peer, body = await asyncio.to_thread(
                _exchange, runtime, socket_path, frame
            )
            assert peer[0] == os.getpid()
            assert peer[1] == 0
            response = runtime.parse_response(body)
            assert response["challenge_b64url"] == CHALLENGE
            assert response["signature_b64url"]

            _peer, replay = await asyncio.to_thread(
                _exchange, runtime, socket_path, frame
            )
            assert replay == b""

            os.chmod(socket_path, 0o666)
            denied = await _exchange_as_service_user(socket_path, frame)
            assert denied == b""
        finally:
            await server.close()
        assert not socket_path.exists()

    asyncio.run(scenario())


def test_socket_cleanup_requires_matching_inode(
    privileged_linux_environment,
    tmp_path,
):
    import license_server.runtime_attestation as runtime

    async def scenario():
        socket_path = tmp_path / "attestation.sock"
        owned_path = tmp_path / "attestation.owned"
        server = runtime.RuntimeAttestationServer(
            signing_identity=LicenseSigningIdentity(PRIVATE_KEY_B64),
            source_commit="a" * 40,
            socket_path=socket_path,
            expected_peer_uid=0,
            enforce_production_path=False,
        )
        await server.start()
        socket_path.rename(owned_path)
        attacker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        attacker.bind(str(socket_path))
        attacker_inode = os.lstat(socket_path).st_ino
        try:
            await server.close()
            assert socket_path.exists()
            assert os.lstat(socket_path).st_ino == attacker_inode
        finally:
            attacker.close()
            socket_path.unlink(missing_ok=True)
            owned_path.unlink(missing_ok=True)

    asyncio.run(scenario())


@pytest.mark.parametrize("existing_kind", ("file", "symlink"))
def test_socket_start_rejects_unknown_existing_path(
    privileged_linux_environment,
    tmp_path,
    existing_kind,
):
    import license_server.runtime_attestation as runtime

    async def scenario():
        socket_path = tmp_path / "attestation.sock"
        target = tmp_path / "target"
        target.write_text("keep\n", encoding="utf-8")
        if existing_kind == "file":
            socket_path.write_text("keep\n", encoding="utf-8")
        else:
            socket_path.symlink_to(target)
        server = runtime.RuntimeAttestationServer(
            signing_identity=LicenseSigningIdentity(PRIVATE_KEY_B64),
            source_commit="a" * 40,
            socket_path=socket_path,
            expected_peer_uid=0,
            enforce_production_path=False,
        )
        with pytest.raises(
            runtime.RuntimeAttestationError,
            match="socket_path_exists",
        ):
            await server.start()
        assert socket_path.exists() or socket_path.is_symlink()

    asyncio.run(scenario())
