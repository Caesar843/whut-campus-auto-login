from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import socket
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app_version import APP_VERSION  # noqa: E402
from license_server.runtime_attestation import (  # noqa: E402
    IO_TIMEOUT_SECONDS,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROOF_LIFETIME_SECONDS,
    PROTOCOL,
    RuntimeAttestationError,
    SOCKET_PATH,
    canonical_json_bytes,
    decode_frame_header,
    encode_frame,
    parse_response,
    peer_credentials,
    process_started_at,
    read_process_start_ticks,
    require_supported_production_platform,
)
from license_server.signer import RUNTIME_ATTESTATION_SIGNING_DOMAIN  # noqa: E402


DEPLOY_ROOT = Path("/opt/whut-campus-auto-login")
PUBLIC_KEY_FILE = Path(
    "/etc/whut-campus-auto-login/license-public-key.b64"
)
SERVICE_NAME = "whut-license-server.service"
SERVICE_USER = "whutlogin"
SYSTEMCTL = Path("/usr/bin/systemctl")
GIT = Path("/usr/bin/git")
SOURCE_COMMIT_ENV = "LICENSE_RUNTIME_SOURCE_COMMIT"
_COMMIT_LENGTH = 40


class AuditError(Exception):
    pass


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def verify_attestation_response(
    body: bytes,
    *,
    challenge_b64url: str,
    expected_public_key: Ed25519PublicKey,
    expected_pid: int,
    expected_uid: int,
    expected_start_ticks: str,
    expected_source_commit: str,
    expected_app_version: str,
    now: datetime,
) -> dict[str, Any]:
    try:
        response = parse_response(body)
        signature = _decode_b64url(
            response["signature_b64url"],
            expected_length=64,
        )
        payload = {
            key: value
            for key, value in response.items()
            if key != "signature_b64url"
        }
        expected_public_key.verify(
            signature,
            RUNTIME_ATTESTATION_SIGNING_DOMAIN
            + canonical_json_bytes(payload),
        )
        issued_at = _parse_utc(response["issued_at"])
        expires_at = _parse_utc(response["expires_at"])
        _parse_utc(response["process_started_at"])
        _decode_b64url(response["instance_id"], expected_length=16)
    except (
        InvalidSignature,
        RuntimeAttestationError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        raise AuditError("proof_invalid") from exc

    expected = {
        "protocol": PROTOCOL,
        "challenge_b64url": challenge_b64url,
        "pid": expected_pid,
        "service_uid": expected_uid,
        "process_start_ticks": expected_start_ticks,
        "source_commit": expected_source_commit,
        "app_version": expected_app_version,
        "public_key_sha256": public_key_fingerprint(expected_public_key),
    }
    if any(response.get(key) != value for key, value in expected.items()):
        raise AuditError("proof_identity_mismatch")
    if (
        type(response["pid"]) is not int
        or type(response["service_uid"]) is not int
        or not isinstance(response["process_start_ticks"], str)
        or not response["process_start_ticks"].isascii()
        or not response["process_start_ticks"].isdigit()
    ):
        raise AuditError("proof_identity_invalid")
    if (
        expires_at - issued_at
        != timedelta(seconds=PROOF_LIFETIME_SECONDS)
        or issued_at > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
        or now > expires_at
    ):
        raise AuditError("proof_time_invalid")
    return payload


def _parse_utc(value: Any) -> datetime:
    if (
        not isinstance(value, str)
        or len(value) != 20
        or not value.endswith("Z")
    ):
        raise ValueError("timestamp_invalid")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return parsed.replace(tzinfo=timezone.utc)


def _decode_b64url(value: Any, *, expected_length: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        )
    ):
        raise ValueError("base64url_invalid")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("base64url_invalid") from exc
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if len(raw) != expected_length or canonical != value:
        raise ValueError("base64url_invalid")
    return raw


def _read_public_key() -> Ed25519PublicKey:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(PUBLIC_KEY_FILE, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_size > 1024
        ):
            raise AuditError("public_key_file_insecure")
        encoded = os.read(descriptor, 1025).decode("ascii").strip()
    finally:
        os.close(descriptor)
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) != 32:
        raise AuditError("public_key_invalid")
    return Ed25519PublicKey.from_public_bytes(raw)


def _service_uid() -> int:
    import pwd

    return pwd.getpwnam(SERVICE_USER).pw_uid


def _main_pid() -> int:
    result = subprocess.run(
        [
            str(SYSTEMCTL),
            "show",
            "--property=MainPID",
            "--value",
            SERVICE_NAME,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=IO_TIMEOUT_SECONDS,
    )
    value = result.stdout.strip()
    if not value.isascii() or not value.isdigit() or int(value) <= 0:
        raise AuditError("service_pid_invalid")
    return int(value)


def _git_output(*arguments: str) -> str:
    result = subprocess.run(
        [str(GIT), "-C", str(DEPLOY_ROOT), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=IO_TIMEOUT_SECONDS,
    )
    return result.stdout.strip()


def _repository_state() -> str:
    commit = _git_output("rev-parse", "HEAD")
    if not _valid_commit(commit):
        raise AuditError("source_commit_invalid")
    if _git_output("status", "--porcelain", "--untracked-files=all"):
        raise AuditError("source_tree_dirty")
    return commit


def _valid_commit(value: str) -> bool:
    return (
        len(value) == _COMMIT_LENGTH
        and value.isascii()
        and all(character in "0123456789abcdef" for character in value)
    )


def _receive_frame(connected: socket.socket) -> bytes:
    header = _recv_exact(connected, 4)
    length = decode_frame_header(header, maximum=MAX_RESPONSE_BYTES)
    body = _recv_exact(connected, length)
    if connected.recv(1):
        raise AuditError("extra_response_bytes")
    return body


def _recv_exact(connected: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connected.recv(length - len(chunks))
        if not chunk:
            raise AuditError("response_truncated")
        chunks.extend(chunk)
    return bytes(chunks)


def live_audit() -> dict[str, Any]:
    require_supported_production_platform()
    if os.geteuid() != 0:
        raise AuditError("root_required")
    public_key = _read_public_key()
    expected_uid = _service_uid()
    expected_pid = _main_pid()
    _validate_socket_path(expected_uid)
    source_commit = _repository_state()
    expected_start_ticks = read_process_start_ticks(expected_pid)
    expected_started_at = process_started_at(expected_start_ticks)
    if Path(f"/proc/{expected_pid}/cwd").resolve(strict=True) != DEPLOY_ROOT:
        raise AuditError("process_cwd_mismatch")

    challenge = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    request = canonical_json_bytes(
        {"challenge_b64url": challenge, "protocol": PROTOCOL}
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connected:
        connected.settimeout(IO_TIMEOUT_SECONDS)
        connected.connect(str(SOCKET_PATH))
        peer_pid, peer_uid, _peer_gid = peer_credentials(connected)
        if peer_pid != expected_pid or peer_uid != expected_uid:
            raise AuditError("socket_peer_mismatch")
        connected.sendall(encode_frame(request, maximum=MAX_REQUEST_BYTES))
        connected.shutdown(socket.SHUT_WR)
        body = _receive_frame(connected)

    payload = verify_attestation_response(
        body,
        challenge_b64url=challenge,
        expected_public_key=public_key,
        expected_pid=expected_pid,
        expected_uid=expected_uid,
        expected_start_ticks=expected_start_ticks,
        expected_source_commit=source_commit,
        expected_app_version=APP_VERSION,
        now=datetime.now(timezone.utc),
    )
    if payload["process_started_at"] != expected_started_at:
        raise AuditError("process_start_time_mismatch")
    return payload


def _validate_socket_path(expected_uid: int) -> None:
    metadata = os.lstat(SOCKET_PATH)
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise AuditError("socket_path_insecure")


def startup_gate() -> None:
    require_supported_production_platform()
    if os.geteuid() != 0:
        raise AuditError("root_required")
    expected_commit = os.environ.get(SOURCE_COMMIT_ENV, "")
    if not _valid_commit(expected_commit):
        raise AuditError("source_commit_invalid")
    if _repository_state() != expected_commit:
        raise AuditError("source_commit_mismatch")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--startup-gate", action="store_true")
    modes.add_argument("--live-audit", action="store_true")
    return parser


def _print_success(payload: dict[str, Any]) -> None:
    print("runtime_attestation=pass")
    print("socket_peer_identity=pass")
    print("process_identity=pass")
    print("source_tree=pass")
    print("signature=pass")
    print(f"process_started_at={payload['process_started_at']}")
    print(f"app_version={payload['app_version']}")
    print(f"source_commit={payload['source_commit']}")
    print(f"public_key_sha256={payload['public_key_sha256']}")
    print("result=PASS")


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.startup_gate:
            startup_gate()
            print("result=PASS")
        else:
            _print_success(live_audit())
        return 0
    except (
        AuditError,
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        code = str(exc) if isinstance(exc, (AuditError, RuntimeError)) else "audit_failed"
        print(f"error={code}", file=sys.stderr)
        print("result=FAIL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
