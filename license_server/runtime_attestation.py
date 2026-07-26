from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import re
import secrets
import socket
import stat
import struct
import sys
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from app_version import APP_VERSION
from license_server.signer import LicenseSigningIdentity


PROTOCOL = "whut-license-runtime-attestation-v1"
SOCKET_PATH = Path("/run/whut-license-server/runtime-attestation.sock")
MAX_REQUEST_BYTES = 256
MAX_RESPONSE_BYTES = 1024
IO_TIMEOUT_SECONDS = 2.0
PROOF_LIFETIME_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 5
REPLAY_CACHE_CAPACITY = 256
SIGNED_PAYLOAD_FIELDS = {
    "app_version",
    "challenge_b64url",
    "expires_at",
    "instance_id",
    "issued_at",
    "pid",
    "process_start_ticks",
    "process_started_at",
    "protocol",
    "public_key_sha256",
    "service_uid",
    "source_commit",
}
RESPONSE_FIELDS = SIGNED_PAYLOAD_FIELDS | {"signature_b64url"}
_REQUEST_FIELDS = {"challenge_b64url", "protocol"}
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_B64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]+\Z")


class RuntimeAttestationError(Exception):
    pass


@dataclass(frozen=True)
class RuntimeAttestationState:
    instance_id: str
    pid: int
    process_start_ticks: str
    process_started_at: str
    service_uid: int
    source_commit: str
    app_version: str
    public_key_sha256: str


class ReplayCache:
    def __init__(
        self,
        *,
        capacity: int = REPLAY_CACHE_CAPACITY,
        ttl_seconds: int = PROOF_LIFETIME_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._capacity = capacity
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, challenge_b64url: str) -> None:
        now = self._clock()
        with self._lock:
            self._entries = {
                challenge: expires_at
                for challenge, expires_at in self._entries.items()
                if expires_at > now
            }
            if challenge_b64url in self._entries:
                raise RuntimeAttestationError("challenge_replayed")
            if len(self._entries) >= self._capacity:
                raise RuntimeAttestationError("replay_cache_full")
            self._entries[challenge_b64url] = now + self._ttl_seconds


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def parse_request(body: bytes) -> str:
    payload = _parse_canonical_object(
        body,
        maximum=MAX_REQUEST_BYTES,
        expected_fields=_REQUEST_FIELDS,
    )
    if payload["protocol"] != PROTOCOL:
        raise RuntimeAttestationError("protocol_invalid")
    challenge = payload["challenge_b64url"]
    if not isinstance(challenge, str):
        raise RuntimeAttestationError("challenge_invalid")
    _decode_canonical_b64url(challenge, expected_bytes=32)
    return challenge


def parse_response(body: bytes) -> dict[str, Any]:
    return _parse_canonical_object(
        body,
        maximum=MAX_RESPONSE_BYTES,
        expected_fields=RESPONSE_FIELDS,
    )


def encode_frame(body: bytes, *, maximum: int) -> bytes:
    if not 0 < len(body) <= maximum:
        raise RuntimeAttestationError("frame_length_invalid")
    return struct.pack(">I", len(body)) + body


def decode_frame_header(header: bytes, *, maximum: int) -> int:
    if len(header) != 4:
        raise RuntimeAttestationError("frame_header_invalid")
    length = struct.unpack(">I", header)[0]
    if not 0 < length <= maximum:
        raise RuntimeAttestationError("frame_length_invalid")
    return length


def build_payload(
    state: RuntimeAttestationState,
    challenge_b64url: str,
    issued_at: datetime,
) -> dict[str, Any]:
    issued_at = issued_at.astimezone(timezone.utc).replace(microsecond=0)
    return {
        "app_version": state.app_version,
        "challenge_b64url": challenge_b64url,
        "expires_at": utc_text(
            issued_at + timedelta(seconds=PROOF_LIFETIME_SECONDS)
        ),
        "instance_id": state.instance_id,
        "issued_at": utc_text(issued_at),
        "pid": state.pid,
        "process_start_ticks": state.process_start_ticks,
        "process_started_at": state.process_started_at,
        "protocol": PROTOCOL,
        "public_key_sha256": state.public_key_sha256,
        "service_uid": state.service_uid,
        "source_commit": state.source_commit,
    }


def utc_text(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def require_supported_production_platform() -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("runtime_attestation_linux_required")
    if is_wsl():
        raise RuntimeError("runtime_attestation_wsl_not_supported")
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("runtime_attestation_peer_credentials_required")


def is_wsl() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(
            encoding="utf-8"
        )
    except OSError:
        return False
    return "microsoft" in release.casefold()


def read_process_start_ticks(pid: int | str = "self") -> str:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeAttestationError("process_stat_unavailable") from exc
    closing_parenthesis = text.rfind(")")
    if closing_parenthesis < 1:
        raise RuntimeAttestationError("process_stat_invalid")
    fields = text[closing_parenthesis + 2 :].split()
    if len(fields) <= 19 or not fields[19].isascii() or not fields[19].isdigit():
        raise RuntimeAttestationError("process_stat_invalid")
    return fields[19]


def process_started_at(start_ticks: str) -> str:
    try:
        clock_ticks = int(os.sysconf("SC_CLK_TCK"))
        boot_time = _linux_boot_time()
        started = boot_time + (int(start_ticks) / clock_ticks)
    except (OSError, TypeError, ValueError) as exc:
        raise RuntimeAttestationError("process_start_time_unavailable") from exc
    return utc_text(datetime.fromtimestamp(started, tz=timezone.utc))


def peer_credentials(connected_socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeAttestationError("peer_credentials_unavailable")
    try:
        raw = connected_socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        return struct.unpack("3i", raw)
    except (OSError, struct.error) as exc:
        raise RuntimeAttestationError("peer_credentials_unavailable") from exc


class RuntimeAttestationServer:
    def __init__(
        self,
        *,
        signing_identity: LicenseSigningIdentity,
        source_commit: str,
        socket_path: Path = SOCKET_PATH,
        expected_peer_uid: int = 0,
        enforce_production_path: bool = True,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if _COMMIT_PATTERN.fullmatch(source_commit) is None:
            raise RuntimeError("runtime_attestation_source_commit_invalid")
        if enforce_production_path and socket_path != SOCKET_PATH:
            raise RuntimeError("runtime_attestation_socket_path_invalid")
        self._identity = signing_identity
        self._source_commit = source_commit
        self._socket_path = Path(socket_path)
        self._expected_peer_uid = expected_peer_uid
        self._enforce_production_path = enforce_production_path
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._replay_cache = ReplayCache()
        self._server: asyncio.AbstractServer | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._state: RuntimeAttestationState | None = None

    @asynccontextmanager
    async def lifespan(self, _app):
        await self.start()
        try:
            yield
        finally:
            await self.close()

    async def start(self) -> None:
        if self._enforce_production_path:
            require_supported_production_platform()
        self._validate_socket_location()
        start_ticks = read_process_start_ticks()
        self._state = RuntimeAttestationState(
            instance_id=_canonical_b64url(secrets.token_bytes(16)),
            pid=os.getpid(),
            process_start_ticks=start_ticks,
            process_started_at=process_started_at(start_ticks),
            service_uid=os.getuid(),
            source_commit=self._source_commit,
            app_version=APP_VERSION,
            public_key_sha256=self._identity.public_key_sha256,
        )
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_client,
                path=str(self._socket_path),
            )
            os.chmod(self._socket_path, 0o600)
            metadata = os.lstat(self._socket_path)
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise RuntimeAttestationError("socket_security_invalid")
            self._socket_identity = (metadata.st_dev, metadata.st_ino)
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._remove_owned_socket()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            connected_socket = writer.get_extra_info("socket")
            if connected_socket is None:
                return
            _pid, uid, _gid = peer_credentials(connected_socket)
            if uid != self._expected_peer_uid:
                return
            header = await asyncio.wait_for(
                reader.readexactly(4),
                IO_TIMEOUT_SECONDS,
            )
            length = decode_frame_header(header, maximum=MAX_REQUEST_BYTES)
            body = await asyncio.wait_for(
                reader.readexactly(length),
                IO_TIMEOUT_SECONDS,
            )
            trailing = await asyncio.wait_for(
                reader.read(1),
                IO_TIMEOUT_SECONDS,
            )
            if trailing:
                raise RuntimeAttestationError("extra_request_bytes")
            challenge = parse_request(body)
            self._replay_cache.consume(challenge)
            if self._state is None:
                raise RuntimeAttestationError("server_not_ready")
            payload = build_payload(self._state, challenge, self._clock())
            canonical_payload = canonical_json_bytes(payload)
            response = canonical_json_bytes(
                {
                    **payload,
                    "signature_b64url": _canonical_b64url(
                        self._identity.sign_runtime_attestation(
                            canonical_payload
                        )
                    ),
                }
            )
            writer.write(
                encode_frame(response, maximum=MAX_RESPONSE_BYTES)
            )
            await asyncio.wait_for(writer.drain(), IO_TIMEOUT_SECONDS)
        except (
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
            RuntimeAttestationError,
            ValueError,
            OSError,
        ):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    def _validate_socket_location(self) -> None:
        parent = self._socket_path.parent
        try:
            metadata = os.lstat(parent)
        except OSError as exc:
            raise RuntimeAttestationError("socket_directory_invalid") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeAttestationError("socket_directory_invalid")
        if self._enforce_production_path and (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o750
        ):
            raise RuntimeAttestationError("socket_directory_security_invalid")
        try:
            os.lstat(self._socket_path)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise RuntimeAttestationError("socket_path_invalid") from exc
        raise RuntimeAttestationError("socket_path_exists")

    def _remove_owned_socket(self) -> None:
        if self._socket_identity is None:
            return
        try:
            metadata = os.lstat(self._socket_path)
        except FileNotFoundError:
            self._socket_identity = None
            return
        except OSError:
            return
        if (
            stat.S_ISSOCK(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and (metadata.st_dev, metadata.st_ino) == self._socket_identity
        ):
            self._socket_path.unlink()
            self._socket_identity = None


def _parse_canonical_object(
    body: bytes,
    *,
    maximum: int,
    expected_fields: set[str],
) -> dict[str, Any]:
    if not 0 < len(body) <= maximum or body.startswith(b"\xef\xbb\xbf"):
        raise RuntimeAttestationError("json_invalid")
    try:
        text = body.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_unique_object)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RuntimeAttestationError,
    ) as exc:
        raise RuntimeAttestationError("json_invalid") from exc
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise RuntimeAttestationError("json_shape_invalid")
    if canonical_json_bytes(value) != body:
        raise RuntimeAttestationError("json_not_canonical")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeAttestationError("json_duplicate_field")
        value[key] = item
    return value


def _canonical_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_canonical_b64url(
    value: str,
    *,
    expected_bytes: int,
) -> bytes:
    if (
        not value
        or "=" in value
        or _B64URL_PATTERN.fullmatch(value) is None
    ):
        raise RuntimeAttestationError("base64url_invalid")
    try:
        raw = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise RuntimeAttestationError("base64url_invalid") from exc
    if len(raw) != expected_bytes or _canonical_b64url(raw) != value:
        raise RuntimeAttestationError("base64url_invalid")
    return raw


def _linux_boot_time() -> int:
    try:
        lines = Path("/proc/stat").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeAttestationError("boot_time_unavailable") from exc
    for line in lines:
        if line.startswith("btime "):
            value = line.removeprefix("btime ")
            if value.isascii() and value.isdigit():
                return int(value)
    raise RuntimeAttestationError("boot_time_unavailable")
