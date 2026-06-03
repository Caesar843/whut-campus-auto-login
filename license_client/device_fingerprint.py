from __future__ import annotations

import hashlib
import logging
import os
import platform
import socket
import subprocess
import sys
import uuid
from typing import Callable, Optional


LOGGER = logging.getLogger(__name__)
_FINGERPRINT_SALT = "whut-campus-auto-login-device-v1"


def generate_device_fingerprint_hash(
    *,
    machine_guid_reader: Optional[Callable[[], Optional[str]]] = None,
) -> str:
    """Return a SHA-256 hash of stable local device information.

    The raw device attributes are never returned by this function.
    """

    reader = machine_guid_reader or _read_windows_machine_guid
    parts = []
    machine_guid = reader()
    if machine_guid:
        parts.append(f"machine_guid={_normalize(machine_guid)}")
    else:
        LOGGER.warning("MachineGuid unavailable; using weak device fingerprint fallback.")
        parts.extend(_fallback_parts())

    normalized = "|".join([_FINGERPRINT_SALT, *sorted(parts)])
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _read_windows_machine_guid() -> Optional[str]:
    if sys.platform != "win32":
        return None
    command = [
        "reg",
        "query",
        r"HKLM\SOFTWARE\Microsoft\Cryptography",
        "/v",
        "MachineGuid",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    for line in completed.stdout.splitlines():
        if "MachineGuid" not in line:
            continue
        parts = line.split()
        if parts:
            return parts[-1]
    return None


def _fallback_parts() -> list[str]:
    return [
        f"node={uuid.getnode()}",
        f"hostname={socket.gethostname()}",
        f"platform={platform.platform()}",
        f"user={os.environ.get('USERNAME') or os.environ.get('USER') or ''}",
    ]


def _normalize(value: object) -> str:
    return str(value or "").strip().lower()
