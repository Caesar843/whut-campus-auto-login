from __future__ import annotations

import hmac
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from license_server.ed25519_keys import (
    Ed25519KeyFormatError,
    derive_public_key_raw_bytes,
    load_private_key_b64,
    load_public_key_b64,
    public_key_raw_bytes,
    public_key_sha256,
)

EXIT_UNEXPECTED = 1
EXIT_ENVIRONMENT = 2
EXIT_KEY_FORMAT = 3
EXIT_KEY_MISMATCH = 4
EXIT_SIGN_VERIFY = 5
_ALLOWED_KEYS = {
    "LICENSE_SERVER_ENV",
    "LICENSE_PRIVATE_KEY",
    "LICENSE_PUBLIC_KEY",
}
_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CHALLENGE_PREFIX = (
    b"whut-campus-auto-login:production-license-key-preflight:v1\x00"
)


class PreflightError(Exception):
    def __init__(self, category: str, exit_code: int) -> None:
        super().__init__(category)
        self.category = category
        self.exit_code = exit_code


@dataclass(frozen=True, repr=False)
class PreflightReport:
    environment: str
    public_key_sha256: str
    public_key_base64: str


def parse_restricted_env_file(path: Path) -> dict[str, str]:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise PreflightError("env_file_path_not_absolute", EXIT_ENVIRONMENT)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise PreflightError("env_file_unreadable", EXIT_ENVIRONMENT) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise PreflightError("env_file_symlink_rejected", EXIT_ENVIRONMENT)
    if not stat.S_ISREG(metadata.st_mode):
        raise PreflightError("env_file_not_regular", EXIT_ENVIRONMENT)
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PreflightError("env_file_permissions_too_open", EXIT_ENVIRONMENT)
    try:
        raw = candidate.read_bytes()
        if b"\x00" in raw:
            raise PreflightError("env_file_contains_nul", EXIT_ENVIRONMENT)
        text = raw.decode("utf-8")
    except PreflightError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise PreflightError("env_file_unreadable", EXIT_ENVIRONMENT) from exc

    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw_line.rstrip().endswith("\\"):
            raise PreflightError(
                "env_file_unsupported_syntax",
                EXIT_ENVIRONMENT,
            )
        if stripped.startswith("export ") or "=" not in raw_line:
            raise PreflightError(
                "env_file_unsupported_syntax",
                EXIT_ENVIRONMENT,
            )
        key_text, value = raw_line.split("=", 1)
        key = key_text.strip()
        if key_text != key or not _KEY_PATTERN.fullmatch(key):
            raise PreflightError("env_file_invalid_key", EXIT_ENVIRONMENT)
        if key in parsed:
            raise PreflightError("env_file_duplicate_key", EXIT_ENVIRONMENT)
        if "$" in value or "`" in value or "<<" in value:
            raise PreflightError(
                "env_file_unsupported_syntax",
                EXIT_ENVIRONMENT,
            )
        if "'" in value or '"' in value:
            raise PreflightError(
                "env_file_unsupported_quoting",
                EXIT_ENVIRONMENT,
            )
        parsed[key] = value
    return {key: parsed[key] for key in _ALLOWED_KEYS if key in parsed}


def verify_configured_keypair(env_file: Path) -> PreflightReport:
    values = parse_restricted_env_file(env_file)
    environment = values.get("LICENSE_SERVER_ENV", "").strip().lower()
    if environment != "production":
        raise PreflightError(
            "production_environment_required",
            EXIT_ENVIRONMENT,
        )
    private_value = values.get("LICENSE_PRIVATE_KEY", "").strip()
    public_value = values.get("LICENSE_PUBLIC_KEY", "").strip()
    if not private_value:
        raise PreflightError("configured_private_key_missing", EXIT_KEY_FORMAT)
    if not public_value:
        raise PreflightError("configured_public_key_missing", EXIT_KEY_FORMAT)
    try:
        private_key = load_private_key_b64(
            private_value,
            source="LICENSE_PRIVATE_KEY",
        )
    except Ed25519KeyFormatError as exc:
        raise PreflightError(
            "configured_private_key_invalid",
            EXIT_KEY_FORMAT,
        ) from exc
    try:
        public_key = load_public_key_b64(
            public_value,
            source="LICENSE_PUBLIC_KEY",
        )
    except Ed25519KeyFormatError as exc:
        raise PreflightError(
            "configured_public_key_invalid",
            EXIT_KEY_FORMAT,
        ) from exc

    derived_raw = derive_public_key_raw_bytes(private_key)
    configured_raw = public_key_raw_bytes(public_key)
    if not hmac.compare_digest(derived_raw, configured_raw):
        raise PreflightError(
            "configured_keypair_mismatch",
            EXIT_KEY_MISMATCH,
        )

    challenge = _CHALLENGE_PREFIX + secrets.token_bytes(32)
    signature = private_key.sign(challenge)
    try:
        public_key.verify(signature, challenge)
    except InvalidSignature as exc:
        raise PreflightError(
            "configured_sign_verify_failed",
            EXIT_SIGN_VERIFY,
        ) from exc

    return PreflightReport(
        environment=environment,
        public_key_sha256=public_key_sha256(configured_raw),
        public_key_base64=public_value,
    )
