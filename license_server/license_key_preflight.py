from __future__ import annotations

import errno
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
MAX_SECURE_TEXT_FILE_BYTES = 64 * 1024
_ALLOWED_KEYS = {
    "LICENSE_SERVER_ENV",
    "LICENSE_PRIVATE_KEY",
    "LICENSE_PRIVATE_KEY_FILE",
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


def _read_secure_text_file(
    path: Path,
    *,
    category_prefix: str,
    exit_code: int,
) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise PreflightError(f"{category_prefix}_path_not_absolute", exit_code)

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    before_open = None
    if not nofollow:
        try:
            before_open = candidate.lstat()
        except OSError as exc:
            raise PreflightError(
                f"{category_prefix}_unreadable",
                exit_code,
            ) from exc
        if stat.S_ISLNK(before_open.st_mode):
            raise PreflightError(
                f"{category_prefix}_symlink_rejected",
                exit_code,
            )
        if not stat.S_ISREG(before_open.st_mode):
            raise PreflightError(
                f"{category_prefix}_not_regular",
                exit_code,
            )

    try:
        file_descriptor = os.open(candidate, flags)
    except OSError as exc:
        category = (
            f"{category_prefix}_symlink_rejected"
            if nofollow and exc.errno == errno.ELOOP
            else f"{category_prefix}_unreadable"
        )
        raise PreflightError(category, exit_code) from exc

    try:
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PreflightError(
                f"{category_prefix}_not_regular",
                exit_code,
            )
        if metadata.st_size > MAX_SECURE_TEXT_FILE_BYTES:
            raise PreflightError(
                f"{category_prefix}_too_large",
                exit_code,
            )
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PreflightError(
                f"{category_prefix}_permissions_too_open",
                exit_code,
            )
        if before_open is not None:
            current = candidate.lstat()
            if (
                stat.S_ISLNK(current.st_mode)
                or not os.path.samestat(before_open, metadata)
                or not os.path.samestat(current, metadata)
            ):
                raise PreflightError(
                    f"{category_prefix}_changed_during_open",
                    exit_code,
                )
        chunks = []
        total_bytes = 0
        while True:
            remaining = MAX_SECURE_TEXT_FILE_BYTES - total_bytes
            chunk = os.read(file_descriptor, min(65536, remaining + 1))
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_SECURE_TEXT_FILE_BYTES:
                raise PreflightError(
                    f"{category_prefix}_too_large",
                    exit_code,
                )
            chunks.append(chunk)
    except PreflightError:
        raise
    except OSError as exc:
        raise PreflightError(
            f"{category_prefix}_unreadable",
            exit_code,
        ) from exc
    finally:
        os.close(file_descriptor)

    raw = b"".join(chunks)
    if b"\x00" in raw:
        raise PreflightError(f"{category_prefix}_contains_nul", exit_code)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PreflightError(
            f"{category_prefix}_unreadable",
            exit_code,
        ) from exc


def parse_restricted_env_file(path: Path) -> dict[str, str]:
    text = _read_secure_text_file(
        path,
        category_prefix="env_file",
        exit_code=EXIT_ENVIRONMENT,
    )

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
    private_key_file = values.get("LICENSE_PRIVATE_KEY_FILE", "").strip()
    public_value = values.get("LICENSE_PUBLIC_KEY", "").strip()
    private_source = "LICENSE_PRIVATE_KEY"
    if not private_value and private_key_file:
        private_value = _read_secure_text_file(
            Path(private_key_file),
            category_prefix="configured_private_key_file",
            exit_code=EXIT_KEY_FORMAT,
        ).strip()
        private_source = "LICENSE_PRIVATE_KEY_FILE"
    if not private_value:
        raise PreflightError("configured_private_key_missing", EXIT_KEY_FORMAT)
    if not public_value:
        raise PreflightError("configured_public_key_missing", EXIT_KEY_FORMAT)
    try:
        private_key = load_private_key_b64(
            private_value,
            source=private_source,
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
