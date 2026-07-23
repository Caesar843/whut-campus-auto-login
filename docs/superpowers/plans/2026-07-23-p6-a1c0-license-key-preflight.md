# P6-A1c-0B Production License Key Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repeatable, fail-closed, server-side preflight that proves the configured production Ed25519 private key and public key match, emits a stable SHA-256 public-key fingerprint, and never exposes or moves the private key.

**Architecture:** Extract one side-effect-free Ed25519 key-format helper used by the production server and the preflight so there is only one interpretation of the private-key format. Implement the restricted environment-file parser and preflight logic in a focused `license_server` module, using one descriptor-based safe reader for both the environment file and optional private-key file, then expose it through a thin CLI script. Keep all checks offline, read-only, deterministic in output, and covered with runtime-generated temporary keys.

**Tech Stack:** Python 3.11, `cryptography` Ed25519 primitives, `argparse`, `pathlib`, `stat`, `hashlib`, `hmac`, `secrets`, `pytest`.

## Global Constraints

- Work only on branch `feature/p6-a1c0-license-key-preflight`, based on `main@05dcdab8c5818811f45b88decbe5f40678aead5f`.
- Never add production key material, key fingerprints, environment-file contents, or server output to Git history.
- The script must perform no network access, no database access, no service restart, no deployment, and no executable build.
- The production private key must never be printed to stdout, stderr, exceptions, test diagnostics, snapshots, or logs.
- The preflight must accept only an explicit absolute `--env-file` path and only the restricted literal `KEY=value` subset defined by the approved design.
- The preflight may consume only `LICENSE_SERVER_ENV`, `LICENSE_PRIVATE_KEY`, `LICENSE_PRIVATE_KEY_FILE`, and `LICENSE_PUBLIC_KEY`; all other keys are ignored and never printed.
- Private-key source selection must match `license_server.config._private_key_from_env()`: non-empty inline value first, file fallback only for an empty inline value, and exit `3` when both are missing.
- Both input files must be opened read-only and read from the same validated file descriptor; POSIX uses `O_NOFOLLOW` when available and Windows uses a conservative identity-checked fallback.
- `LICENSE_SERVER_ENV` must normalize to `production` using the same lower-case/trim behavior as `license_server.config`.
- The configured public key must be compared with the private-key-derived raw public key using `hmac.compare_digest`.
- The SHA-256 fingerprint must be computed over the raw 32-byte Ed25519 public key and rendered as 64 lowercase hexadecimal characters.
- Expected validation failures must not emit tracebacks.
- Exit codes are fixed: `0` pass, `1` unexpected controlled failure, `2` environment-file/path/syntax/permission/environment failure, `3` configured private-key source or key-format failure, `4` key mismatch, `5` sign/verify failure.
- Successful default output must include `running_service_keypair=not_verified`; this stage must never claim the running process has reloaded the file.
- POSIX permission and symlink checks must run on Linux; corresponding tests may skip on Windows only when the platform cannot enforce equivalent semantics.
- Use TDD and keep commits focused. Run targeted tests after each task and the full suite before requesting review.

---

## File Structure

- Create `license_server/ed25519_keys.py`: shared, side-effect-free Ed25519 Base64 parsing, raw public-key serialization, derivation, and fingerprinting.
- Modify `license_server/config.py`: reuse the shared private-key parser while preserving the existing `RuntimeError` contract.
- Modify `license_server/signer.py`: reuse the shared private-key parser without changing token wire format.
- Create `tests/license_server/test_ed25519_keys.py`: helper and regression coverage.
- Create `license_server/license_key_preflight.py`: restricted environment-file parsing, preflight result model, exit categories, and pure core verification.
- Create `scripts/ops/verify_production_license_keypair.py`: thin CLI entry point and safe output boundary.
- Create `tests/ops/test_verify_production_license_keypair.py`: parser, crypto flow, output, exit-code, redaction, offline, and read-only coverage.
- Create `docs/release/PRODUCTION_LICENSE_KEY_PREFLIGHT.md`: exact server procedure, result interpretation, and safety boundaries.
- Modify `docs/release/WINDOWS_RELEASE_BUILD.md`: add a narrow cross-reference that P6-A1c-1 must use the fingerprint frozen by this preflight.

---

### Task 1: Share the Production Ed25519 Key Format

**Files:**
- Create: `license_server/ed25519_keys.py`
- Modify: `license_server/config.py`
- Modify: `license_server/signer.py`
- Create: `tests/license_server/test_ed25519_keys.py`

**Interfaces:**
- Produces: `load_private_key_b64(value: str, *, source: str = "LICENSE_PRIVATE_KEY") -> Ed25519PrivateKey`
- Produces: `load_public_key_b64(value: str, *, source: str = "LICENSE_PUBLIC_KEY") -> Ed25519PublicKey`
- Produces: `public_key_raw_bytes(key: Ed25519PublicKey) -> bytes`
- Produces: `derive_public_key_raw_bytes(private_key: Ed25519PrivateKey) -> bytes`
- Produces: `public_key_sha256(raw_public_key: bytes) -> str`
- Produces: `Ed25519KeyFormatError(ValueError)` whose message names only the source field and required format.
- Preserves: `license_server.config.validate_private_key_b64()` raises `RuntimeError` with the existing message.
- Preserves: `license_server.signer.sign_license_payload()` token format and `verify_license_token_payload()` behavior.

- [ ] **Step 1: Write failing helper tests**

Create `tests/license_server/test_ed25519_keys.py` with runtime-generated keys and these exact behavioral cases:

```python
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from license_server.ed25519_keys import (
    Ed25519KeyFormatError,
    derive_public_key_raw_bytes,
    load_private_key_b64,
    load_public_key_b64,
    public_key_raw_bytes,
    public_key_sha256,
)


def _keypair_b64() -> tuple[str, str, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
        public_raw,
    )


def test_loaders_and_derivation_share_raw_key_format():
    private_b64, public_b64, public_raw = _keypair_b64()
    private_key = load_private_key_b64(private_b64)
    public_key = load_public_key_b64(public_b64)
    assert derive_public_key_raw_bytes(private_key) == public_raw
    assert public_key_raw_bytes(public_key) == public_raw


def test_public_key_fingerprint_hashes_raw_bytes_not_base64_text():
    _private_b64, public_b64, public_raw = _keypair_b64()
    assert public_key_sha256(public_raw) == hashlib.sha256(public_raw).hexdigest()
    assert public_key_sha256(public_raw) != hashlib.sha256(public_b64.encode("ascii")).hexdigest()


@pytest.mark.parametrize("value", ["not-base64", base64.b64encode(b"short").decode("ascii")])
def test_private_key_loader_rejects_invalid_values_without_echo(value):
    with pytest.raises(Ed25519KeyFormatError) as exc_info:
        load_private_key_b64(value, source="LICENSE_PRIVATE_KEY")
    message = str(exc_info.value)
    assert "base64-encoded 32-byte Ed25519 private key" in message
    assert value not in message


@pytest.mark.parametrize("value", ["not-base64", base64.b64encode(b"short").decode("ascii")])
def test_public_key_loader_rejects_invalid_values_without_echo(value):
    with pytest.raises(Ed25519KeyFormatError) as exc_info:
        load_public_key_b64(value, source="LICENSE_PUBLIC_KEY")
    message = str(exc_info.value)
    assert "base64-encoded 32-byte Ed25519 public key" in message
    assert value not in message
```

- [ ] **Step 2: Run the new tests and confirm they fail because the module does not exist**

Run:

```bash
python -m pytest tests/license_server/test_ed25519_keys.py -q
```

Expected: collection failure containing `ModuleNotFoundError: No module named 'license_server.ed25519_keys'`.

- [ ] **Step 3: Implement the shared helper**

Create `license_server/ed25519_keys.py` with no application, database, network, or logging imports:

```python
from __future__ import annotations

import base64
import binascii
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class Ed25519KeyFormatError(ValueError):
    pass


def load_private_key_b64(
    value: str,
    *,
    source: str = "LICENSE_PRIVATE_KEY",
) -> Ed25519PrivateKey:
    try:
        raw = base64.b64decode(str(value or "").strip(), validate=True)
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, binascii.Error) as exc:
        raise Ed25519KeyFormatError(
            f"{source} must be a base64-encoded 32-byte Ed25519 private key."
        ) from exc


def load_public_key_b64(
    value: str,
    *,
    source: str = "LICENSE_PUBLIC_KEY",
) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(str(value or "").strip(), validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, binascii.Error) as exc:
        raise Ed25519KeyFormatError(
            f"{source} must be a base64-encoded 32-byte Ed25519 public key."
        ) from exc


def public_key_raw_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_public_key_raw_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return public_key_raw_bytes(private_key.public_key())


def public_key_sha256(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes.")
    return hashlib.sha256(raw_public_key).hexdigest()
```

- [ ] **Step 4: Refactor production config validation to use the helper**

In `license_server/config.py`:

1. Remove direct imports of `base64`, `binascii`, and `Ed25519PrivateKey` only when they are no longer used elsewhere in that file.
2. Add:

```python
from license_server.ed25519_keys import Ed25519KeyFormatError, load_private_key_b64
```

3. Replace `validate_private_key_b64()` with:

```python
def validate_private_key_b64(
    private_key_b64: str,
    *,
    source: str = "LICENSE_PRIVATE_KEY",
) -> None:
    try:
        load_private_key_b64(private_key_b64, source=source)
    except Ed25519KeyFormatError as exc:
        raise RuntimeError(str(exc)) from exc
```

Preserve the exact existing `RuntimeError` message.

- [ ] **Step 5: Refactor the signer to use the helper without changing the token format**

In `license_server/signer.py`:

1. Keep `base64` because `_b64url()` still needs it.
2. Replace the direct `Ed25519PrivateKey` import with:

```python
from license_server.ed25519_keys import load_private_key_b64
```

3. Replace both calls to `Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))` with:

```python
private_key = load_private_key_b64(private_key_b64)
```

Do not change payload JSON canonicalization, Base64URL encoding, signature input, token separator, or verification exception mapping.

- [ ] **Step 6: Run helper and signer/config regressions**

Run:

```bash
python -m pytest \
  tests/license_server/test_ed25519_keys.py \
  tests/license_server/test_license_server.py \
  -q
```

Expected: all selected tests pass.

- [ ] **Step 7: Commit Task 1**

```bash
git add \
  license_server/ed25519_keys.py \
  license_server/config.py \
  license_server/signer.py \
  tests/license_server/test_ed25519_keys.py
git commit -m "refactor(license): share Ed25519 key parsing"
```

---

### Task 2: Implement the Restricted Preflight Core and CLI

**Files:**
- Create: `license_server/license_key_preflight.py`
- Create: `scripts/ops/verify_production_license_keypair.py`
- Create: `tests/ops/test_verify_production_license_keypair.py`

**Interfaces:**
- Consumes: all Task 1 helper functions.
- Produces: `PreflightError(category: str, exit_code: int)` with redacted category-only messages.
- Produces: `PreflightReport` fields matching successful output.
- Produces: a focused internal secure text-file reader shared by the environment and private-key file paths.
- Produces: `parse_restricted_env_file(path: Path) -> dict[str, str]`.
- Produces: `verify_configured_keypair(env_file: Path) -> PreflightReport`.
- Produces: `main(argv: list[str] | None = None) -> int` in the CLI script.

- [ ] **Step 1: Write failing parser and success-flow tests**

Create `tests/ops/test_verify_production_license_keypair.py` with local helpers that:

- generate temporary Ed25519 key pairs at runtime;
- create mode `0o600` environment files on POSIX;
- import `license_server.license_key_preflight` and load the CLI script through `importlib.util.spec_from_file_location`;
- never use production values.

The first test block must cover:

```python
def test_valid_matching_production_keypair_passes(tmp_path):
    env_file, private_b64, public_b64, public_raw = _write_valid_env(tmp_path)
    report = verify_configured_keypair(env_file)
    assert report.environment == "production"
    assert report.public_key_sha256 == hashlib.sha256(public_raw).hexdigest()
    assert report.public_key_base64 == public_b64
    assert private_b64 not in repr(report)


def test_mismatched_public_key_returns_exit_code_4(tmp_path):
    env_file, private_b64, _public_b64, _public_raw = _write_valid_env(tmp_path)
    other_public_b64 = _generated_public_key_b64()
    _replace_key(env_file, "LICENSE_PUBLIC_KEY", other_public_b64)
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.exit_code == 4
    assert exc_info.value.category == "configured_keypair_mismatch"
    assert private_b64 not in str(exc_info.value)
    assert other_public_b64 not in str(exc_info.value)


@pytest.mark.parametrize("environment", ["development", "test", "staging", ""])
def test_non_production_environment_returns_exit_code_2(tmp_path, environment):
    env_file, *_ = _write_valid_env(tmp_path, environment=environment)
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.exit_code == 2
    assert exc_info.value.category == "production_environment_required"
```

Also add tests for invalid private/public Base64, wrong decoded lengths, missing key fields, and raw-byte fingerprinting.

Compatibility coverage must also include inline-only, file-only, inline
priority, empty-inline fallback, private-key file safety and redaction, and
descriptor-based reads for both input files.

- [ ] **Step 2: Run targeted tests and confirm module import failure**

Run:

```bash
python -m pytest tests/ops/test_verify_production_license_keypair.py -q
```

Expected: collection failure naming missing `license_server.license_key_preflight` or missing CLI script.

- [ ] **Step 3: Implement the preflight core**

Create `license_server/license_key_preflight.py` with:

```python
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
_ALLOWED_KEYS = {
    "LICENSE_SERVER_ENV",
    "LICENSE_PRIVATE_KEY",
    "LICENSE_PRIVATE_KEY_FILE",
    "LICENSE_PUBLIC_KEY",
}
_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CHALLENGE_PREFIX = b"whut-campus-auto-login:production-license-key-preflight:v1\x00"


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
        while chunk := os.read(file_descriptor, 65536):
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
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw_line.rstrip().endswith("\\"):
            raise PreflightError("env_file_unsupported_syntax", EXIT_ENVIRONMENT)
        if stripped.startswith("export ") or "=" not in raw_line:
            raise PreflightError("env_file_unsupported_syntax", EXIT_ENVIRONMENT)
        key_text, value = raw_line.split("=", 1)
        key = key_text.strip()
        if key_text != key or not _KEY_PATTERN.fullmatch(key):
            raise PreflightError("env_file_invalid_key", EXIT_ENVIRONMENT)
        if key in parsed:
            raise PreflightError("env_file_duplicate_key", EXIT_ENVIRONMENT)
        if any(marker in value for marker in ("$(", "${", "`", "<<")):
            raise PreflightError("env_file_unsupported_syntax", EXIT_ENVIRONMENT)
        if value.startswith(("'", '"')) or value.endswith(("'", '"')):
            raise PreflightError("env_file_unsupported_quoting", EXIT_ENVIRONMENT)
        parsed[key] = value
    return {key: parsed[key] for key in _ALLOWED_KEYS if key in parsed}


def verify_configured_keypair(env_file: Path) -> PreflightReport:
    values = parse_restricted_env_file(env_file)
    environment = values.get("LICENSE_SERVER_ENV", "").strip().lower()
    if environment != "production":
        raise PreflightError("production_environment_required", EXIT_ENVIRONMENT)
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
        private_key = load_private_key_b64(private_value, source=private_source)
        public_key = load_public_key_b64(public_value, source="LICENSE_PUBLIC_KEY")
    except Ed25519KeyFormatError as exc:
        category = (
            "configured_private_key_invalid"
            if "private key" in str(exc)
            else "configured_public_key_invalid"
        )
        raise PreflightError(category, EXIT_KEY_FORMAT) from exc
    derived_raw = derive_public_key_raw_bytes(private_key)
    configured_raw = public_key_raw_bytes(public_key)
    if not hmac.compare_digest(derived_raw, configured_raw):
        raise PreflightError("configured_keypair_mismatch", EXIT_KEY_MISMATCH)
    challenge = _CHALLENGE_PREFIX + secrets.token_bytes(32)
    signature = private_key.sign(challenge)
    try:
        public_key.verify(signature, challenge)
    except InvalidSignature as exc:
        raise PreflightError("configured_sign_verify_failed", EXIT_SIGN_VERIFY) from exc
    return PreflightReport(
        environment=environment,
        public_key_sha256=public_key_sha256(configured_raw),
        public_key_base64=public_value,
    )
```

During implementation, do not add logging, network imports, database imports, file writes, or key-generation code to production modules.

- [ ] **Step 4: Implement the thin CLI and safe output boundary**

Create `scripts/ops/verify_production_license_keypair.py`:

```python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from license_server.license_key_preflight import (
    EXIT_UNEXPECTED,
    PreflightError,
    verify_configured_keypair,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the configured production Ed25519 license key pair."
    )
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--show-public-key", action="store_true")
    return parser


def _print_success(report, *, show_public_key: bool) -> None:
    print("environment_file=pass")
    print(f"environment={report.environment}")
    print("configured_private_key=pass")
    print("configured_public_key=pass")
    print("configured_keypair_match=pass")
    print("configured_sign_verify=pass")
    print(f"public_key_sha256={report.public_key_sha256}")
    if show_public_key:
        print(f"public_key_base64={report.public_key_base64}")
    print("running_service_keypair=not_verified")
    print("result=PASS")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = verify_configured_keypair(args.env_file)
    except PreflightError as exc:
        print(f"error={exc.category}", file=sys.stderr)
        print("result=FAIL")
        return exc.exit_code
    except Exception as exc:
        print(f"error=unexpected_failure:{type(exc).__name__}", file=sys.stderr)
        print("result=FAIL")
        return EXIT_UNEXPECTED
    _print_success(report, show_public_key=args.show_public_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Do not print exception messages in the unexpected-failure path.

- [ ] **Step 5: Complete security and parser tests**

Expand `tests/ops/test_verify_production_license_keypair.py` to cover all of these exact categories and exit codes:

- relative path -> `env_file_path_not_absolute`, `2`;
- missing file -> `env_file_unreadable`, `2`;
- symlink -> `env_file_symlink_rejected`, `2` on POSIX;
- mode with any group/other bit -> `env_file_permissions_too_open`, `2` on POSIX;
- duplicate key -> `env_file_duplicate_key`, `2`;
- `export`, command substitution, variable expansion, backticks, heredoc marker, trailing backslash, quoted values, malformed key, and NUL -> exit `2`;
- missing private/public field -> exit `3`;
- invalid private/public key -> exit `3` without echoing supplied values;
- mismatched pair -> exit `4`;
- forced `InvalidSignature` -> exit `5` by monkeypatching the public-key verification object through a focused seam, not by changing production output;
- default success output exactly matches the approved fields and excludes private key, challenge, signature, and public-key Base64;
- `--show-public-key` adds only `public_key_base64=<value>`;
- failure prints category to stderr and `result=FAIL` to stdout with no traceback;
- monkeypatched `socket.socket`, `urllib.request.urlopen`, and `sqlite3.connect` raise if called, while valid verification still passes;
- environment-file bytes, mode, size, and `st_mtime_ns` are unchanged after verification;
- private-key source selection matches inline-first/file-fallback server semantics;
- private-key file relative, missing, symlink, non-regular, POSIX permission, invalid Base64/length, NUL, and UTF-8 failures return exit `3`;
- private-key file bytes, mode, size, and `st_mtime_ns` are unchanged after verification;
- environment and private-key file reads use `os.open`/`fstat`/`os.read` on the same descriptor;
- an unrelated key containing a sentinel secret is ignored and never printed.

Use `pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics required")` only on permission/symlink cases that Windows cannot enforce.

- [ ] **Step 6: Run targeted tests**

Run:

```bash
python -m pytest \
  tests/license_server/test_ed25519_keys.py \
  tests/ops/test_verify_production_license_keypair.py \
  -q
```

Expected: all selected tests pass; POSIX-only tests may be skipped on Windows with explicit reasons.

- [ ] **Step 7: Run license-server regressions**

Run:

```bash
python -m pytest tests/license_server -q
python -m compileall -q license_server scripts/ops
```

Expected: all license-server tests pass and compileall exits `0`.

- [ ] **Step 8: Commit Task 2**

```bash
git add \
  license_server/license_key_preflight.py \
  scripts/ops/verify_production_license_keypair.py \
  tests/ops/test_verify_production_license_keypair.py
git commit -m "feat(release): add production license key preflight"
```

---

### Task 3: Document the Operational Contract and Release Boundary

**Files:**
- Create: `docs/release/PRODUCTION_LICENSE_KEY_PREFLIGHT.md`
- Modify: `docs/release/WINDOWS_RELEASE_BUILD.md`

**Interfaces:**
- Consumes: the CLI path, exit codes, output fields, and constraints from Task 2.
- Produces: an operator SOP that does not include production values.
- Produces: a release-build cross-reference to the frozen fingerprint.

- [ ] **Step 1: Write the production preflight SOP**

Create `docs/release/PRODUCTION_LICENSE_KEY_PREFLIGHT.md` with these sections and exact operational meaning:

1. Purpose: proves only the configured environment-file key pair, supporting either inline `LICENSE_PRIVATE_KEY` or `LICENSE_PRIVATE_KEY_FILE` with production source priority.
2. Preconditions: approved commit synced; no environment-file changes; server Python virtual environment available; operator has read permission through `sudo`.
3. Command:

```bash
cd /opt/whut-campus-auto-login
sudo /opt/whut-campus-auto-login/.venv/bin/python \
  scripts/ops/verify_production_license_keypair.py \
  --env-file /etc/whut-campus-auto-login/license-server.env
```

4. Optional public-key output command with `--show-public-key`.
5. Exact successful output fields, including `running_service_keypair=not_verified`.
6. Exit-code table `0` through `5`.
7. Stop conditions: any non-zero exit, unexpected output, traceback, private-key appearance, environment-file modification, or mismatch.
8. Evidence to retain: commit SHA, UTC execution time, safe output, and public-key SHA-256 only.
9. Evidence never to retain: private key, environment-file dump, challenge, signature, payment secrets, administrator secrets, or database contents.
10. Interpretation: `PASS` means configured pair only; it does not prove running-service reload, HTTPS, or final EXE embedding.
11. Next stage: after ICP and HTTPS readiness, P6-A1c-1 must verify a running-service token and compare all three fingerprints: server preflight, build input, packaged client.
12. Memory limitation: Python cannot guarantee complete zeroization; do not claim otherwise.

- [ ] **Step 2: Add the narrow release-build cross-reference**

In `docs/release/WINDOWS_RELEASE_BUILD.md`, add a short P6-A1c prerequisite paragraph near the production command:

```markdown
Before a production build, run `docs/release/PRODUCTION_LICENSE_KEY_PREFLIGHT.md` on the production server and freeze the successful `public_key_sha256` value. The public key supplied to `scripts/build_windows.ps1` must reproduce that fingerprint. A preflight `PASS` does not replace the later public HTTPS and running-service token checks.
```

Do not add the real URL, public key, fingerprint, or server output.

- [ ] **Step 3: Verify documentation and scope**

Run:

```bash
git diff --check
rg -n "LICENSE_PRIVATE_KEY=|public_key_sha256=[0-9a-f]{64}|BEGIN (RSA|PRIVATE) KEY" \
  docs scripts license_server tests
```

Expected:

- `git diff --check` exits `0`.
- The secret scan finds only intentional variable names, test assertions, or documentation placeholders; no real key material or frozen production fingerprint exists.

- [ ] **Step 4: Commit Task 3**

```bash
git add \
  docs/release/PRODUCTION_LICENSE_KEY_PREFLIGHT.md \
  docs/release/WINDOWS_RELEASE_BUILD.md
git commit -m "docs(release): add license key preflight SOP"
```

---

### Task 4: Whole-Branch Verification, Review, and Read-Only Production Acceptance

**Files:**
- Review all branch changes from `05dcdab8c5818811f45b88decbe5f40678aead5f` to `HEAD`.
- Do not commit production execution output.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: reviewed implementation, passing test evidence, and a safe production fingerprint recorded outside Git.

- [ ] **Step 1: Run complete automated verification**

Run from the repository root:

```bash
python -m pytest tests/license_server/test_ed25519_keys.py -q
python -m pytest tests/ops/test_verify_production_license_keypair.py -q
python -m pytest tests/license_server -q
python -m pytest -q
python -m compileall -q license_server scripts/ops
git diff --check 05dcdab8c5818811f45b88decbe5f40678aead5f..HEAD
```

Expected: all tests pass; only documented platform skips remain; compileall and diff check exit `0`.

- [ ] **Step 2: Perform a branch-wide security review**

Review the full range and explicitly confirm:

- only the three whitelisted environment fields are consumed;
- no parsed environment map or private value is printed;
- expected failures have no traceback;
- all exit codes and categories match the approved contract;
- helper reuse prevents a second private-key format interpretation;
- token wire format is unchanged;
- there are no network/database/write/service/build code paths;
- public-key fingerprint hashes raw bytes;
- the success statement does not overclaim running-service verification;
- no production key material appears in history.

Fix every Critical, High, or Medium issue and rerun the covering tests before proceeding.

- [ ] **Step 3: Update the draft PR for implementation review**

Update PR #17 title and body to reflect implementation status, test commands, scope boundaries, and the fact that production execution has not yet been committed or performed. Mark it ready only after branch review is clean.

- [ ] **Step 4: Merge only after review approval**

Required gates:

- CI green;
- CodeRabbit completed or its absence accurately disclosed;
- independent Codex review has no unresolved High or Medium finding;
- full suite passed on the final commit;
- no production values in Git.

Use rebase merge only after confirming the expected head SHA.

- [ ] **Step 5: Run the read-only production preflight after the approved commit is deployed**

On the Tencent Cloud server, from the approved deployed commit:

```bash
cd /opt/whut-campus-auto-login
git rev-parse HEAD
git status --short
sudo /opt/whut-campus-auto-login/.venv/bin/python \
  scripts/ops/verify_production_license_keypair.py \
  --env-file /etc/whut-campus-auto-login/license-server.env
printf 'preflight_exit=%s\n' "$?"
```

Acceptance:

```text
environment_file=pass
environment=production
configured_private_key=pass
configured_public_key=pass
configured_keypair_match=pass
configured_sign_verify=pass
public_key_sha256=<64 lowercase hexadecimal characters>
running_service_keypair=not_verified
result=PASS
preflight_exit=0
```

Do not paste or commit the private key or the complete environment file. Store the safe fingerprint and execution metadata in the private release record only.

- [ ] **Step 6: Freeze the later build input without building yet**

Only when needed for P6-A1c-1, rerun with:

```bash
sudo /opt/whut-campus-auto-login/.venv/bin/python \
  scripts/ops/verify_production_license_keypair.py \
  --env-file /etc/whut-campus-auto-login/license-server.env \
  --show-public-key
```

Copy only `public_key_base64` and `public_key_sha256` into the controlled local release session. Do not put them in Git, issue comments, PR bodies, CI variables, or public logs.

---

## Final Completion State

The implementation is complete only when all code and documentation gates pass and the server execution returns `result=PASS`. The allowed project statement is:

```text
Configured production Ed25519 key pair: READY
Configured public-key fingerprint: FROZEN
Production private key left the server: NO
Running service end-to-end signing: NOT VERIFIED
Public HTTPS: BLOCKED pending ICP filing
Production Windows executable: NOT BUILT
Production release: NOT APPROVED
```
