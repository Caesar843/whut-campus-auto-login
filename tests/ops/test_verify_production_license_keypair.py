import base64
import hashlib
import importlib.util
import os
import socket
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import license_server.license_key_preflight as preflight
from license_server.license_key_preflight import (
    EXIT_ENVIRONMENT,
    EXIT_KEY_FORMAT,
    EXIT_KEY_MISMATCH,
    EXIT_SIGN_VERIFY,
    MAX_SECURE_TEXT_FILE_BYTES,
    PreflightError,
    parse_restricted_env_file,
    verify_configured_keypair,
)


CLI_PATH = Path("scripts/ops/verify_production_license_keypair.py")
# Absolute repo root, derived from this test file's location (tests/ops/).
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_CLI_SCRIPT = _REPO_ROOT / "scripts/ops" / "verify_production_license_keypair.py"


def _keypair_b64() -> tuple[str, str, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
        public_raw,
    )


def _generated_public_key_b64() -> str:
    return _keypair_b64()[1]


def _write_env(tmp_path: Path, lines: list[str]) -> Path:
    env_file = tmp_path / "license-server.env"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    env_file.chmod(0o600)
    return env_file


def _write_valid_env(
    tmp_path: Path,
    *,
    environment: str = "production",
) -> tuple[Path, str, str, bytes]:
    private_b64, public_b64, public_raw = _keypair_b64()
    env_file = _write_env(
        tmp_path,
        [
            f"LICENSE_SERVER_ENV={environment}",
            f"LICENSE_PRIVATE_KEY={private_b64}",
            f"LICENSE_PUBLIC_KEY={public_b64}",
        ],
    )
    return env_file, private_b64, public_b64, public_raw


def _write_private_key_file(tmp_path: Path, value: str | bytes) -> Path:
    private_key_file = tmp_path / "license-private-key"
    if isinstance(value, bytes):
        private_key_file.write_bytes(value)
    else:
        private_key_file.write_text(value, encoding="utf-8")
    private_key_file.chmod(0o600)
    return private_key_file


def _set_private_key_sources(
    env_file: Path,
    *,
    inline: str | None,
    private_key_file: Path | str | None,
) -> None:
    lines = [
        line
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if not line.startswith(("LICENSE_PRIVATE_KEY=", "LICENSE_PRIVATE_KEY_FILE="))
    ]
    if inline is not None:
        lines.append(f"LICENSE_PRIVATE_KEY={inline}")
    if private_key_file is not None:
        lines.append(f"LICENSE_PRIVATE_KEY_FILE={private_key_file}")
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _replace_key(env_file: Path, key: str, value: str) -> None:
    lines = env_file.read_text(encoding="utf-8").splitlines()
    env_file.write_text(
        "\n".join(
            f"{key}={value}" if line.startswith(f"{key}=") else line
            for line in lines
        )
        + "\n",
        encoding="utf-8",
    )


def _pad_text_file_to_size(path: Path, size: int) -> None:
    current = path.read_bytes()
    remaining = size - len(current)
    assert remaining >= 2
    padding = ("#" + ("x" * (remaining - 2)) + "\n").encode("utf-8")
    path.write_bytes(current + padding)
    assert path.stat().st_size == size


def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "verify_production_license_keypair",
        CLI_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_inline_private_key_only_passes(tmp_path):
    env_file, private_b64, public_b64, public_raw = _write_valid_env(tmp_path)

    report = verify_configured_keypair(env_file)

    assert report.environment == "production"
    assert report.public_key_sha256 == hashlib.sha256(public_raw).hexdigest()
    assert report.public_key_base64 == public_b64
    assert private_b64 not in repr(report)


def test_private_key_file_only_passes(tmp_path):
    env_file, private_b64, public_b64, public_raw = _write_valid_env(tmp_path)
    private_key_file = _write_private_key_file(tmp_path, private_b64)
    _set_private_key_sources(
        env_file,
        inline=None,
        private_key_file=private_key_file,
    )

    report = verify_configured_keypair(env_file)

    assert report.public_key_base64 == public_b64
    assert report.public_key_sha256 == hashlib.sha256(public_raw).hexdigest()
    assert private_b64 not in repr(report)


def test_inline_private_key_takes_priority_over_private_key_file(tmp_path):
    env_file, _private_b64, _public_b64, _public_raw = _write_valid_env(tmp_path)
    unused_file_secret = "INVALID-UNUSED-PRIVATE-KEY-FILE"
    private_key_file = _write_private_key_file(tmp_path, unused_file_secret)
    with env_file.open("a", encoding="utf-8") as stream:
        stream.write(f"LICENSE_PRIVATE_KEY_FILE={private_key_file}\n")

    report = verify_configured_keypair(env_file)

    assert report.environment == "production"
    assert unused_file_secret not in repr(report)


def test_empty_inline_private_key_falls_back_to_private_key_file(tmp_path):
    env_file, private_b64, _public_b64, _public_raw = _write_valid_env(tmp_path)
    private_key_file = _write_private_key_file(tmp_path, private_b64)
    _set_private_key_sources(
        env_file,
        inline="   ",
        private_key_file=private_key_file,
    )

    assert verify_configured_keypair(env_file).environment == "production"


@pytest.mark.parametrize(
    ("file_value", "category"),
    [
        ("relative-private-key", "configured_private_key_file_path_not_absolute"),
        ("missing-private-key", "configured_private_key_file_unreadable"),
    ],
)
def test_private_key_file_path_failures_return_exit_code_3(
    tmp_path,
    file_value,
    category,
):
    env_file, *_ = _write_valid_env(tmp_path)
    path = file_value
    if file_value.startswith("missing"):
        path = tmp_path / file_value
    _set_private_key_sources(env_file, inline=None, private_key_file=path)

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        category,
        EXIT_KEY_FORMAT,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics required")
def test_private_key_file_symbolic_link_is_rejected(tmp_path):
    env_file, private_b64, *_ = _write_valid_env(tmp_path)
    private_key_file = _write_private_key_file(tmp_path, private_b64)
    link = tmp_path / "linked-private-key"
    link.symlink_to(private_key_file)
    _set_private_key_sources(env_file, inline=None, private_key_file=link)

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "configured_private_key_file_symlink_rejected",
        EXIT_KEY_FORMAT,
    )


def test_private_key_file_must_be_regular(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    private_key_directory = tmp_path / "private-key-directory"
    private_key_directory.mkdir()
    _set_private_key_sources(
        env_file,
        inline=None,
        private_key_file=private_key_directory,
    )

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "configured_private_key_file_not_regular",
        EXIT_KEY_FORMAT,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics required")
def test_private_key_file_group_or_other_permissions_are_rejected(tmp_path):
    env_file, private_b64, *_ = _write_valid_env(tmp_path)
    private_key_file = _write_private_key_file(tmp_path, private_b64)
    private_key_file.chmod(0o640)
    _set_private_key_sources(
        env_file,
        inline=None,
        private_key_file=private_key_file,
    )

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "configured_private_key_file_permissions_too_open",
        EXIT_KEY_FORMAT,
    )


@pytest.mark.parametrize(
    "value",
    [
        "not-base64-private-file",
        base64.b64encode(b"short-private-file").decode("ascii"),
    ],
)
def test_private_key_file_rejects_invalid_key_values_without_echo(tmp_path, value):
    env_file, *_ = _write_valid_env(tmp_path)
    private_key_file = _write_private_key_file(tmp_path, value)
    _set_private_key_sources(
        env_file,
        inline=None,
        private_key_file=private_key_file,
    )

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "configured_private_key_invalid",
        EXIT_KEY_FORMAT,
    )
    assert value not in str(exc_info.value)
    assert value not in repr(exc_info.value)


@pytest.mark.parametrize(
    ("content", "category"),
    [
        (b"private-key\x00value", "configured_private_key_file_contains_nul"),
        (b"private-key\xffvalue", "configured_private_key_file_unreadable"),
    ],
)
def test_private_key_file_rejects_nul_and_invalid_utf8(
    tmp_path,
    content,
    category,
):
    env_file, *_ = _write_valid_env(tmp_path)
    private_key_file = _write_private_key_file(tmp_path, content)
    _set_private_key_sources(
        env_file,
        inline=None,
        private_key_file=private_key_file,
    )

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        category,
        EXIT_KEY_FORMAT,
    )


def test_private_key_file_secret_never_reaches_output_exception_or_repr(
    tmp_path,
    capsys,
):
    env_file, *_ = _write_valid_env(tmp_path)
    secret = "PRIVATE-FILE-SECRET-SENTINEL"
    private_key_file = _write_private_key_file(tmp_path, secret)
    _set_private_key_sources(
        env_file,
        inline=None,
        private_key_file=private_key_file,
    )

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value)

    cli = _load_cli()
    assert cli.main(["--env-file", str(env_file)]) == EXIT_KEY_FORMAT
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err


def test_private_key_file_is_not_modified(tmp_path):
    env_file, private_b64, *_ = _write_valid_env(tmp_path)
    private_key_file = _write_private_key_file(tmp_path, private_b64)
    _set_private_key_sources(
        env_file,
        inline=None,
        private_key_file=private_key_file,
    )
    before_bytes = private_key_file.read_bytes()
    before_stat = private_key_file.stat()

    verify_configured_keypair(env_file)

    after_stat = private_key_file.stat()
    assert private_key_file.read_bytes() == before_bytes
    assert after_stat.st_mode == before_stat.st_mode
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns


def test_environment_file_is_read_from_open_descriptor(tmp_path, monkeypatch):
    env_file, *_ = _write_valid_env(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("path-based read attempted")

    monkeypatch.setattr(Path, "read_bytes", forbidden)

    assert verify_configured_keypair(env_file).environment == "production"


def test_environment_file_at_size_limit_is_not_rejected_for_size(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    _pad_text_file_to_size(env_file, MAX_SECURE_TEXT_FILE_BYTES)

    assert verify_configured_keypair(env_file).environment == "production"


def test_environment_file_over_size_limit_fails_safely(tmp_path, capsys):
    env_file, *_ = _write_valid_env(tmp_path)
    sentinel = "OVERSIZED-ENV-FILE-SENTINEL"
    _pad_text_file_to_size(
        env_file,
        MAX_SECURE_TEXT_FILE_BYTES + 1 - len(sentinel),
    )
    env_file.write_bytes(env_file.read_bytes() + sentinel.encode("utf-8"))
    assert env_file.stat().st_size == MAX_SECURE_TEXT_FILE_BYTES + 1

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "env_file_too_large",
        EXIT_ENVIRONMENT,
    )
    assert sentinel not in str(exc_info.value)
    assert sentinel not in repr(exc_info.value)

    cli = _load_cli()
    assert cli.main(["--env-file", str(env_file)]) == EXIT_ENVIRONMENT
    captured = capsys.readouterr()
    assert captured.out == "result=FAIL\n"
    assert captured.err == "error=env_file_too_large\n"
    assert sentinel not in captured.out + captured.err


def test_private_key_file_over_size_limit_fails_safely(tmp_path, capsys):
    env_file, *_ = _write_valid_env(tmp_path)
    sentinel = "OVERSIZED-PRIVATE-KEY-FILE-SENTINEL"
    private_key_file = _write_private_key_file(
        tmp_path,
        ("x" * (MAX_SECURE_TEXT_FILE_BYTES + 1 - len(sentinel))) + sentinel,
    )
    _set_private_key_sources(
        env_file,
        inline=None,
        private_key_file=private_key_file,
    )

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "configured_private_key_file_too_large",
        EXIT_KEY_FORMAT,
    )
    assert sentinel not in str(exc_info.value)
    assert sentinel not in repr(exc_info.value)

    cli = _load_cli()
    assert cli.main(["--env-file", str(env_file)]) == EXIT_KEY_FORMAT
    captured = capsys.readouterr()
    assert captured.out == "result=FAIL\n"
    assert captured.err == "error=configured_private_key_file_too_large\n"
    assert sentinel not in captured.out + captured.err


def test_file_descriptor_is_closed_after_size_limit_failure(
    tmp_path,
    monkeypatch,
):
    env_file, *_ = _write_valid_env(tmp_path)
    _pad_text_file_to_size(env_file, MAX_SECURE_TEXT_FILE_BYTES + 1)
    assert env_file.stat().st_size == MAX_SECURE_TEXT_FILE_BYTES + 1
    closed_fds: list[int] = []
    original_close = preflight.os.close

    def close_and_record(file_descriptor):
        closed_fds.append(file_descriptor)
        original_close(file_descriptor)

    monkeypatch.setattr(preflight.os, "close", close_and_record)

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert exc_info.value.category == "env_file_too_large"
    assert len(closed_fds) == 1
    with pytest.raises(OSError):
        os.fstat(closed_fds[0])


def test_file_that_grows_during_read_is_rejected(tmp_path, monkeypatch):
    env_file, *_ = _write_valid_env(tmp_path)
    _pad_text_file_to_size(env_file, 500)
    assert env_file.stat().st_size == 500

    read_call_count = 0
    original_read = preflight.os.read

    def growing_read(fd, n):
        nonlocal read_call_count
        read_call_count += 1
        if read_call_count == 1:
            return original_read(fd, n)
        return b"x" * min(n, MAX_SECURE_TEXT_FILE_BYTES)

    monkeypatch.setattr(preflight.os, "read", growing_read)

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert exc_info.value.category == "env_file_too_large"
    assert read_call_count == 2, (
        f"os.read called {read_call_count} times (expected 2). "
        "The function continued reading after exceeding the 64 KiB size limit."
    )


def test_mismatched_public_key_returns_exit_code_4(tmp_path):
    env_file, private_b64, _public_b64, _public_raw = _write_valid_env(tmp_path)
    other_public_b64 = _generated_public_key_b64()
    _replace_key(env_file, "LICENSE_PUBLIC_KEY", other_public_b64)

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert exc_info.value.exit_code == EXIT_KEY_MISMATCH
    assert exc_info.value.category == "configured_keypair_mismatch"
    assert private_b64 not in str(exc_info.value)
    assert other_public_b64 not in str(exc_info.value)


@pytest.mark.parametrize("environment", ["development", "test", "staging", ""])
def test_non_production_environment_returns_exit_code_2(tmp_path, environment):
    env_file, *_ = _write_valid_env(tmp_path, environment=environment)

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert exc_info.value.exit_code == EXIT_ENVIRONMENT
    assert exc_info.value.category == "production_environment_required"


def test_production_environment_uses_server_trim_and_lower_normalization(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path, environment="  ProDucTion  ")

    assert verify_configured_keypair(env_file).environment == "production"


@pytest.mark.parametrize(
    ("key", "value", "category"),
    [
        ("LICENSE_PRIVATE_KEY", "not-base64-private", "configured_private_key_invalid"),
        ("LICENSE_PUBLIC_KEY", "not-base64-public", "configured_public_key_invalid"),
        (
            "LICENSE_PRIVATE_KEY",
            base64.b64encode(b"short-private").decode("ascii"),
            "configured_private_key_invalid",
        ),
        (
            "LICENSE_PUBLIC_KEY",
            base64.b64encode(b"short-public").decode("ascii"),
            "configured_public_key_invalid",
        ),
    ],
)
def test_invalid_key_formats_return_exit_code_3_without_echo(
    tmp_path,
    key,
    value,
    category,
):
    env_file, private_b64, public_b64, _public_raw = _write_valid_env(tmp_path)
    _replace_key(env_file, key, value)

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert exc_info.value.exit_code == EXIT_KEY_FORMAT
    assert exc_info.value.category == category
    assert value not in str(exc_info.value)
    assert private_b64 not in str(exc_info.value)
    assert public_b64 not in str(exc_info.value)


@pytest.mark.parametrize(
    ("missing_key", "category"),
    [
        ("LICENSE_PRIVATE_KEY", "configured_private_key_missing"),
        ("LICENSE_PUBLIC_KEY", "configured_public_key_missing"),
    ],
)
def test_missing_key_fields_return_exit_code_3(tmp_path, missing_key, category):
    env_file, *_ = _write_valid_env(tmp_path)
    remaining = [
        line
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if not line.startswith(f"{missing_key}=")
    ]
    env_file.write_text("\n".join(remaining) + "\n", encoding="utf-8")

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert exc_info.value.exit_code == EXIT_KEY_FORMAT
    assert exc_info.value.category == category


def test_public_key_fingerprint_hashes_raw_bytes_not_base64_text(tmp_path):
    env_file, _private_b64, public_b64, public_raw = _write_valid_env(tmp_path)

    fingerprint = verify_configured_keypair(env_file).public_key_sha256

    assert fingerprint == hashlib.sha256(public_raw).hexdigest()
    assert fingerprint != hashlib.sha256(public_b64.encode("ascii")).hexdigest()


def test_relative_path_is_rejected():
    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(Path("relative-license-server.env"))

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "env_file_path_not_absolute",
        EXIT_ENVIRONMENT,
    )


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(tmp_path / "missing.env")

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "env_file_unreadable",
        EXIT_ENVIRONMENT,
    )


def test_non_regular_file_is_rejected(tmp_path):
    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(tmp_path)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "env_file_not_regular",
        EXIT_ENVIRONMENT,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics required")
def test_symbolic_link_is_rejected(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    link = tmp_path / "linked.env"
    link.symlink_to(env_file)

    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(link)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "env_file_symlink_rejected",
        EXIT_ENVIRONMENT,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics required")
def test_group_or_other_permissions_are_rejected(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    env_file.chmod(0o640)

    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "env_file_permissions_too_open",
        EXIT_ENVIRONMENT,
    )


def test_duplicate_key_is_rejected(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    with env_file.open("a", encoding="utf-8") as stream:
        stream.write("LICENSE_SERVER_ENV=production\n")

    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "env_file_duplicate_key",
        EXIT_ENVIRONMENT,
    )


@pytest.mark.parametrize(
    "line",
    [
        "export LICENSE_SERVER_ENV=production",
        "LICENSE_SERVER_ENV=$(printf production)",
        "LICENSE_SERVER_ENV=${TARGET_ENV}",
        "LICENSE_SERVER_ENV=$TARGET_ENV",
        "LICENSE_SERVER_ENV=`printf production`",
        "LICENSE_SERVER_ENV=production <<EOF",
        "LICENSE_SERVER_ENV=production\\",
        "LICENSE_SERVER_ENV='production'",
        'LICENSE_SERVER_ENV="production"',
        "1INVALID=value",
        " LICENSE_SERVER_ENV=production",
        "LICENSE_SERVER_ENV =production",
        "LICENSE_SERVER_ENV",
    ],
)
def test_unsupported_shell_or_assignment_syntax_is_rejected(tmp_path, line):
    env_file = _write_env(tmp_path, [line])

    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(env_file)

    assert exc_info.value.exit_code == EXIT_ENVIRONMENT
    assert exc_info.value.category in {
        "env_file_invalid_key",
        "env_file_unsupported_quoting",
        "env_file_unsupported_syntax",
    }


def test_nul_and_invalid_utf8_are_rejected(tmp_path):
    env_file = tmp_path / "license-server.env"
    env_file.write_bytes(b"LICENSE_SERVER_ENV=production\x00\n")
    env_file.chmod(0o600)

    with pytest.raises(PreflightError) as nul_error:
        parse_restricted_env_file(env_file)
    assert nul_error.value.category == "env_file_contains_nul"

    env_file.write_bytes(b"LICENSE_SERVER_ENV=production\xff\n")
    with pytest.raises(PreflightError) as utf8_error:
        parse_restricted_env_file(env_file)
    assert utf8_error.value.category == "env_file_unreadable"


def test_blank_lines_comments_and_literal_value_after_first_equals_are_supported(
    tmp_path,
):
    env_file = _write_env(
        tmp_path,
        [
            "",
            "   # comment",
            "LICENSE_SERVER_ENV=production",
            "UNRELATED_LITERAL=one=two",
        ],
    )

    assert parse_restricted_env_file(env_file) == {
        "LICENSE_SERVER_ENV": "production"
    }


def test_unrelated_keys_are_ignored_and_never_exposed(tmp_path, capsys):
    env_file, *_ = _write_valid_env(tmp_path)
    sentinel = "UNRELATED-SENTINEL-SECRET"
    with env_file.open("a", encoding="utf-8") as stream:
        stream.write(f"UNRELATED_KEY={sentinel}\n")

    parsed = parse_restricted_env_file(env_file)
    report = verify_configured_keypair(env_file)

    assert set(parsed) == {
        "LICENSE_SERVER_ENV",
        "LICENSE_PRIVATE_KEY",
        "LICENSE_PUBLIC_KEY",
    }
    assert sentinel not in repr(parsed)
    assert sentinel not in repr(report)
    assert sentinel not in capsys.readouterr().out


def test_forced_invalid_signature_returns_exit_code_5(tmp_path, monkeypatch):
    env_file, *_ = _write_valid_env(tmp_path)
    original_loader = preflight.load_public_key_b64

    class FailingVerifier:
        def __init__(self, key):
            self._key = key

        def public_bytes(self, encoding, format):
            return self._key.public_bytes(encoding, format)

        def verify(self, signature, challenge):
            raise InvalidSignature

    monkeypatch.setattr(
        preflight,
        "load_public_key_b64",
        lambda value, *, source: FailingVerifier(
            original_loader(value, source=source)
        ),
    )

    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)

    assert (exc_info.value.category, exc_info.value.exit_code) == (
        "configured_sign_verify_failed",
        EXIT_SIGN_VERIFY,
    )


def test_verification_is_offline_database_free_and_does_not_launch_commands(
    tmp_path,
    monkeypatch,
):
    env_file, *_ = _write_valid_env(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("forbidden side effect")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    assert verify_configured_keypair(env_file).environment == "production"


def test_verification_does_not_write_or_modify_environment_file(tmp_path, monkeypatch):
    env_file, *_ = _write_valid_env(tmp_path)
    before_bytes = env_file.read_bytes()
    before_stat = env_file.stat()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("file write attempted")

    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)

    verify_configured_keypair(env_file)

    after_stat = env_file.stat()
    assert env_file.read_bytes() == before_bytes
    assert after_stat.st_mode == before_stat.st_mode
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns


def test_cli_default_success_output_is_exact_and_redacted(tmp_path, capsys, monkeypatch):
    env_file, private_b64, public_b64, public_raw = _write_valid_env(tmp_path)
    monkeypatch.setattr(preflight.secrets, "token_bytes", lambda size: b"C" * size)
    cli = _load_cli()

    exit_code = cli.main(["--env-file", str(env_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "environment_file=pass",
        "environment=production",
        "configured_private_key=pass",
        "configured_public_key=pass",
        "configured_keypair_match=pass",
        "configured_sign_verify=pass",
        f"public_key_sha256={hashlib.sha256(public_raw).hexdigest()}",
        "running_service_keypair=not_verified",
        "result=PASS",
    ]
    assert private_b64 not in captured.out
    assert public_b64 not in captured.out
    assert "C" * 32 not in captured.out
    assert "signature" not in captured.out


def test_cli_show_public_key_adds_only_the_public_key_line(tmp_path, capsys):
    env_file, _private_b64, public_b64, _public_raw = _write_valid_env(tmp_path)
    cli = _load_cli()

    assert cli.main(["--env-file", str(env_file)]) == 0
    default_lines = capsys.readouterr().out.splitlines()
    assert cli.main(["--env-file", str(env_file), "--show-public-key"]) == 0
    shown_lines = capsys.readouterr().out.splitlines()

    assert shown_lines == (
        default_lines[:-2]
        + [f"public_key_base64={public_b64}"]
        + default_lines[-2:]
    )


@pytest.mark.parametrize("exit_code", [2, 3, 4, 5])
def test_cli_expected_failures_route_category_and_exit_code(
    tmp_path,
    capsys,
    monkeypatch,
    exit_code,
):
    env_file, *_ = _write_valid_env(tmp_path)
    cli = _load_cli()
    monkeypatch.setattr(
        cli,
        "verify_configured_keypair",
        lambda _path: (_ for _ in ()).throw(
            PreflightError("controlled_failure", exit_code)
        ),
    )

    assert cli.main(["--env-file", str(env_file)]) == exit_code

    captured = capsys.readouterr()
    assert captured.out == "result=FAIL\n"
    assert captured.err == "error=controlled_failure\n"
    assert "Traceback" not in captured.out + captured.err


def test_cli_failure_output_never_echoes_supplied_secret(tmp_path, capsys):
    env_file, _private_b64, _public_b64, _public_raw = _write_valid_env(tmp_path)
    supplied_secret = "INVALID-PRIVATE-KEY-SENTINEL"
    _replace_key(env_file, "LICENSE_PRIVATE_KEY", supplied_secret)
    cli = _load_cli()

    assert cli.main(["--env-file", str(env_file)]) == EXIT_KEY_FORMAT

    captured = capsys.readouterr()
    assert supplied_secret not in captured.out + captured.err
    assert captured.out == "result=FAIL\n"
    assert captured.err == "error=configured_private_key_invalid\n"
    assert "Traceback" not in captured.out + captured.err


SENTINEL_KEYS = [
    'LOG_TEMPLATE="$HOST"',
    "SHELL_NOTE='internal'",
    "OTHER_COMMAND=`hostname`",
    "DOC_MARKER=<<EOF",
    'CONTINUED_VALUE=abc\\',
    "DOLLAR_VALUE=$UNUSED",
]

QUOTED_SENTINEL_VALUES = ['"$HOST"', "'internal'", "`hostname`", "<<EOF", "$UNUSED"]


def test_unrelated_keys_with_special_values_are_ignored(tmp_path):
    env_file, private_b64, public_b64, public_raw = _write_valid_env(tmp_path)
    for line in SENTINEL_KEYS:
        with env_file.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")

    report = verify_configured_keypair(env_file)

    assert report.environment == "production"
    assert report.public_key_sha256 == hashlib.sha256(public_raw).hexdigest()
    assert report.public_key_base64 == public_b64
    for sentinel in QUOTED_SENTINEL_VALUES:
        assert sentinel not in str(report)
        assert sentinel not in repr(report)


def test_duplicate_unrelated_keys_are_ignored(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    with env_file.open("a", encoding="utf-8") as stream:
        stream.write('UNRELATED=first\nUNRELATED="$SECOND"\n')

    assert verify_configured_keypair(env_file).environment == "production"


def test_allowed_key_rejects_double_quotes(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    _replace_key(env_file, "LICENSE_PUBLIC_KEY", '"value"')
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.category == "env_file_unsupported_quoting"


def test_allowed_key_rejects_single_quotes(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    _replace_key(env_file, "LICENSE_PUBLIC_KEY", "'value'")
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.category == "env_file_unsupported_quoting"


def test_allowed_key_rejects_variable_expansion(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    _replace_key(env_file, "LICENSE_PUBLIC_KEY", "$VARIABLE")
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.category == "env_file_unsupported_syntax"


def test_allowed_key_rejects_backtick_command(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    _replace_key(env_file, "LICENSE_PUBLIC_KEY", "`command`")
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.category == "env_file_unsupported_syntax"


def test_allowed_key_rejects_heredoc_marker(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    _replace_key(env_file, "LICENSE_PUBLIC_KEY", "<<EOF")
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.category == "env_file_unsupported_syntax"


def test_allowed_key_rejects_trailing_backslash(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    _replace_key(env_file, "LICENSE_PUBLIC_KEY", "trailing\\")
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.category == "env_file_unsupported_syntax"


def test_duplicate_allowed_key_is_rejected(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    with env_file.open("a", encoding="utf-8") as stream:
        stream.write("LICENSE_PUBLIC_KEY=duplicate\n")
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.category == "env_file_duplicate_key"


def test_export_line_is_rejected(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    _replace_key(env_file, "LICENSE_SERVER_ENV", "export production")
    with pytest.raises(PreflightError) as exc_info:
        verify_configured_keypair(env_file)
    assert exc_info.value.exit_code == EXIT_ENVIRONMENT


def test_missing_equals_line_is_rejected(tmp_path):
    env_file = _write_env(tmp_path, ["NO_EQUALS_LINE"])
    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(env_file)
    assert exc_info.value.category == "env_file_unsupported_syntax"


def test_line_with_leading_space_key_is_rejected(tmp_path):
    env_file = _write_env(tmp_path, [" BAD_KEY=value"])
    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(env_file)
    assert exc_info.value.category == "env_file_invalid_key"


def test_line_with_hyphen_key_is_rejected(tmp_path):
    env_file = _write_env(tmp_path, ["BAD-KEY=value"])
    with pytest.raises(PreflightError) as exc_info:
        parse_restricted_env_file(env_file)
    assert exc_info.value.category == "env_file_invalid_key"


def test_name_similar_to_allowed_key_is_ignored(tmp_path):
    env_file, *_ = _write_valid_env(tmp_path)
    with env_file.open("a", encoding="utf-8") as stream:
        stream.write(
            'LICENSE_PUBLIC_KEY_BACKUP="$IGNORED"\n'
            "LICENSE_PRIVATE_KEY_NOTE='ignored'\n"
        )

    assert verify_configured_keypair(env_file).environment == "production"


def test_cli_success_with_unrelated_special_values(tmp_path, capsys):
    env_file, private_b64, public_b64, public_raw = _write_valid_env(tmp_path)
    for line in SENTINEL_KEYS:
        with env_file.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")

    cli = _load_cli()
    exit_code = cli.main(["--env-file", str(env_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.splitlines() == [
        "environment_file=pass",
        "environment=production",
        "configured_private_key=pass",
        "configured_public_key=pass",
        "configured_keypair_match=pass",
        "configured_sign_verify=pass",
        f"public_key_sha256={hashlib.sha256(public_raw).hexdigest()}",
        "running_service_keypair=not_verified",
        "result=PASS",
    ]
    assert private_b64 not in captured.out
    assert public_b64 not in captured.out
    for sentinel in QUOTED_SENTINEL_VALUES:
        assert sentinel not in captured.out + captured.err


def test_cli_unexpected_failure_prints_only_exception_type(
    tmp_path,
    capsys,
    monkeypatch,
):
    env_file, *_ = _write_valid_env(tmp_path)
    cli = _load_cli()
    secret_message = "UNEXPECTED-SECRET-SENTINEL"

    def fail(_path):
        raise RuntimeError(secret_message)

    monkeypatch.setattr(cli, "verify_configured_keypair", fail)

    assert cli.main(["--env-file", str(env_file)]) == 1

    captured = capsys.readouterr()
    assert captured.out == "result=FAIL\n"
    assert captured.err == "error=unexpected_failure:RuntimeError\n"
    assert secret_message not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err


# ---------------------------------------------------------------------------
# POSIX FIFO regression tests  (subprocess-isolated, timeout=5)
# ---------------------------------------------------------------------------
# On POSIX, os.open(path, os.O_RDONLY) on a FIFO (named pipe) blocks
# indefinitely until a writer opens the same FIFO.  _read_secure_text_file()
# must add O_NONBLOCK to the open flags so that the fstat+S_ISREG check
# following the open can reject the FIFO quickly.
#
# These tests run in an isolated subprocess so that a hang kills only
# the child process, never the pytest runner.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="FIFO/named-pipe only on POSIX")
def test_fifo_used_as_env_file_exits_without_hanging(tmp_path: Path) -> None:
    """Regression: env-file FIFO must not hang os.open()."""
    fifo = tmp_path / "license-server.env"
    os.mkfifo(fifo)
    fifo.chmod(0o600)

    proc = subprocess.run(
        [sys.executable, str(_CLI_SCRIPT), "--env-file", str(fifo)],
        capture_output=True,
        timeout=5,
        cwd=_REPO_ROOT,
    )
    assert proc.returncode == EXIT_ENVIRONMENT
    assert "env_file_not_regular" in (proc.stdout + proc.stderr).decode()


@pytest.mark.skipif(os.name != "posix", reason="FIFO/named-pipe only on POSIX")
def test_fifo_used_as_private_key_file_exits_without_hanging(tmp_path: Path) -> None:
    """Regression: private-key-file FIFO must not hang os.open()."""
    private_fifo = tmp_path / "private-key-fifo"
    os.mkfifo(private_fifo)
    private_fifo.chmod(0o600)

    env_file, private_b64, public_b64, _public_raw = _write_valid_env(tmp_path)
    _set_private_key_sources(
        env_file, inline=None, private_key_file=str(private_fifo)
    )

    proc = subprocess.run(
        [sys.executable, str(_CLI_SCRIPT), "--env-file", str(env_file)],
        capture_output=True,
        timeout=5,
        cwd=_REPO_ROOT,
    )
    assert proc.returncode == EXIT_KEY_FORMAT
    assert "configured_private_key_file_not_regular" in (
        proc.stdout + proc.stderr
    ).decode()


@pytest.mark.skipif(os.name != "posix", reason="FIFO/named-pipe only on POSIX")
def test_regular_file_not_affected_by_fifo_regression_change(tmp_path: Path) -> None:
    """Positive control: a normal env+key pair still passes with O_NONBLOCK."""
    env_file, private_b64, public_b64, _public_raw = _write_valid_env(tmp_path)

    proc = subprocess.run(
        [sys.executable, str(_CLI_SCRIPT), "--env-file", str(env_file)],
        capture_output=True,
        timeout=5,
        cwd=_REPO_ROOT,
    )
    assert proc.returncode == 0
    stdout = proc.stdout.decode()
    assert "result=PASS" in stdout
    assert private_b64 not in stdout
    assert public_b64 not in stdout
