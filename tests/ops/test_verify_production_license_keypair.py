import base64
import hashlib
import importlib.util
import os
import socket
import sqlite3
import subprocess
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
    PreflightError,
    parse_restricted_env_file,
    verify_configured_keypair,
)


CLI_PATH = Path("scripts/ops/verify_production_license_keypair.py")


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


def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "verify_production_license_keypair",
        CLI_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
