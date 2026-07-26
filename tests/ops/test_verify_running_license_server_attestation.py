import base64
import stat
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from license_server.signer import LicenseSigningIdentity


PRIVATE_KEY_B64 = base64.b64encode(bytes(range(32))).decode("ascii")
CHALLENGE = base64.urlsafe_b64encode(b"c" * 32).decode("ascii").rstrip("=")
INSTANCE_ID = base64.urlsafe_b64encode(b"i" * 16).decode("ascii").rstrip("=")


def _ops():
    from scripts.ops import verify_running_license_server_attestation as ops

    return ops


def _signed_response(*, issued_at: datetime, expires_at: datetime | None = None):
    import license_server.runtime_attestation as runtime

    identity = LicenseSigningIdentity(PRIVATE_KEY_B64)
    state = runtime.RuntimeAttestationState(
        instance_id=INSTANCE_ID,
        pid=123,
        process_start_ticks="456",
        process_started_at="2026-07-26T00:00:00Z",
        service_uid=789,
        source_commit="b" * 40,
        app_version="0.1.0",
        public_key_sha256=identity.public_key_sha256,
    )
    payload = runtime.build_payload(state, CHALLENGE, issued_at)
    if expires_at is not None:
        payload["expires_at"] = runtime.utc_text(expires_at)
    signature = identity.sign_runtime_attestation(
        runtime.canonical_json_bytes(payload)
    )
    response = {
        **payload,
        "signature_b64url": base64.urlsafe_b64encode(signature)
        .decode("ascii")
        .rstrip("="),
    }
    public_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(PRIVATE_KEY_B64)
    ).public_key()
    return runtime.canonical_json_bytes(response), public_key


def test_cli_validates_signature_identity_and_exact_lifetime():
    ops = _ops()
    now = datetime(2026, 7, 26, 1, 2, 4, tzinfo=timezone.utc)
    body, public_key = _signed_response(
        issued_at=datetime(2026, 7, 26, 1, 2, 3, tzinfo=timezone.utc)
    )

    payload = ops.verify_attestation_response(
        body,
        challenge_b64url=CHALLENGE,
        expected_public_key=public_key,
        expected_pid=123,
        expected_uid=789,
        expected_start_ticks="456",
        expected_source_commit="b" * 40,
        expected_app_version="0.1.0",
        now=now,
    )

    assert payload["public_key_sha256"] == ops.public_key_fingerprint(public_key)


@pytest.mark.parametrize(
    ("issued_delta", "expires_delta"),
    [
        (timedelta(seconds=6), timedelta(seconds=66)),
        (timedelta(), timedelta(seconds=61)),
        (timedelta(seconds=-61), timedelta(seconds=-1)),
    ],
)
def test_cli_rejects_future_extended_and_expired_proofs(
    issued_delta,
    expires_delta,
):
    ops = _ops()
    now = datetime(2026, 7, 26, 1, 2, 3, tzinfo=timezone.utc)
    body, public_key = _signed_response(
        issued_at=now + issued_delta,
        expires_at=now + expires_delta,
    )

    with pytest.raises(ops.AuditError):
        ops.verify_attestation_response(
            body,
            challenge_b64url=CHALLENGE,
            expected_public_key=public_key,
            expected_pid=123,
            expected_uid=789,
            expected_start_ticks="456",
            expected_source_commit="b" * 40,
            expected_app_version="0.1.0",
            now=now,
        )


def test_cli_rejects_tampered_signature_and_identity():
    ops = _ops()
    now = datetime(2026, 7, 26, 1, 2, 4, tzinfo=timezone.utc)
    body, public_key = _signed_response(
        issued_at=datetime(2026, 7, 26, 1, 2, 3, tzinfo=timezone.utc)
    )

    for kwargs in (
        {"expected_pid": 999},
        {"expected_uid": 999},
        {"expected_start_ticks": "999"},
        {"expected_source_commit": "c" * 40},
        {"expected_app_version": "9.9.9"},
        {"challenge_b64url": "x" * 43},
    ):
        values = {
            "challenge_b64url": CHALLENGE,
            "expected_public_key": public_key,
            "expected_pid": 123,
            "expected_uid": 789,
            "expected_start_ticks": "456",
            "expected_source_commit": "b" * 40,
            "expected_app_version": "0.1.0",
            "now": now,
            **kwargs,
        }
        with pytest.raises(ops.AuditError):
            ops.verify_attestation_response(body, **values)

    tampered = body.replace(b'"app_version":"0.1.0"', b'"app_version":"0.1.1"')
    with pytest.raises(ops.AuditError):
        ops.verify_attestation_response(
            tampered,
            challenge_b64url=CHALLENGE,
            expected_public_key=public_key,
            expected_pid=123,
            expected_uid=789,
            expected_start_ticks="456",
            expected_source_commit="b" * 40,
            expected_app_version="0.1.1",
            now=now,
        )


def test_public_key_fixture_is_raw_ed25519():
    _body, public_key = _signed_response(
        issued_at=datetime(2026, 7, 26, 1, 2, 3, tzinfo=timezone.utc)
    )

    assert len(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)) == 32


def test_cli_accepts_only_the_two_fixed_modes():
    ops = _ops()

    assert ops._parser().parse_args(["--startup-gate"]).startup_gate is True
    assert ops._parser().parse_args(["--live-audit"]).live_audit is True
    for arguments in (
        [],
        ["--live-audit", "--socket", "/tmp/other.sock"],
        ["--startup-gate", "--service", "other.service"],
        ["--live-audit", "--public-key", "/tmp/key"],
    ):
        with pytest.raises(SystemExit):
            ops._parser().parse_args(arguments)


def test_startup_gate_checks_fixed_commit_tree_and_service_write_boundary(
    monkeypatch,
):
    ops = _ops()
    calls = []
    monkeypatch.setattr(ops, "require_supported_production_platform", lambda: None)
    monkeypatch.setattr(ops.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv(ops.SOURCE_COMMIT_ENV, "a" * 40)
    monkeypatch.setattr(ops, "_repository_state", lambda: "a" * 40)
    monkeypatch.setattr(
        ops,
        "_validate_deployment_security",
        lambda: calls.append("security"),
    )
    monkeypatch.setattr(
        ops,
        "_service_account_cannot_write",
        lambda: calls.append("write"),
    )

    ops.startup_gate()

    assert calls == ["security", "write"]


def test_root_controlled_path_rejects_symlink_nonroot_and_unsafe_mode(
    monkeypatch,
):
    ops = _ops()
    path = ops.Path("/fixed")

    for mode, uid in (
        (stat.S_IFLNK | 0o777, 0),
        (stat.S_IFREG | 0o600, 1000),
        (stat.S_IFREG | 0o620, 0),
    ):
        monkeypatch.setattr(
            ops.os,
            "lstat",
            lambda _path, mode=mode, uid=uid: SimpleNamespace(
                st_mode=mode,
                st_uid=uid,
            ),
        )
        with pytest.raises(ops.AuditError):
            ops._validate_root_controlled_path(path, kind="file")

    monkeypatch.setattr(
        ops.os,
        "lstat",
        lambda _path: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=0,
        ),
    )
    ops._validate_root_controlled_path(path, kind="file")
