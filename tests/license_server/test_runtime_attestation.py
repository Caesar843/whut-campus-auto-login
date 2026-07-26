import base64
import asyncio
import json
import os
import socket
import struct
import sys
from datetime import datetime, timezone

import pytest

from license_server.app import create_app
from license_server.config import load_config
from license_server.signer import LicenseSigningIdentity
from tests.license_server.test_license_server import _production_env


PRIVATE_KEY_B64 = base64.b64encode(bytes(range(32))).decode("ascii")
CHALLENGE = base64.urlsafe_b64encode(b"c" * 32).decode("ascii").rstrip("=")


def _runtime():
    import license_server.runtime_attestation as runtime

    return runtime


def test_request_requires_exact_canonical_shape():
    runtime = _runtime()
    expected = runtime.canonical_json_bytes(
        {
            "challenge_b64url": CHALLENGE,
            "protocol": runtime.PROTOCOL,
        }
    )

    assert runtime.parse_request(expected) == CHALLENGE

    rejected = (
        b"\xef\xbb\xbf" + expected,
        expected + b" ",
        expected.replace(b"{", b'{ "unused":1,', 1),
        b'{"challenge_b64url":"' + CHALLENGE.encode() + b'",'
        b'"challenge_b64url":"' + CHALLENGE.encode() + b'",'
        b'"protocol":"whut-license-runtime-attestation-v1"}',
        runtime.canonical_json_bytes(
            {
                "challenge_b64url": CHALLENGE + "=",
                "protocol": runtime.PROTOCOL,
            }
        ),
        runtime.canonical_json_bytes(
            {
                "challenge_b64url": base64.urlsafe_b64encode(b"x" * 31)
                .decode("ascii")
                .rstrip("="),
                "protocol": runtime.PROTOCOL,
            }
        ),
        b"[]",
        b"\xff",
        b"x" * (runtime.MAX_REQUEST_BYTES + 1),
    )
    for body in rejected:
        with pytest.raises(runtime.RuntimeAttestationError):
            runtime.parse_request(body)


def test_frame_limits_are_strict():
    runtime = _runtime()

    assert runtime.encode_frame(b"ok", maximum=2) == b"\x00\x00\x00\x02ok"
    with pytest.raises(runtime.RuntimeAttestationError):
        runtime.encode_frame(b"too long", maximum=2)
    with pytest.raises(runtime.RuntimeAttestationError):
        runtime.decode_frame_header(b"\x00\x00\x00\x00", maximum=10)
    with pytest.raises(runtime.RuntimeAttestationError):
        runtime.decode_frame_header(b"\x00\x00\x00\x0b", maximum=10)


def test_replay_cache_rejects_duplicates_and_fails_closed_when_full():
    runtime = _runtime()
    now = [100.0]
    cache = runtime.ReplayCache(capacity=2, ttl_seconds=60, clock=lambda: now[0])

    cache.consume("a")
    with pytest.raises(runtime.RuntimeAttestationError, match="challenge_replayed"):
        cache.consume("a")
    cache.consume("b")
    with pytest.raises(runtime.RuntimeAttestationError, match="replay_cache_full"):
        cache.consume("c")

    now[0] = 161.0
    cache.consume("c")


def test_payload_has_exact_fields_and_sixty_second_lifetime():
    runtime = _runtime()
    identity = LicenseSigningIdentity(PRIVATE_KEY_B64)
    state = runtime.RuntimeAttestationState(
        instance_id="a" * 22,
        pid=123,
        process_start_ticks="456",
        process_started_at="2026-07-26T00:00:00Z",
        service_uid=789,
        source_commit="b" * 40,
        app_version="0.1.0",
        public_key_sha256=identity.public_key_sha256,
    )
    issued_at = datetime(2026, 7, 26, 1, 2, 3, tzinfo=timezone.utc)

    payload = runtime.build_payload(state, CHALLENGE, issued_at)

    assert set(payload) == runtime.SIGNED_PAYLOAD_FIELDS
    assert payload["issued_at"] == "2026-07-26T01:02:03Z"
    assert payload["expires_at"] == "2026-07-26T01:03:03Z"
    assert payload["challenge_b64url"] == CHALLENGE


def test_enabled_platform_gate_is_import_safe_and_fail_closed(monkeypatch):
    runtime = _runtime()

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    with pytest.raises(RuntimeError, match="runtime_attestation_linux_required"):
        runtime.require_supported_production_platform()

    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime, "is_wsl", lambda: True)
    with pytest.raises(RuntimeError, match="runtime_attestation_wsl_not_supported"):
        runtime.require_supported_production_platform()


def test_response_body_is_canonical_and_within_limit():
    runtime = _runtime()
    response = runtime.canonical_json_bytes(
        {
            "app_version": "0.1.0",
            "challenge_b64url": CHALLENGE,
            "expires_at": "2026-07-26T01:03:03Z",
            "instance_id": "a" * 22,
            "issued_at": "2026-07-26T01:02:03Z",
            "pid": 123,
            "process_start_ticks": "456",
            "process_started_at": "2026-07-26T00:00:00Z",
            "protocol": "whut-license-runtime-attestation-v1",
            "public_key_sha256": "b" * 64,
            "service_uid": 789,
            "signature_b64url": "c" * 86,
            "source_commit": "d" * 40,
        }
    )

    decoded = runtime.parse_response(response)

    assert decoded["pid"] == 123
    with pytest.raises(runtime.RuntimeAttestationError):
        runtime.parse_response(response + b"\n")


def test_runtime_attestation_config_defaults_off_and_requires_production(
    tmp_path,
    monkeypatch,
):
    default_config = load_config(
        _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    )
    assert default_config.runtime_attestation_enabled is False
    assert default_config.runtime_source_commit is None

    development = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    development["LICENSE_SERVER_ENV"] = "development"
    development["LICENSE_RUNTIME_ATTESTATION_ENABLED"] = "true"
    development["LICENSE_RUNTIME_SOURCE_COMMIT"] = "a" * 40
    with pytest.raises(RuntimeError, match="production"):
        load_config(development)

    enabled = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    enabled["LICENSE_RUNTIME_ATTESTATION_ENABLED"] = "true"
    enabled["LICENSE_RUNTIME_SOURCE_COMMIT"] = "a" * 40
    monkeypatch.setattr(
        "license_server.runtime_attestation.require_supported_production_platform",
        lambda: None,
    )
    config = load_config(enabled)
    assert config.runtime_attestation_enabled is True
    assert config.runtime_source_commit == "a" * 40


def test_runtime_attestation_config_fails_closed(tmp_path):
    env = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    env["LICENSE_RUNTIME_ATTESTATION_ENABLED"] = "true"
    env["LICENSE_RUNTIME_SOURCE_COMMIT"] = "2c555007"

    with pytest.raises(RuntimeError, match="SOURCE_COMMIT"):
        load_config(env)


def test_default_app_has_no_runtime_attestation_http_route(tmp_path):
    app = create_app(
        database_path=tmp_path / "license.sqlite3",
        private_key_b64=PRIVATE_KEY_B64,
    )

    assert not any(
        route.path.startswith("/internal/runtime-attestation")
        for route in app.routes
    )
    assert not hasattr(app.state, "runtime_attestation_server")


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux AF_UNIX and SO_PEERCRED",
)
def test_test_mode_unix_socket_round_trip_and_peer_check(tmp_path):
    runtime = _runtime()

    async def scenario():
        server = runtime.RuntimeAttestationServer(
            signing_identity=LicenseSigningIdentity(PRIVATE_KEY_B64),
            source_commit="a" * 40,
            socket_path=tmp_path / "attestation.sock",
            expected_peer_uid=os.getuid(),
            enforce_production_path=False,
        )
        await server.start()
        request = runtime.canonical_json_bytes(
            {
                "challenge_b64url": CHALLENGE,
                "protocol": runtime.PROTOCOL,
            }
        )

        def exchange():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(runtime.IO_TIMEOUT_SECONDS)
                client.connect(str(tmp_path / "attestation.sock"))
                client.sendall(
                    runtime.encode_frame(
                        request,
                        maximum=runtime.MAX_REQUEST_BYTES,
                    )
                )
                client.shutdown(socket.SHUT_WR)
                header = client.recv(4)
                length = struct.unpack(">I", header)[0]
                body = bytearray()
                while len(body) < length:
                    body.extend(client.recv(length - len(body)))
                assert client.recv(1) == b""
                return bytes(body)

        try:
            response = await asyncio.to_thread(exchange)
            assert runtime.parse_response(response)["challenge_b64url"] == CHALLENGE
        finally:
            await server.close()

    asyncio.run(scenario())
