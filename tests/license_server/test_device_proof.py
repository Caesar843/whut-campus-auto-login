from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from license_server.app import create_app
from license_server.db import connect
from license_server.device_proof import bearer_token, verify_device_proof_token
from license_server.signer import sign_license_payload, verify_license_token_payload
from tests.license_server.test_license_server import _private_key_b64, _register_payload


def test_valid_token_proves_device(tmp_path):
    private_key_b64, token = _registered_token(tmp_path)

    with connect(tmp_path / "license.sqlite3") as connection:
        proof = verify_device_proof_token(
            connection,
            signed_license_token=token,
            private_key_b64=private_key_b64,
        )

    assert proof.device_fingerprint_hash == "device-a"
    assert proof.license_id > 0


def test_tampered_token_is_rejected(tmp_path):
    private_key_b64, token = _registered_token(tmp_path)

    with connect(tmp_path / "license.sqlite3") as connection:
        with pytest.raises(HTTPException) as exc_info:
            verify_device_proof_token(
                connection,
                signed_license_token=_tamper(token),
                private_key_b64=private_key_b64,
            )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid_device_proof"


def test_malformed_non_ascii_token_is_rejected(tmp_path):
    private_key_b64, _token = _registered_token(tmp_path)

    with connect(tmp_path / "license.sqlite3") as connection:
        with pytest.raises(HTTPException) as exc_info:
            verify_device_proof_token(
                connection,
                signed_license_token="签名.invalid",
                private_key_b64=private_key_b64,
            )

    assert exc_info.value.status_code == 401


def test_wrong_product_token_is_rejected(tmp_path):
    private_key_b64, token = _registered_token(tmp_path)
    payload = verify_license_token_payload(token, private_key_b64=private_key_b64)
    payload["product_id"] = "other-product"
    token = sign_license_payload(payload, private_key_b64=private_key_b64)

    with connect(tmp_path / "license.sqlite3") as connection:
        with pytest.raises(HTTPException) as exc_info:
            verify_device_proof_token(
                connection,
                signed_license_token=token,
                private_key_b64=private_key_b64,
            )

    assert exc_info.value.status_code == 401


def test_missing_device_hash_is_rejected(tmp_path):
    private_key_b64, token = _registered_token(tmp_path)
    payload = verify_license_token_payload(token, private_key_b64=private_key_b64)
    payload["device_fingerprint_hash"] = "missing-device"
    token = sign_license_payload(payload, private_key_b64=private_key_b64)

    with connect(tmp_path / "license.sqlite3") as connection:
        with pytest.raises(HTTPException) as exc_info:
            verify_device_proof_token(
                connection,
                signed_license_token=token,
                private_key_b64=private_key_b64,
            )

    assert exc_info.value.status_code == 401


def test_license_id_must_belong_to_device(tmp_path):
    private_key_b64 = _private_key_b64()
    client = _proof_client(tmp_path, private_key_b64)
    first = client.post("/device/register", json=_register_payload("device-a")).json()
    second = client.post("/device/register", json=_register_payload("device-b")).json()
    payload = verify_license_token_payload(
        first["signed_license_token"],
        private_key_b64=private_key_b64,
    )
    payload["license_id"] = second["license_id"]
    token = sign_license_payload(payload, private_key_b64=private_key_b64)

    with connect(tmp_path / "license.sqlite3") as connection:
        with pytest.raises(HTTPException) as exc_info:
            verify_device_proof_token(
                connection,
                signed_license_token=token,
                private_key_b64=private_key_b64,
            )

    assert exc_info.value.status_code == 401


def test_expired_trial_token_can_still_prove_device(tmp_path):
    private_key_b64, token = _registered_token(tmp_path)
    payload = verify_license_token_payload(token, private_key_b64=private_key_b64)
    payload["expires_at"] = _time_text(datetime.now(timezone.utc) - timedelta(days=1))
    token = sign_license_payload(payload, private_key_b64=private_key_b64)

    with connect(tmp_path / "license.sqlite3") as connection:
        proof = verify_device_proof_token(
            connection,
            signed_license_token=token,
            private_key_b64=private_key_b64,
        )

    assert proof.device_fingerprint_hash == "device-a"


def test_revoked_license_is_rejected(tmp_path):
    private_key_b64, token = _registered_token(tmp_path)
    with connect(tmp_path / "license.sqlite3") as connection:
        connection.execute("UPDATE licenses SET status = 'revoked'")
        connection.commit()

    with connect(tmp_path / "license.sqlite3") as connection:
        with pytest.raises(HTTPException) as exc_info:
            verify_device_proof_token(
                connection,
                signed_license_token=token,
                private_key_b64=private_key_b64,
            )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "device_proof_revoked"


def test_missing_and_non_bearer_authorization_are_rejected():
    for value in ("", "Basic token"):
        with pytest.raises(HTTPException) as exc_info:
            bearer_token(value)
        assert exc_info.value.status_code == 401
        assert "token" not in str(exc_info.value.detail).lower()


def _registered_token(tmp_path):
    private_key_b64 = _private_key_b64()
    client = _proof_client(tmp_path, private_key_b64)
    payload = client.post("/device/register", json=_register_payload()).json()
    return private_key_b64, payload["signed_license_token"]


def _tamper(token: str) -> str:
    replacement = "A" if token[0] != "A" else "B"
    return replacement + token[1:]


def _proof_client(tmp_path, private_key_b64: str) -> TestClient:
    return TestClient(
        create_app(
            database_path=tmp_path / "license.sqlite3",
            private_key_b64=private_key_b64,
            admin_token="admin-token",
        )
    )


def _time_text(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")
