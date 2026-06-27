import sqlite3
from datetime import datetime, timedelta, timezone

from license_server.db import connect
from license_server.signer import datetime_text
from tests.license_server.test_license_server import _client, _register_payload


def _payment_payload(device_hash="device-a", channel="wechat_pay"):
    return {
        "product_id": "whut-campus-auto-login",
        "device_fingerprint_hash": device_hash,
        "payment_channel": channel,
        "plan": "yearly",
    }


def test_create_payment_order_returns_unpaid_order_without_provider_urls(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.post("/payment/create", json=_payment_payload())

    assert response.status_code == 200
    payload = response.json()
    assert payload["order_id"]
    assert payload["amount"] == "9.9"
    assert payload["currency"] == "CNY"
    assert payload["payment_channel"] == "wechat_pay"
    assert payload["order_status"] == "created"
    assert payload["payment_status"] == "unpaid"
    assert payload["provider_status"] == "not_configured"
    assert payload["payment_url"] is None
    assert payload["qr_code_url"] is None
    assert payload["message"] == "order_created_payment_provider_not_configured"


def test_create_payment_order_rejects_client_controlled_amount(tmp_path):
    client, _public_key = _client(tmp_path)
    payload = _payment_payload()
    payload["amount"] = "0.01"

    response = client.post("/payment/create", json=payload)

    assert response.status_code == 422


def test_create_payment_order_rejects_invalid_channel(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.post("/payment/create", json=_payment_payload(channel="cash"))

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid_payment_channel"


def test_status_returns_unpaid_order_for_matching_device(tmp_path):
    client, _public_key = _client(tmp_path)
    created = client.post("/payment/create", json=_payment_payload()).json()

    response = client.get(
        "/payment/status",
        params={
            "product_id": "whut-campus-auto-login",
            "order_id": created["order_id"],
            "device_fingerprint_hash": "device-a",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["order_id"] == created["order_id"]
    assert payload["order_status"] == "created"
    assert payload["payment_status"] == "unpaid"
    assert payload["provider_status"] == "not_configured"
    assert payload["amount"] == "9.9"
    assert payload["currency"] == "CNY"
    assert payload["payment_channel"] == "wechat_pay"
    assert payload["paid_at"] is None
    assert payload["message"] == "order_waiting_for_payment_provider"


def test_status_returns_404_for_missing_order(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.get(
        "/payment/status",
        params={
            "product_id": "whut-campus-auto-login",
            "order_id": "missing",
            "device_fingerprint_hash": "device-a",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "order_not_found"


def test_status_rejects_device_mismatch(tmp_path):
    client, _public_key = _client(tmp_path)
    created = client.post("/payment/create", json=_payment_payload()).json()

    response = client.get(
        "/payment/status",
        params={
            "product_id": "whut-campus-auto-login",
            "order_id": created["order_id"],
            "device_fingerprint_hash": "other-device",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "order_device_mismatch"


def test_unpaid_payment_order_does_not_create_paid_license(tmp_path):
    client, _public_key = _client(tmp_path)
    client.post("/device/register", json=_register_payload())

    client.post("/payment/create", json=_payment_payload())
    refreshed = client.post(
        "/license/refresh",
        json={
            "product_id": "whut-campus-auto-login",
            "device_fingerprint_hash": "device-a",
            "app_version": "0.1.0",
        },
    ).json()

    assert refreshed["license_type"] == "trial"
    assert refreshed["status"] == "trial_active"


def test_create_payment_order_reuses_open_unpaid_order(tmp_path):
    client, _public_key = _client(tmp_path)

    first = client.post("/payment/create", json=_payment_payload()).json()
    second = client.post("/payment/create", json=_payment_payload(channel="alipay")).json()

    assert second["order_id"] == first["order_id"]
    assert second["payment_channel"] == "wechat_pay"


def test_status_lazily_expires_unpaid_order(tmp_path):
    client, _public_key = _client(tmp_path)
    created = client.post("/payment/create", json=_payment_payload()).json()
    database_path = tmp_path / "license.sqlite3"
    expired_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    with connect(database_path) as connection:
        connection.execute(
            "UPDATE payment_orders SET expire_at = ? WHERE order_id = ?",
            (datetime_text(expired_at), created["order_id"]),
        )
        connection.commit()

    response = client.get(
        "/payment/status",
        params={
            "product_id": "whut-campus-auto-login",
            "order_id": created["order_id"],
            "device_fingerprint_hash": "device-a",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["order_status"] == "expired"
    assert payload["payment_status"] == "unpaid"
    assert payload["message"] == "order_expired"


def test_paid_active_device_cannot_create_payment_order(tmp_path):
    client, _public_key = _client(tmp_path)
    client.post("/device/register", json=_register_payload())
    client.post(
        "/admin/grant",
        headers={"X-License-Admin-Token": "admin-token"},
        json={
            "device_fingerprint_hash": "device-a",
            "license_days": 365,
            "reason": "dev grant",
        },
    )

    response = client.post("/payment/create", json=_payment_payload())

    assert response.status_code == 409
    assert response.json()["detail"] == "already_paid_active"


def test_payment_order_schema_exists_without_campus_account_columns(tmp_path):
    client, _public_key = _client(tmp_path)
    client.post("/payment/create", json=_payment_payload())

    with sqlite3.connect(tmp_path / "license.sqlite3") as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(payment_orders)").fetchall()
        }

    assert "campus_account" not in columns
    assert "campus_password" not in columns
