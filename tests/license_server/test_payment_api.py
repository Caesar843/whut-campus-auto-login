import sqlite3
from pathlib import Path

from license_server.db import connect
from license_server.config import WechatPayConfig
from license_server.payment_gateway import MockPaymentGateway
from tests.license_server.test_license_server import _client, _register_payload


MOCK_TOKEN = "mockR4ndomValue123456"


def test_create_order_uses_bearer_token_and_returns_mock_code_url(tmp_path):
    client, token = _registered_mock_client(tmp_path)

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["product_code"] == "annual_v1"
    assert payload["amount_fen"] == 990
    assert payload["currency"] == "CNY"
    assert payload["provider"] == "mock"
    assert payload["status"] == "WAITING_PAYMENT"
    assert payload["code_url"] == f"mock://whut-payment/{payload['order_id']}"
    assert "device_fingerprint_hash" not in payload
    assert "id" not in payload


def test_create_order_rejects_client_controlled_amount(tmp_path):
    client, token = _registered_mock_client(tmp_path)

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1", "amount_fen": 1},
    )

    assert response.status_code == 422


def test_create_order_requires_configured_provider(tmp_path):
    client, _public_key = _client(tmp_path)
    token = client.post("/device/register", json=_register_payload()).json()[
        "signed_license_token"
    ]

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "payment_provider_not_configured"


def test_query_order_requires_configured_provider(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.get("/api/v1/payment/orders/missing")

    assert response.status_code == 503
    assert response.json()["detail"] == "payment_provider_not_configured"


def test_wechat_provider_uses_injected_gateway_and_notify_url(tmp_path):
    gateway = CapturingGateway()
    config = WechatPayConfig(
        app_id="wx-test-app",
        mch_id="1900000109",
        merchant_serial_no="merchant-serial",
        merchant_private_key_path=Path("unused-merchant-key.pem"),
        public_key_id="wechat-public-key-id",
        public_key_path=Path("unused-wechat-key.pem"),
        api_v3_key=b"a" * 32,
        notify_url="https://pay.example.test/wechat/notify",
    )
    client, _public_key = _client(
        tmp_path,
        payment_provider="wechat_native",
        wechat_pay_config=config,
        payment_gateway=gateway,
    )
    token = client.post("/device/register", json=_register_payload()).json()[
        "signed_license_token"
    ]

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    )

    assert response.status_code == 200
    assert response.json()["provider"] == "wechat_native"
    assert response.json()["code_url"].startswith("mock://whut-payment/")
    assert gateway.request.notify_url == config.notify_url


def test_wechat_provider_without_config_refuses_startup(tmp_path):
    import pytest

    with pytest.raises(RuntimeError, match="wechat_native configuration"):
        _client(tmp_path, payment_provider="wechat_native")


def test_same_device_reuses_open_order(tmp_path):
    client, token = _registered_mock_client(tmp_path)

    first = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()
    second = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()

    assert second["order_id"] == first["order_id"]


def test_different_devices_create_separate_orders(tmp_path):
    client, first_token = _registered_mock_client(tmp_path)
    second_token = client.post("/device/register", json=_register_payload("device-b")).json()[
        "signed_license_token"
    ]

    first = client.post(
        "/api/v1/payment/orders",
        headers=_auth(first_token),
        json={"product_code": "annual_v1"},
    ).json()
    second = client.post(
        "/api/v1/payment/orders",
        headers=_auth(second_token),
        json={"product_code": "annual_v1"},
    ).json()

    assert second["order_id"] != first["order_id"]


def test_query_order_requires_own_device_token(tmp_path):
    client, first_token = _registered_mock_client(tmp_path)
    second_token = client.post("/device/register", json=_register_payload("device-b")).json()[
        "signed_license_token"
    ]
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(first_token),
        json={"product_code": "annual_v1"},
    ).json()

    owner = client.get(f"/api/v1/payment/orders/{order['order_id']}", headers=_auth(first_token))
    other = client.get(f"/api/v1/payment/orders/{order['order_id']}", headers=_auth(second_token))

    assert owner.status_code == 200
    assert owner.json()["status"] == "WAITING_PAYMENT"
    assert other.status_code == 404
    assert other.json()["detail"] == "payment_order_not_found"


def test_tampered_bearer_token_is_rejected(tmp_path):
    client, token = _registered_mock_client(tmp_path)

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(_tamper(token)),
        json={"product_code": "annual_v1"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_device_proof"


def test_mock_payment_loop_refreshes_to_paid_token_and_is_idempotent(tmp_path):
    client, token = _registered_mock_client(tmp_path)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()

    paid = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )
    duplicate = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )
    queried = client.get(
        f"/api/v1/payment/orders/{order['order_id']}",
        headers=_auth(token),
    )
    refreshed = client.post(
        "/license/refresh",
        json={
            "product_id": "whut-campus-auto-login",
            "device_fingerprint_hash": "device-a",
        },
    )

    assert paid.status_code == 200
    assert paid.json()["status"] == "PAID"
    assert paid.json()["idempotent"] is False
    assert duplicate.status_code == 200
    assert duplicate.json()["idempotent"] is True
    assert queried.json()["status"] == "PAID"
    assert refreshed.json()["status"] == "paid_active"
    assert refreshed.json()["license_type"] == "paid"
    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_mock_pay_requires_admin_token_and_rejects_amount_body(tmp_path):
    client, token = _registered_mock_client(tmp_path)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()

    missing = client.post(f"/api/v1/payment/mock/orders/{order['order_id']}/pay", json={})
    extra = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={"amount_fen": 1},
    )

    assert missing.status_code == 403
    assert missing.json()["detail"] == "invalid_mock_payment_token"
    assert extra.status_code == 422


def test_mock_route_is_not_registered_without_mock_provider(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.post(
        "/api/v1/payment/mock/orders/missing/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )

    assert response.status_code == 404


def test_closed_order_cannot_be_mock_paid(tmp_path):
    client, token = _registered_mock_client(tmp_path)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()
    with sqlite3.connect(tmp_path / "license.sqlite3") as connection:
        connection.execute(
            "UPDATE payment_orders SET status = 'CLOSED', open_slot = NULL WHERE order_id = ?",
            (order["order_id"],),
        )

    response = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "closed_order"


def _registered_mock_client(tmp_path):
    client, _public_key = _client(
        tmp_path,
        payment_provider="mock",
        payment_mock_admin_token=MOCK_TOKEN,
    )
    token = client.post("/device/register", json=_register_payload()).json()[
        "signed_license_token"
    ]
    return client, token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _tamper(token: str) -> str:
    replacement = "A" if token[0] != "A" else "B"
    return replacement + token[1:]


class CapturingGateway(MockPaymentGateway):
    def __init__(self):
        self.request = None

    def create_native_order(self, request):
        self.request = request
        return super().create_native_order(request)
