from tests.license_server.test_license_server import _client


def test_legacy_payment_create_route_is_not_registered(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.post(
        "/payment/create",
        json={
            "product_id": "whut-campus-auto-login",
            "device_fingerprint_hash": "device-a",
            "payment_channel": "wechat_pay",
            "plan": "yearly",
        },
    )

    assert response.status_code == 404


def test_legacy_payment_status_route_is_not_registered(tmp_path):
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


def test_payment_channels_default_is_wechat_native_only(tmp_path):
    client, _public_key = _client(tmp_path)
    schema = client.get("/openapi.json").json()

    assert "/payment/create" not in schema["paths"]
    assert "/payment/status" not in schema["paths"]
    assert "/api/v1/payment/orders" in schema["paths"]
