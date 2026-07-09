from pathlib import Path
import sys

import pytest
import requests


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from license_client.payment_api import (
    ANNUAL_PRODUCT_CODE,
    PaymentApiClient,
    PaymentApiError,
)
from license_client.token_store import TokenLoadResult


TOKEN = "signed-token-secret"
ORDER_ID = "pay_" + "1" * 32
SECOND_ORDER_ID = "pay_" + "2" * 32


class FakeResponse:
    def __init__(self, status_code=200, payload=None, content=b"{}"):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = content

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def _order_payload(**overrides):
    payload = {
        "order_id": ORDER_ID,
        "product_code": "annual_v1",
        "amount_fen": 990,
        "currency": "CNY",
        "provider": "mock",
        "status": "WAITING_PAYMENT",
        "code_url": f"mock://whut-payment/{ORDER_ID}",
        "created_at": "2026-07-06T08:00:00Z",
        "expires_at": "2026-07-06T08:15:00Z",
        "paid_at": None,
    }
    payload.update(overrides)
    return payload


def _client():
    return PaymentApiClient(
        base_url="http://license.local/",
        token_loader=lambda: TokenLoadResult(status="loaded", signed_license_token=TOKEN),
        token_initializer=lambda: None,
    )


def test_create_order_uses_bearer_header_and_only_product_code(monkeypatch):
    captured = {}

    def fake_post(url, headers, timeout, json):
        captured.update(url=url, headers=headers, timeout=timeout, json=json)
        return FakeResponse(payload=_order_payload())

    monkeypatch.setattr("license_client.payment_api.requests.post", fake_post)

    order = _client().create_or_resume_order(ANNUAL_PRODUCT_CODE)

    assert order.order_id == ORDER_ID
    assert captured["url"] == "http://license.local/api/v1/payment/orders"
    assert captured["headers"] == {"Authorization": f"Bearer {TOKEN}"}
    assert captured["json"] == {"product_code": "annual_v1"}
    assert "device_fingerprint_hash" not in captured["json"]
    assert "amount_fen" not in captured["json"]
    assert "currency" not in captured["json"]
    assert "provider" not in captured["json"]


def test_get_order_uses_payment_order_path(monkeypatch):
    captured = {}

    def fake_get(url, headers, timeout):
        captured.update(url=url, headers=headers, timeout=timeout)
        return FakeResponse(payload=_order_payload(order_id=SECOND_ORDER_ID))

    monkeypatch.setattr("license_client.payment_api.requests.get", fake_get)

    order = _client().get_order(SECOND_ORDER_ID)

    assert order.order_id == SECOND_ORDER_ID
    assert captured["url"] == f"http://license.local/api/v1/payment/orders/{SECOND_ORDER_ID}"
    assert captured["headers"] == {"Authorization": f"Bearer {TOKEN}"}


def test_get_order_strips_safe_whitespace_before_request(monkeypatch):
    captured = {}

    def fake_get(url, headers, timeout):
        captured.update(url=url, headers=headers, timeout=timeout)
        return FakeResponse(payload=_order_payload())

    monkeypatch.setattr("license_client.payment_api.requests.get", fake_get)

    _client().get_order(f"  {ORDER_ID}\n")

    assert captured["url"] == f"http://license.local/api/v1/payment/orders/{ORDER_ID}"


@pytest.mark.parametrize(
    "order_id",
    [
        "",
        "   ",
        "pay_1",
        "bad_" + "1" * 32,
        "pay_" + "g" * 32,
        "pay_" + "A" * 32,
        "pay_" + "1" * 33,
        "pay_" + "1" * 31,
        ORDER_ID + "/extra",
        ORDER_ID + "\\extra",
        ORDER_ID + "?x=1",
        ORDER_ID + "#frag",
        ORDER_ID.replace("1", "%2F", 1),
        ORDER_ID.replace("1", "%2f", 1),
        ORDER_ID[:8] + "\n" + ORDER_ID[8:],
        123,
    ],
)
def test_invalid_order_id_is_rejected_before_http(monkeypatch, order_id):
    calls = []

    def fake_get(*args, **kwargs):
        calls.append(args)
        raise AssertionError("HTTP must not be called for invalid order ids")

    monkeypatch.setattr("license_client.payment_api.requests.get", fake_get)

    with pytest.raises(PaymentApiError) as exc_info:
        _client().get_order(order_id)

    assert exc_info.value.code == "invalid_payment_order_id"
    assert TOKEN not in str(exc_info.value)
    assert TOKEN not in repr(exc_info.value)
    assert calls == []


def test_missing_token_uses_initializer_before_failing(monkeypatch):
    calls = []

    def fake_post(url, headers, timeout, json):
        calls.append(headers["Authorization"])
        return FakeResponse(payload=_order_payload())

    monkeypatch.setattr("license_client.payment_api.requests.post", fake_post)
    client = PaymentApiClient(
        base_url="http://license.local",
        token_loader=lambda: TokenLoadResult(status="missing"),
        token_initializer=lambda: "initialized-token",
    )

    client.create_or_resume_order()

    assert calls == ["Bearer initialized-token"]


def test_error_text_and_repr_do_not_include_token(monkeypatch):
    def fake_post(url, headers, timeout, json):
        return FakeResponse(status_code=401, payload={"detail": "invalid_device_proof"})

    monkeypatch.setattr("license_client.payment_api.requests.post", fake_post)

    with pytest.raises(PaymentApiError) as exc_info:
        _client().create_or_resume_order()

    assert exc_info.value.code == "token_rejected"
    assert TOKEN not in str(exc_info.value)
    assert TOKEN not in repr(exc_info.value)


def test_timeout_and_network_errors_are_classified(monkeypatch):
    client = _client()

    monkeypatch.setattr(
        "license_client.payment_api.requests.get",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.Timeout("slow")),
    )
    with pytest.raises(PaymentApiError) as timeout_error:
        client.get_order(ORDER_ID)
    assert timeout_error.value.code == "request_timeout"

    monkeypatch.setattr(
        "license_client.payment_api.requests.get",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.ConnectionError("down")),
    )
    with pytest.raises(PaymentApiError) as network_error:
        client.get_order(ORDER_ID)
    assert network_error.value.code == "network_unreachable"


def test_non_json_or_missing_fields_are_invalid_response(monkeypatch):
    client = _client()
    monkeypatch.setattr(
        "license_client.payment_api.requests.get",
        lambda *args, **kwargs: FakeResponse(payload=ValueError("not-json")),
    )

    with pytest.raises(PaymentApiError) as non_json:
        client.get_order(ORDER_ID)
    assert non_json.value.code == "invalid_response"

    monkeypatch.setattr(
        "license_client.payment_api.requests.get",
        lambda *args, **kwargs: FakeResponse(payload={"order_id": ORDER_ID}),
    )

    with pytest.raises(PaymentApiError) as missing_fields:
        client.get_order(ORDER_ID)
    assert missing_fields.value.code == "invalid_response"
