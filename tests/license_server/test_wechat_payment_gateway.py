import base64
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from license_server.config import WechatPayConfig
from license_server.payment_gateway import (
    CloseOrderOutcome,
    CreateNativeOrderRequest,
    QueryOrderOutcome,
)
from license_server.wechat_payment import (
    WECHAT_HTTP_TIMEOUT,
    WeChatNativePaymentGateway,
    WechatPaymentError,
)


NOW = datetime(2026, 7, 13, 4, 0, tzinfo=timezone.utc)
PUBLIC_KEY_ID = "PUB_KEY_ID_TEST"


def test_gateway_uses_explicit_four_phase_timeouts():
    assert WECHAT_HTTP_TIMEOUT.connect == 5.0
    assert WECHAT_HTTP_TIMEOUT.read == 10.0
    assert WECHAT_HTTP_TIMEOUT.write == 10.0
    assert WECHAT_HTTP_TIMEOUT.pool == 5.0


def test_native_create_sends_direct_merchant_request_and_returns_verified_code_url(
    tmp_path,
):
    private_key, config = _config(tmp_path)

    def handler(request: httpx.Request):
        assert request.method == "POST"
        assert request.url.path == "/v3/pay/transactions/native"
        assert request.headers["Authorization"].startswith(
            "WECHATPAY2-SHA256-RSA2048 "
        )
        assert json.loads(request.content) == {
            "appid": "wx-test-app",
            "mchid": "1900000109",
            "description": "annual license",
            "out_trade_no": "pay_test",
            "time_expire": "2026-07-13T04:15:00+00:00",
            "notify_url": "https://pay.example.test/wechat/notify",
            "amount": {"total": 990, "currency": "CNY"},
            "attach": "annual_v1",
        }
        return _signed_response(
            private_key,
            request,
            200,
            b'{"code_url":"weixin://wxpay/bizpayurl?pr=test"}',
            request_id="REQ_123",
        )

    gateway = _gateway(config, handler)
    result = gateway.create_native_order(_create_request())

    assert result.code_url == "weixin://wxpay/bizpayurl?pr=test"
    assert result.provider_order_id == "pay_test"
    assert result.provider_trade_state == "NOTPAY"
    assert result.request_id == "REQ_123"


def test_native_create_rejects_untrusted_non_json_and_incomplete_responses(tmp_path):
    private_key, config = _config(tmp_path)

    def untrusted(request):
        return httpx.Response(200, content=b'{"code_url":"untrusted"}', request=request)

    with pytest.raises(
        WechatPaymentError,
        match="PAYMENT_RESPONSE_SIGNATURE_MISSING",
    ) as exc_info:
        _gateway(config, untrusted).create_native_order(_create_request())
    assert exc_info.value.result_unknown is True

    for body in (b"not-json", b"{}"):
        def invalid(request, body=body):
            return _signed_response(private_key, request, 200, body)

        with pytest.raises(
            WechatPaymentError,
            match="PAYMENT_RESPONSE_INVALID",
        ) as exc_info:
            _gateway(config, invalid).create_native_order(_create_request())
        assert exc_info.value.result_unknown is True


@pytest.mark.parametrize(
    ("trade_state", "outcome"),
    (
        ("SUCCESS", QueryOrderOutcome.PAID),
        ("NOTPAY", QueryOrderOutcome.UNPAID),
        ("USERPAYING", QueryOrderOutcome.UNPAID),
        ("CLOSED", QueryOrderOutcome.CLOSED),
        ("PAYERROR", QueryOrderOutcome.UNCLEAR),
    ),
)
def test_query_by_out_trade_no_maps_verified_trade_states(
    tmp_path,
    trade_state,
    outcome,
):
    private_key, config = _config(tmp_path)

    def handler(request):
        assert request.method == "GET"
        assert request.url.path == "/v3/pay/transactions/out-trade-no/pay_test"
        assert dict(request.url.params) == {"mchid": "1900000109"}
        payload = {
            "appid": "wx-test-app",
            "mchid": "1900000109",
            "out_trade_no": "pay_test",
            "trade_type": "NATIVE",
            "trade_state": trade_state,
            "amount": {"total": 990, "currency": "CNY"},
        }
        if trade_state == "SUCCESS":
            payload.update(
                transaction_id="4200000001",
                success_time="2026-07-13T12:00:00+08:00",
            )
        body = json.dumps(payload, separators=(",", ":")).encode()
        return _signed_response(private_key, request, 200, body)

    result = _gateway(config, handler).query_order("pay_test")

    assert result.outcome is outcome
    assert result.out_trade_no == "pay_test"
    assert result.appid == "wx-test-app"
    assert result.mchid == "1900000109"
    assert result.amount_total == 990
    assert result.currency == "CNY"


def test_query_distinguishes_not_found_signature_invalid_and_http_unknown(tmp_path):
    private_key, config = _config(tmp_path)

    def not_found(request):
        return _signed_response(
            private_key,
            request,
            404,
            b'{"code":"ORDER_NOT_EXIST","message":"not found"}',
        )

    assert (
        _gateway(config, not_found).query_order("pay_test").outcome
        is QueryOrderOutcome.NOT_FOUND
    )

    def untrusted(request):
        return httpx.Response(200, content=b"{}", request=request)

    assert (
        _gateway(config, untrusted).query_order("pay_test").outcome
        is QueryOrderOutcome.SIGNATURE_INVALID
    )

    def timeout(request):
        raise httpx.ReadTimeout("sensitive upstream detail", request=request)

    assert (
        _gateway(config, timeout).query_order("pay_test").outcome
        is QueryOrderOutcome.HTTP_UNKNOWN
    )


def test_close_verifies_empty_204_and_maps_signed_business_errors(tmp_path):
    private_key, config = _config(tmp_path)

    def success(request):
        assert request.method == "POST"
        assert request.url.path == "/v3/pay/transactions/out-trade-no/pay_test/close"
        assert json.loads(request.content) == {"mchid": "1900000109"}
        return _signed_response(private_key, request, 204, b"")

    assert (
        _gateway(config, success).close_order("pay_test").outcome
        is CloseOrderOutcome.SUCCESS
    )

    cases = {
        "ORDER_PAID": CloseOrderOutcome.PAID,
        "ORDER_CLOSED": CloseOrderOutcome.CLOSED,
        "ORDER_NOT_EXIST": CloseOrderOutcome.NOT_FOUND,
        "PARAM_ERROR": CloseOrderOutcome.REJECTED,
    }
    for code, expected in cases.items():
        body = json.dumps({"code": code, "message": "ignored"}).encode()

        def rejected(request, body=body):
            return _signed_response(private_key, request, 400, body)

        assert _gateway(config, rejected).close_order("pay_test").outcome is expected


@pytest.mark.parametrize(
    ("error", "code", "unknown"),
    (
        (httpx.ConnectTimeout, "PAYMENT_CONNECT_TIMEOUT", True),
        (httpx.PoolTimeout, "PAYMENT_REQUEST_NOT_SENT", False),
        (httpx.ReadTimeout, "PAYMENT_RESULT_UNKNOWN", True),
        (httpx.WriteTimeout, "PAYMENT_RESULT_UNKNOWN", True),
    ),
)
def test_create_classifies_transport_errors_without_leaking_details(
    tmp_path,
    error,
    code,
    unknown,
):
    _private_key, config = _config(tmp_path)

    def handler(request):
        raise error("sensitive upstream detail", request=request)

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, handler).create_native_order(_create_request())

    assert str(exc_info.value) == code
    assert exc_info.value.result_unknown is unknown
    assert "sensitive upstream detail" not in str(exc_info.value)


def test_signed_5xx_and_unsafe_request_id_return_safe_error(tmp_path):
    private_key, config = _config(tmp_path)

    def handler(request):
        return _signed_response(
            private_key,
            request,
            500,
            b'{"code":"SYSTEM_ERROR","message":"sensitive detail"}',
            request_id="unsafe request id",
        )

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, handler).create_native_order(_create_request())

    assert str(exc_info.value) == "PAYMENT_UPSTREAM_UNAVAILABLE"
    assert "sensitive detail" not in str(exc_info.value)


def _config(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "merchant.pem"
    public_path = tmp_path / "wechat-public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_key, WechatPayConfig(
        app_id="wx-test-app",
        mch_id="1900000109",
        merchant_serial_no="MERCHANT-SERIAL",
        merchant_private_key_path=private_path,
        public_key_id=PUBLIC_KEY_ID,
        public_key_path=public_path,
        api_v3_key=b"0123456789abcdef0123456789abcdef",
        notify_url="https://pay.example.test/wechat/notify",
    )


def _gateway(config, handler):
    client = httpx.Client(
        base_url="https://api.mch.weixin.qq.com",
        transport=httpx.MockTransport(handler),
    )
    return WeChatNativePaymentGateway(
        config,
        client=client,
        clock=lambda: NOW,
        nonce_factory=lambda: "fixed-nonce",
    )


def _create_request():
    return CreateNativeOrderRequest(
        out_trade_no="pay_test",
        description="annual license",
        amount_fen=990,
        currency="CNY",
        notify_url="https://pay.example.test/wechat/notify",
        expires_at=NOW + timedelta(minutes=15),
        attach="annual_v1",
    )


def _signed_response(
    private_key,
    request,
    status_code,
    body,
    *,
    request_id=None,
):
    timestamp = str(int(NOW.timestamp()))
    nonce = "response-nonce"
    message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body + b"\n"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    headers = {
        "Wechatpay-Timestamp": timestamp,
        "Wechatpay-Nonce": nonce,
        "Wechatpay-Signature": base64.b64encode(signature).decode(),
        "Wechatpay-Serial": PUBLIC_KEY_ID,
    }
    if request_id is not None:
        headers["Request-ID"] = request_id
    return httpx.Response(status_code, content=body, headers=headers, request=request)
