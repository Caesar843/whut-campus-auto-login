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
        ("SUCCESS", QueryOrderOutcome.SUCCESS),
        ("NOTPAY", QueryOrderOutcome.NOTPAY),
        ("CLOSED", QueryOrderOutcome.CLOSED),
        ("REFUND", QueryOrderOutcome.REFUND),
        ("REVOKED", QueryOrderOutcome.REVOKED),
        ("USERPAYING", QueryOrderOutcome.USERPAYING),
        ("PAYERROR", QueryOrderOutcome.PAYERROR),
        ("FUTURE_STATE", QueryOrderOutcome.UNKNOWN),
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
            "bank_type": "SENSITIVE_BANK",
            "payer": {"openid": "sensitive-openid"},
        }
        if trade_state == "SUCCESS":
            payload.update(
                transaction_id="4200000001",
                success_time="2026-07-13T12:00:00+08:00",
            )
        elif trade_state == "CLOSED":
            payload.update(
                transaction_id="must-not-be-exposed",
                success_time="2026-07-13T12:00:00+08:00",
            )
        body = json.dumps(payload, separators=(",", ":")).encode()
        return _signed_response(private_key, request, 200, body)

    result = _gateway(config, handler).query_order("pay_test")

    assert result.outcome is outcome
    assert result.out_trade_no == "pay_test"
    assert result.trade_state == (
        trade_state if trade_state != "FUTURE_STATE" else "UNKNOWN"
    )
    assert not hasattr(result, "openid")
    assert not hasattr(result, "bank_type")
    assert not hasattr(result, "raw_body")
    if trade_state == "SUCCESS":
        assert result.appid == "wx-test-app"
        assert result.mchid == "1900000109"
        assert result.transaction_id == "4200000001"
        assert result.trade_type == "NATIVE"
        assert result.amount_total == 990
        assert result.currency == "CNY"
        assert result.success_time == datetime(
            2026, 7, 13, 4, 0, tzinfo=timezone.utc
        )
    elif trade_state == "CLOSED":
        # The existing CREATED recovery caller validates these fields before closing.
        assert result.amount_total == 990
        assert result.transaction_id is None
        assert result.success_time is None
    else:
        assert result.transaction_id is None
        assert result.success_time is None
        assert result.amount_total is None
        assert result.currency is None
        assert result.appid is None
        assert result.mchid is None


def test_query_rejects_http_signature_schema_and_transport_errors(tmp_path):
    private_key, config = _config(tmp_path)

    def not_found(request):
        return _signed_response(
            private_key,
            request,
            404,
            b'{"code":"ORDER_NOT_EXIST","message":"not found"}',
        )

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, not_found).query_order("pay_test")
    assert exc_info.value.code == "PAYMENT_UPSTREAM_REJECTED"
    assert exc_info.value.retryable is False

    def untrusted(request):
        return httpx.Response(200, content=b"{}", request=request)

    with pytest.raises(WechatPaymentError, match="PAYMENT_RESPONSE_SIGNATURE_MISSING"):
        _gateway(config, untrusted).query_order("pay_test")

    def timeout(request):
        raise httpx.ReadTimeout("sensitive upstream detail", request=request)

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, timeout).query_order("pay_test")
    assert exc_info.value.code == "PAYMENT_READ_TIMEOUT"
    assert exc_info.value.retryable is True
    assert exc_info.value.result_unknown is True

    for body in (b"not-json", b'{}'):
        def invalid(request, body=body):
            return _signed_response(private_key, request, 200, body)

        with pytest.raises(WechatPaymentError, match="PAYMENT_RESPONSE_INVALID"):
            _gateway(config, invalid).query_order("pay_test")


def test_query_rejects_stale_signed_response_before_parsing(tmp_path):
    private_key, config = _config(tmp_path)

    def stale(request):
        return _signed_response(
            private_key,
            request,
            200,
            b'{"trade_state":"SUCCESS"}',
            timestamp=int((NOW - timedelta(minutes=6)).timestamp()),
        )

    with pytest.raises(WechatPaymentError, match="PAYMENT_RESPONSE_TIMESTAMP_INVALID"):
        _gateway(config, stale).query_order("pay_test")


def test_close_maps_only_verified_200_or_204_success_to_closed(tmp_path):
    private_key, config = _config(tmp_path)

    def success(request):
        assert request.method == "POST"
        assert request.url.path == "/v3/pay/transactions/out-trade-no/pay_test/close"
        assert json.loads(request.content) == {"mchid": "1900000109"}
        return _signed_response(private_key, request, 204, b"")

    assert (
        _gateway(config, success).close_order("pay_test").outcome
        is CloseOrderOutcome.CLOSED
    )

    for code, expected in {
        "SUCCESS": CloseOrderOutcome.CLOSED,
        "FUTURE_RESULT": CloseOrderOutcome.UNKNOWN,
    }.items():
        body = json.dumps({"code": code, "message": "ignored"}).encode()

        def response(request, body=body):
            return _signed_response(private_key, request, 200, body)

        assert _gateway(config, response).close_order("pay_test").outcome is expected


def test_close_maps_verified_400_order_paid_exactly_to_paid(tmp_path):
    private_key, config = _config(tmp_path)

    def paid(request):
        return _signed_response(
            private_key,
            request,
            400,
            b'{"code":"ORDER_PAID","message":"ignored"}',
        )

    assert (
        _gateway(config, paid).close_order("pay_test").outcome
        is CloseOrderOutcome.PAID
    )


@pytest.mark.parametrize(
    "body",
    (
        b"not-json",
        b"[]",
        b"{}",
        b'{"code":true}',
        b'{"code":"ORDER_NOT_EXIST"}',
        b'{"code":"SYSTEM_ERROR","message":"order already paid"}',
    ),
)
def test_close_never_infers_paid_from_untrusted_400_payload_shapes(tmp_path, body):
    private_key, config = _config(tmp_path)

    def rejected(request):
        return _signed_response(private_key, request, 400, body)

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, rejected).close_order("pay_test")

    assert exc_info.value.code == "PAYMENT_UPSTREAM_REJECTED"


def test_close_rejects_unsigned_400_order_paid(tmp_path):
    _private_key, config = _config(tmp_path)

    def untrusted(request):
        return httpx.Response(
            400,
            content=b'{"code":"ORDER_PAID"}',
            request=request,
        )

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, untrusted).close_order("pay_test")

    assert exc_info.value.code == "PAYMENT_RESPONSE_SIGNATURE_MISSING"


def test_close_rejects_invalid_or_stale_signed_400_order_paid(tmp_path):
    private_key, config = _config(tmp_path)
    other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def invalid_signature(request):
        return _signed_response(
            other_private_key,
            request,
            400,
            b'{"code":"ORDER_PAID"}',
        )

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, invalid_signature).close_order("pay_test")
    assert exc_info.value.code == "PAYMENT_RESPONSE_SIGNATURE_INVALID"

    def stale(request):
        return _signed_response(
            private_key,
            request,
            400,
            b'{"code":"ORDER_PAID"}',
            timestamp=int((NOW - timedelta(minutes=6)).timestamp()),
        )

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, stale).close_order("pay_test")
    assert exc_info.value.code == "PAYMENT_RESPONSE_TIMESTAMP_INVALID"


def test_close_rejects_signature_transport_http_and_invalid_body(tmp_path):
    private_key, config = _config(tmp_path)

    def untrusted(request):
        return httpx.Response(204, content=b"", request=request)

    with pytest.raises(WechatPaymentError, match="PAYMENT_RESPONSE_SIGNATURE_MISSING"):
        _gateway(config, untrusted).close_order("pay_test")

    def timeout(request):
        raise httpx.ConnectTimeout("sensitive upstream detail", request=request)

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, timeout).close_order("pay_test")
    assert exc_info.value.code == "PAYMENT_CONNECT_TIMEOUT"
    assert exc_info.value.retryable is True

    def rejected(request):
        return _signed_response(
            private_key,
            request,
            400,
            b'{"code":"ORDER_NOT_EXIST","message":"ignored"}',
        )

    with pytest.raises(WechatPaymentError) as exc_info:
        _gateway(config, rejected).close_order("pay_test")
    assert exc_info.value.code == "PAYMENT_UPSTREAM_REJECTED"

    def invalid(request):
        return _signed_response(private_key, request, 200, b"not-json")

    with pytest.raises(WechatPaymentError, match="PAYMENT_RESPONSE_INVALID"):
        _gateway(config, invalid).close_order("pay_test")


@pytest.mark.parametrize(
    ("error", "code", "unknown"),
    (
        (httpx.ConnectTimeout, "PAYMENT_CONNECT_TIMEOUT", True),
        (httpx.PoolTimeout, "PAYMENT_REQUEST_NOT_SENT", False),
        (httpx.ConnectError, "PAYMENT_NETWORK_UNAVAILABLE", False),
        (httpx.ReadTimeout, "PAYMENT_READ_TIMEOUT", True),
        (httpx.WriteTimeout, "PAYMENT_WRITE_TIMEOUT", True),
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
    assert exc_info.value.retryable is True
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
    timestamp=None,
):
    timestamp = str(timestamp if timestamp is not None else int(NOW.timestamp()))
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
