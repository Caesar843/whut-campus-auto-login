from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from license_server.payment_gateway import (
    CloseOrderOutcome,
    CreateNativeOrderRequest,
    MockPaymentGateway,
    QueryOrderOutcome,
)


def test_gateway_request_is_immutable_and_carries_server_trusted_fields():
    request = CreateNativeOrderRequest(
        out_trade_no="pay_test",
        description="WHUT Campus Auto Login annual license",
        amount_fen=990,
        currency="CNY",
        notify_url="https://pay.example.test/wechat/notify",
        expires_at=datetime(2026, 7, 13, tzinfo=timezone.utc),
        attach="annual_v1",
    )

    assert request.out_trade_no == "pay_test"
    with pytest.raises(FrozenInstanceError):
        request.amount_fen = 1


def test_mock_gateway_implements_typed_create_query_and_close():
    request = CreateNativeOrderRequest(
        out_trade_no="pay_test",
        description="annual license",
        amount_fen=990,
        currency="CNY",
        notify_url="https://mock.invalid/notify",
        expires_at=datetime(2026, 7, 13, tzinfo=timezone.utc),
    )
    gateway = MockPaymentGateway()

    created = gateway.create_native_order(request)
    queried = gateway.query_order(request.out_trade_no)
    closed = gateway.close_order(request.out_trade_no)

    assert created.code_url == "mock://whut-payment/pay_test"
    assert queried.outcome is QueryOrderOutcome.UNPAID
    assert queried.out_trade_no == "pay_test"
    assert closed.outcome is CloseOrderOutcome.SUCCESS
