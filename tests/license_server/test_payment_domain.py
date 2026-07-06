from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from license_server.payment import (
    OrderStatus,
    PaymentDomainError,
    PaymentEvidence,
    PaymentEvidenceSource,
    assert_order_transition,
    get_product,
)


def test_annual_v1_product_is_fixed_and_immutable():
    product = get_product("annual_v1")

    assert product.product_code == "annual_v1"
    assert product.amount_fen == 990
    assert product.currency == "CNY"
    assert product.duration_days == 365
    with pytest.raises(FrozenInstanceError):
        product.amount_fen = 1


def test_unknown_product_raises_domain_error():
    with pytest.raises(PaymentDomainError, match="unknown_product"):
        get_product("monthly")


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (OrderStatus.CREATED, OrderStatus.WAITING_PAYMENT),
        (OrderStatus.CREATED, OrderStatus.CLOSED),
        (OrderStatus.CREATED, OrderStatus.ABNORMAL),
        (OrderStatus.WAITING_PAYMENT, OrderStatus.PAID),
        (OrderStatus.WAITING_PAYMENT, OrderStatus.CLOSED),
        (OrderStatus.WAITING_PAYMENT, OrderStatus.ABNORMAL),
        (OrderStatus.ABNORMAL, OrderStatus.PAID),
        (OrderStatus.ABNORMAL, OrderStatus.CLOSED),
    ],
)
def test_allowed_order_transitions(current, target):
    assert_order_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (OrderStatus.PAID, OrderStatus.CLOSED),
        (OrderStatus.CLOSED, OrderStatus.WAITING_PAYMENT),
        (OrderStatus.CREATED, OrderStatus.PAID),
        (OrderStatus.WAITING_PAYMENT, OrderStatus.CREATED),
    ],
)
def test_invalid_order_transitions_raise_domain_error(current, target):
    with pytest.raises(PaymentDomainError, match="invalid_order_transition"):
        assert_order_transition(current, target)


def test_payment_evidence_normalizes_currency_and_utc_time():
    evidence = PaymentEvidence(
        source=PaymentEvidenceSource.MOCK,
        out_trade_no="pay_123",
        provider_transaction_id="txn_123",
        trade_type="NATIVE",
        trade_state="SUCCESS",
        amount_fen=990,
        currency="cny",
        paid_at=datetime(2026, 7, 6, 10, 0, tzinfo=timezone.utc),
        appid="mock-app",
        mchid="mock-mch",
    )

    assert evidence.currency == "CNY"
    assert evidence.paid_at.tzinfo == timezone.utc
    assert evidence.provider_notification_id is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"out_trade_no": "   "},
        {"provider_transaction_id": ""},
        {"trade_type": " "},
        {"trade_state": ""},
        {"appid": " "},
        {"mchid": ""},
    ],
)
def test_payment_evidence_rejects_blank_required_strings(kwargs):
    data = _evidence_kwargs()
    data.update(kwargs)

    with pytest.raises(PaymentDomainError, match="required"):
        PaymentEvidence(**data)


def test_payment_evidence_rejects_non_positive_amount():
    data = _evidence_kwargs(amount_fen=0)

    with pytest.raises(PaymentDomainError, match="amount_fen"):
        PaymentEvidence(**data)


def test_payment_evidence_rejects_naive_time():
    data = _evidence_kwargs(paid_at=datetime(2026, 7, 6, 10, 0))

    with pytest.raises(PaymentDomainError, match="paid_at"):
        PaymentEvidence(**data)


def test_payment_evidence_rejects_unknown_source():
    data = _evidence_kwargs(source="cash")

    with pytest.raises(PaymentDomainError, match="source"):
        PaymentEvidence(**data)


def _evidence_kwargs(**overrides):
    data = {
        "source": PaymentEvidenceSource.WECHAT_CALLBACK,
        "out_trade_no": "pay_123",
        "provider_transaction_id": "txn_123",
        "trade_type": "NATIVE",
        "trade_state": "SUCCESS",
        "amount_fen": 990,
        "currency": "CNY",
        "paid_at": datetime(2026, 7, 6, 10, 0, tzinfo=timezone.utc),
        "appid": "wx-app",
        "mchid": "merchant",
        "provider_notification_id": "notice-1",
    }
    data.update(overrides)
    return data
