from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class PaymentDomainError(ValueError):
    pass


@dataclass(frozen=True)
class PaymentProduct:
    product_code: str
    amount_fen: int
    currency: str
    duration_days: int


ANNUAL_V1 = PaymentProduct(
    product_code="annual_v1",
    amount_fen=990,
    currency="CNY",
    duration_days=365,
)
PRODUCTS = {ANNUAL_V1.product_code: ANNUAL_V1}


class OrderStatus(str, Enum):
    CREATED = "CREATED"
    WAITING_PAYMENT = "WAITING_PAYMENT"
    PAID = "PAID"
    CLOSED = "CLOSED"
    ABNORMAL = "ABNORMAL"


ALLOWED_ORDER_TRANSITIONS = {
    OrderStatus.CREATED: {
        OrderStatus.WAITING_PAYMENT,
        OrderStatus.CLOSED,
        OrderStatus.ABNORMAL,
    },
    OrderStatus.WAITING_PAYMENT: {
        OrderStatus.PAID,
        OrderStatus.CLOSED,
        OrderStatus.ABNORMAL,
    },
    OrderStatus.ABNORMAL: {
        OrderStatus.PAID,
        OrderStatus.CLOSED,
    },
}


class PaymentEvidenceSource(str, Enum):
    WECHAT_CALLBACK = "wechat_callback"
    WECHAT_QUERY = "wechat_query"
    ADMIN_VERIFIED_QUERY = "admin_verified_query"
    MOCK = "mock"


@dataclass(frozen=True)
class PaymentEvidence:
    source: PaymentEvidenceSource
    out_trade_no: str
    provider_transaction_id: str
    trade_type: str
    trade_state: str
    amount_fen: int
    currency: str
    paid_at: datetime
    appid: str
    mchid: str
    provider_notification_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _evidence_source(self.source))
        for field in (
            "out_trade_no",
            "provider_transaction_id",
            "trade_type",
            "trade_state",
            "currency",
            "appid",
            "mchid",
        ):
            object.__setattr__(self, field, _required_text(getattr(self, field), field))
        if self.provider_notification_id is not None:
            object.__setattr__(
                self,
                "provider_notification_id",
                _required_text(self.provider_notification_id, "provider_notification_id"),
            )
        if not isinstance(self.amount_fen, int) or self.amount_fen <= 0:
            raise PaymentDomainError("amount_fen must be a positive integer")
        if self.paid_at.tzinfo is None or self.paid_at.utcoffset() is None:
            raise PaymentDomainError("paid_at must include timezone")
        object.__setattr__(self, "currency", self.currency.upper())
        object.__setattr__(self, "paid_at", self.paid_at.astimezone(timezone.utc))


def get_product(product_code: str) -> PaymentProduct:
    try:
        return PRODUCTS[product_code]
    except KeyError as exc:
        raise PaymentDomainError(f"unknown_product: {product_code}") from exc


def assert_order_transition(current: OrderStatus | str, target: OrderStatus | str) -> None:
    current_status = OrderStatus(current)
    target_status = OrderStatus(target)
    if target_status not in ALLOWED_ORDER_TRANSITIONS.get(current_status, set()):
        raise PaymentDomainError(
            f"invalid_order_transition: {current_status.value}->{target_status.value}"
        )


def _required_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise PaymentDomainError(f"{field} is required")
    return text


def _evidence_source(value: PaymentEvidenceSource | str) -> PaymentEvidenceSource:
    try:
        return PaymentEvidenceSource(value)
    except ValueError as exc:
        raise PaymentDomainError(f"invalid source: {value}") from exc
