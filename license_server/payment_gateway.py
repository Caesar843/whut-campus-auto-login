from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping, Protocol


MOCK_APP_ID = "mock-app"
MOCK_MCH_ID = "mock-mch"


class QueryOrderOutcome(str, Enum):
    PAID = "PAID"
    UNPAID = "UNPAID"
    CLOSED = "CLOSED"
    NOT_FOUND = "NOT_FOUND"
    UNCLEAR = "UNCLEAR"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    HTTP_UNKNOWN = "HTTP_UNKNOWN"


class CloseOrderOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    PAID = "PAID"
    CLOSED = "CLOSED"
    NOT_FOUND = "NOT_FOUND"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CreateNativeOrderRequest:
    out_trade_no: str
    description: str
    amount_fen: int
    currency: str
    notify_url: str
    expires_at: datetime
    attach: str | None = None

    @property
    def order_id(self) -> str:
        return self.out_trade_no


@dataclass(frozen=True)
class GatewayOrder:
    code_url: str
    provider_order_id: str
    provider_trade_state: str
    request_id: str | None = None


CreateNativeOrderResult = GatewayOrder


@dataclass(frozen=True)
class QueryOrderResult:
    outcome: QueryOrderOutcome
    out_trade_no: str
    transaction_id: str | None = None
    trade_state: str | None = None
    trade_type: str | None = None
    amount_total: int | None = None
    currency: str | None = None
    success_time: datetime | None = None
    appid: str | None = None
    mchid: str | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class CloseOrderResult:
    outcome: CloseOrderOutcome
    request_id: str | None = None


@dataclass(frozen=True)
class VerifiedPaymentNotification:
    notification_id: str
    event_type: str
    provider_created_time: datetime
    appid: str
    mchid: str
    out_trade_no: str
    transaction_id: str
    trade_type: str
    trade_state: str
    amount_total: int
    currency: str
    success_time: datetime


class PaymentGateway(Protocol):
    def create_native_order(self, request: CreateNativeOrderRequest) -> GatewayOrder:
        ...

    def query_order(self, order_id: str) -> QueryOrderResult:
        ...

    def close_order(self, order_id: str) -> CloseOrderResult:
        ...

    def parse_and_verify_notification(
        self,
        headers: Mapping[str, str],
        body: bytes,
        *,
        now: datetime | None = None,
    ) -> VerifiedPaymentNotification:
        ...


class MockPaymentGateway:
    def create_native_order(self, request: CreateNativeOrderRequest) -> GatewayOrder:
        return GatewayOrder(
            code_url=mock_code_url(request.out_trade_no),
            provider_order_id=request.out_trade_no,
            provider_trade_state="MOCK_WAITING_PAYMENT",
        )

    def query_order(self, order_id: str) -> QueryOrderResult:
        return QueryOrderResult(
            outcome=QueryOrderOutcome.UNPAID,
            out_trade_no=order_id,
            trade_state="NOTPAY",
            trade_type="NATIVE",
            amount_total=990,
            currency="CNY",
            appid=MOCK_APP_ID,
            mchid=MOCK_MCH_ID,
        )

    def close_order(self, order_id: str) -> CloseOrderResult:
        return CloseOrderResult(outcome=CloseOrderOutcome.SUCCESS)

    def parse_and_verify_notification(
        self,
        headers: Mapping[str, str],
        body: bytes,
        *,
        now: datetime | None = None,
    ) -> VerifiedPaymentNotification:
        raise NotImplementedError("mock notifications are not used")


def mock_code_url(order_id: str) -> str:
    return f"mock://whut-payment/{order_id}"
