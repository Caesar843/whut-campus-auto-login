from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


MOCK_APP_ID = "mock-app"
MOCK_MCH_ID = "mock-mch"


@dataclass(frozen=True)
class CreateNativeOrderRequest:
    order_id: str
    description: str
    amount_fen: int
    currency: str
    expires_at: datetime


@dataclass(frozen=True)
class GatewayOrder:
    code_url: str
    provider_order_id: str
    provider_trade_state: str


class PaymentGateway(Protocol):
    def create_native_order(self, request: CreateNativeOrderRequest) -> GatewayOrder:
        ...

    def query_order(self, order_id: str) -> object:
        ...

    def close_order(self, order_id: str) -> object:
        ...


class MockPaymentGateway:
    def create_native_order(self, request: CreateNativeOrderRequest) -> GatewayOrder:
        return GatewayOrder(
            code_url=mock_code_url(request.order_id),
            provider_order_id=request.order_id,
            provider_trade_state="MOCK_WAITING_PAYMENT",
        )

    def query_order(self, order_id: str) -> object:
        raise NotImplementedError("mock query is not used by polling")

    def close_order(self, order_id: str) -> object:
        raise NotImplementedError("mock close is not implemented in P2")


def mock_code_url(order_id: str) -> str:
    return f"mock://whut-payment/{order_id}"
