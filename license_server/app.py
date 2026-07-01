from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI

from license_client.constants import PRICE_AMOUNT, PRICE_CURRENCY
from license_server.config import (
    DEFAULT_PAYMENT_CHANNELS,
    DEFAULT_PAYMENT_ORDER_TTL_MINUTES,
    load_config,
)
from license_server.db import initialize_database
from license_server.routes import create_router


HEALTH_RESPONSE = {"status": "ok", "service": "license_server"}


def create_app(
    *,
    database_path: Optional[Path] = None,
    private_key_b64: Optional[str] = None,
    admin_token: Optional[str] = None,
    payment_amount: Optional[str] = None,
    payment_currency: Optional[str] = None,
    payment_channels: Optional[tuple[str, ...]] = None,
    payment_order_ttl_minutes: Optional[int] = None,
) -> FastAPI:
    if database_path is None or private_key_b64 is None or admin_token is None:
        config = load_config()
        database_path = database_path or config.database_path
        private_key_b64 = private_key_b64 or config.private_key_b64
        admin_token = admin_token or config.admin_token
        payment_amount = payment_amount or config.payment_amount
        payment_currency = payment_currency or config.payment_currency
        payment_channels = payment_channels or config.payment_channels
        payment_order_ttl_minutes = (
            payment_order_ttl_minutes or config.payment_order_ttl_minutes
        )
    payment_amount = payment_amount or PRICE_AMOUNT
    payment_currency = payment_currency or PRICE_CURRENCY
    payment_channels = payment_channels or DEFAULT_PAYMENT_CHANNELS
    payment_order_ttl_minutes = (
        payment_order_ttl_minutes or DEFAULT_PAYMENT_ORDER_TTL_MINUTES
    )
    initialize_database(Path(database_path))
    app = FastAPI(title="WHUT Campus Auto Login License Server")
    _add_health_route(app)
    app.include_router(
        create_router(
            database_path=Path(database_path),
            private_key_b64=str(private_key_b64),
            admin_token=str(admin_token),
            payment_amount=str(payment_amount),
            payment_currency=str(payment_currency),
            payment_channels=tuple(payment_channels),
            payment_order_ttl_minutes=int(payment_order_ttl_minutes),
        )
    )
    return app


def _default_app() -> FastAPI:
    try:
        return create_app()
    except RuntimeError:
        fallback = FastAPI(title="WHUT Campus Auto Login License Server")
        _add_health_route(fallback)
        return fallback


def _add_health_route(app: FastAPI) -> None:
    @app.get("/health")
    def health():
        return HEALTH_RESPONSE


app = _default_app()
