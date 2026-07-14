from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request

from license_client.constants import PRICE_AMOUNT, PRICE_CURRENCY
from license_server.admin_routes import SECURITY_HEADERS, create_admin_router
from license_server.config import (
    DEFAULT_PAYMENT_CHANNELS,
    DEFAULT_PAYMENT_ORDER_TTL_MINUTES,
    DEFAULT_ENVIRONMENT,
    WechatPayConfig,
    is_production_environment,
    load_config,
    validate_mock_admin_token,
    validate_admin_access_token_sha256,
    validate_private_key_b64,
)
from license_server.db import initialize_database
from license_server.payment_gateway import MockPaymentGateway, PaymentGateway
from license_server.payment_notification_routes import (
    create_payment_notification_router,
)
from license_server.payment_routes import create_payment_router
from license_server.routes import create_router
from license_server.wechat_payment import WeChatNativePaymentGateway


HEALTHZ_RESPONSE = {"status": "ok"}
HEALTH_RESPONSE = {"status": "ok", "service": "license_server"}


def create_app(
    *,
    database_path: Optional[Path] = None,
    private_key_b64: Optional[str] = None,
    payment_amount: Optional[str] = None,
    payment_currency: Optional[str] = None,
    payment_channels: Optional[tuple[str, ...]] = None,
    payment_provider: Optional[str] = None,
    payment_mock_admin_token: Optional[str] = None,
    wechat_pay_config: Optional[WechatPayConfig] = None,
    payment_gateway: Optional[PaymentGateway] = None,
    payment_order_ttl_minutes: Optional[int] = None,
    environment: Optional[str] = None,
    admin_enabled: Optional[bool] = None,
    admin_operator_name: Optional[str] = None,
    admin_access_token_sha256: Optional[str] = None,
) -> FastAPI:
    if database_path is None or private_key_b64 is None:
        config = load_config()
        environment = environment or config.environment
        database_path = database_path or config.database_path
        private_key_b64 = private_key_b64 or config.private_key_b64
        payment_amount = payment_amount or config.payment_amount
        payment_currency = payment_currency or config.payment_currency
        payment_channels = payment_channels or config.payment_channels
        payment_provider = payment_provider or config.payment_provider
        payment_mock_admin_token = (
            payment_mock_admin_token or config.payment_mock_admin_token
        )
        wechat_pay_config = wechat_pay_config or config.wechat_pay
        payment_order_ttl_minutes = (
            payment_order_ttl_minutes or config.payment_order_ttl_minutes
        )
        admin_enabled = config.admin_enabled if admin_enabled is None else admin_enabled
        admin_operator_name = admin_operator_name or config.admin_operator_name
        admin_access_token_sha256 = (
            admin_access_token_sha256 or config.admin_access_token_sha256
        )
    environment = environment or DEFAULT_ENVIRONMENT
    validate_private_key_b64(str(private_key_b64), source="private_key_b64")
    if environment == "production" and payment_provider == "mock":
        raise RuntimeError("PAYMENT_PROVIDER=mock is not allowed in production.")
    if payment_provider == "mock" and not str(payment_mock_admin_token or "").strip():
        raise RuntimeError("PAYMENT_MOCK_ADMIN_TOKEN is required when PAYMENT_PROVIDER=mock.")
    if payment_provider == "mock":
        validate_mock_admin_token(str(payment_mock_admin_token))
        payment_gateway = payment_gateway or MockPaymentGateway()
    elif payment_provider == "wechat_native":
        if wechat_pay_config is None:
            raise RuntimeError("wechat_native configuration is required.")
        payment_gateway = payment_gateway or WeChatNativePaymentGateway(
            wechat_pay_config
        )
    payment_amount = payment_amount or PRICE_AMOUNT
    payment_currency = payment_currency or PRICE_CURRENCY
    payment_channels = payment_channels or DEFAULT_PAYMENT_CHANNELS
    payment_order_ttl_minutes = (
        payment_order_ttl_minutes or DEFAULT_PAYMENT_ORDER_TTL_MINUTES
    )
    admin_enabled = bool(admin_enabled)
    if admin_enabled:
        validate_admin_access_token_sha256(admin_access_token_sha256)
    initialize_database(Path(database_path))
    app = FastAPI(title="WHUT Campus Auto Login License Server")
    _add_admin_security_headers(app)
    _add_health_route(app)
    app.include_router(
        create_router(
            database_path=Path(database_path),
            private_key_b64=str(private_key_b64),
            payment_amount=str(payment_amount),
            payment_currency=str(payment_currency),
            payment_channels=tuple(payment_channels),
            payment_order_ttl_minutes=int(payment_order_ttl_minutes),
        )
    )
    app.include_router(
        create_payment_router(
            database_path=Path(database_path),
            private_key_b64=str(private_key_b64),
            payment_provider=payment_provider,
            payment_mock_admin_token=payment_mock_admin_token,
            gateway=payment_gateway,
            notify_url=(
                wechat_pay_config.notify_url if wechat_pay_config is not None else None
            ),
            expected_appid=(
                wechat_pay_config.app_id if wechat_pay_config is not None else None
            ),
            expected_mchid=(
                wechat_pay_config.mch_id if wechat_pay_config is not None else None
            ),
            payment_order_ttl_minutes=int(payment_order_ttl_minutes),
        )
    )
    if (
        payment_provider == "wechat_native"
        and wechat_pay_config is not None
        and isinstance(payment_gateway, WeChatNativePaymentGateway)
    ):
        app.include_router(
            create_payment_notification_router(
                database_path=Path(database_path),
                gateway=payment_gateway,
                expected_appid=wechat_pay_config.app_id,
                expected_mchid=wechat_pay_config.mch_id,
                signature_key_id=wechat_pay_config.public_key_id,
            )
        )
    if admin_enabled:
        app.include_router(
            create_admin_router(
                database_path=Path(database_path),
                operator_name=str(admin_operator_name or ""),
                access_token_sha256=str(admin_access_token_sha256),
            )
        )
    return app


def _default_app() -> FastAPI:
    try:
        return create_app()
    except RuntimeError:
        if _must_fail_startup():
            raise
        fallback = FastAPI(title="WHUT Campus Auto Login License Server")
        _add_health_route(fallback)
        return fallback


def _must_fail_startup() -> bool:
    try:
        if is_production_environment():
            return True
    except RuntimeError:
        return True
    provider = os.environ.get("PAYMENT_PROVIDER", "").strip().lower()
    return bool(provider and provider != "disabled")


def _add_health_route(app: FastAPI) -> None:
    @app.get("/healthz")
    def healthz():
        return HEALTHZ_RESPONSE

    @app.get("/health")
    def health():
        return HEALTH_RESPONSE


def _add_admin_security_headers(app: FastAPI) -> None:
    @app.middleware("http")
    async def add_admin_security_headers(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/internal/admin"):
            for name, value in SECURITY_HEADERS.items():
                response.headers[name] = value
        return response


app = _default_app()
