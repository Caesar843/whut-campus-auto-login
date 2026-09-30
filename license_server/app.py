from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request

from license_server.admin_routes import SECURITY_HEADERS, create_admin_router
from license_server.config import (
    DEFAULT_ENVIRONMENT,
    is_production_environment,
    load_config,
    validate_admin_access_token_sha256,
)
from license_server.db import initialize_database
from license_server.routes import create_router
from license_server.signer import LicenseSigningIdentity


HEALTHZ_RESPONSE = {"status": "ok"}
HEALTH_RESPONSE = {"status": "ok", "service": "license_server"}


def create_app(
    *,
    database_path: Optional[Path] = None,
    private_key_b64: Optional[str] = None,
    environment: Optional[str] = None,
    admin_enabled: Optional[bool] = None,
    admin_operator_name: Optional[str] = None,
    admin_access_token_sha256: Optional[str] = None,
    runtime_attestation_enabled: Optional[bool] = None,
    runtime_source_commit: Optional[str] = None,
) -> FastAPI:
    if database_path is None or private_key_b64 is None:
        config = load_config()
        environment = environment or config.environment
        database_path = database_path or config.database_path
        private_key_b64 = private_key_b64 or config.private_key_b64
        admin_enabled = config.admin_enabled if admin_enabled is None else admin_enabled
        admin_operator_name = admin_operator_name or config.admin_operator_name
        admin_access_token_sha256 = (
            admin_access_token_sha256 or config.admin_access_token_sha256
        )
        runtime_attestation_enabled = (
            config.runtime_attestation_enabled
            if runtime_attestation_enabled is None
            else runtime_attestation_enabled
        )
        runtime_source_commit = (
            runtime_source_commit or config.runtime_source_commit
        )
    environment = environment or DEFAULT_ENVIRONMENT
    signing_identity = LicenseSigningIdentity(
        str(private_key_b64),
        source="private_key_b64",
    )
    admin_enabled = bool(admin_enabled)
    if admin_enabled:
        validate_admin_access_token_sha256(admin_access_token_sha256)
    runtime_attestation_server = None
    if runtime_attestation_enabled:
        if environment != "production":
            raise RuntimeError(
                "LICENSE_RUNTIME_ATTESTATION_ENABLED requires production."
            )
        from license_server.runtime_attestation import RuntimeAttestationServer

        runtime_attestation_server = RuntimeAttestationServer(
            signing_identity=signing_identity,
            source_commit=str(runtime_source_commit or ""),
        )
    initialize_database(Path(database_path))
    app = FastAPI(
        title="WHUT Campus Auto Login License Server",
        lifespan=(
            runtime_attestation_server.lifespan
            if runtime_attestation_server is not None
            else None
        ),
    )
    if runtime_attestation_server is not None:
        app.state.runtime_attestation_server = runtime_attestation_server
    _add_admin_security_headers(app)
    _add_health_route(app)
    app.include_router(
        create_router(
            database_path=Path(database_path),
            signing_identity=signing_identity,
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
    runtime_attestation = os.environ.get(
        "LICENSE_RUNTIME_ATTESTATION_ENABLED",
        "",
    ).strip().lower()
    return runtime_attestation not in {"", "0", "false", "no", "off"}


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