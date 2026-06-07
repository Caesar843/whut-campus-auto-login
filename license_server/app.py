from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI

from license_server.config import load_config
from license_server.db import initialize_database
from license_server.routes import create_router


HEALTH_RESPONSE = {"status": "ok", "service": "license_server"}


def create_app(
    *,
    database_path: Optional[Path] = None,
    private_key_b64: Optional[str] = None,
    admin_token: Optional[str] = None,
) -> FastAPI:
    if database_path is None or private_key_b64 is None or admin_token is None:
        config = load_config()
        database_path = database_path or config.database_path
        private_key_b64 = private_key_b64 or config.private_key_b64
        admin_token = admin_token or config.admin_token
    initialize_database(Path(database_path))
    app = FastAPI(title="WHUT Campus Auto Login License Server")
    _add_health_route(app)
    app.include_router(
        create_router(
            database_path=Path(database_path),
            private_key_b64=str(private_key_b64),
            admin_token=str(admin_token),
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
