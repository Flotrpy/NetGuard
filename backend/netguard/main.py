"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netguard import __version__
from netguard.api import auth
from netguard.config import get_settings
from netguard.core.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from netguard.db import init_db
from netguard.logging import configure_logging, get_logger

log = get_logger("main")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    settings.resolved_secret_key()  # fail fast on a missing/weak production secret
    settings.ensure_dirs()
    init_db(settings)

    app = FastAPI(
        title="NetGuard API",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    # Middleware executes bottom-up: request context wraps everything.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"],
    )
    app.add_middleware(RequestContextMiddleware)

    app.include_router(auth.router)

    @app.get("/api/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    return app
