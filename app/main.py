"""Application factory and lifespan."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from app.api import health
from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.metrics import Metrics
from app.core.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.security import TokenVerifier, build_key_provider
from app.db.session import Database
from app.services.audit import AuditService
from app.services.provider import LocalProvider, ProviderGateway
from app.services.rate_limiter import RateLimiter
from app.services.security_events import SecurityEventRecorder

logger = structlog.get_logger(__name__)
RATE_COUNTER_PURGE_SECONDS = 60


VALIDATION_SCHEMAS = ("HTTPValidationError", "ValidationError")


def install_openapi(app: FastAPI) -> None:
    """Document the 400 problem response instead of FastAPI's default 422 validation response."""

    def build() -> dict[str, Any]:  # Any: an OpenAPI document is arbitrary JSON.
        if app.openapi_schema is None:
            schema = get_openapi(
                title=app.title,
                version=app.version,
                description=app.description,
                routes=app.routes,
            )
            for operations in schema["paths"].values():
                for operation in operations.values():
                    operation["responses"].pop("422", None)
            for name in VALIDATION_SCHEMAS:
                schema.get("components", {}).get("schemas", {}).pop(name, None)
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = build  # type: ignore[method-assign]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        database = Database(settings)
        verifier = TokenVerifier(settings, build_key_provider(settings))
        rate_limiter = RateLimiter(database)
        app.state.database = database
        app.state.verifier = verifier
        app.state.rate_limiter = rate_limiter
        app.state.recorder = SecurityEventRecorder(database, app.state.metrics)
        app.state.audit = AuditService(database)
        app.state.provider_gateway = ProviderGateway(LocalProvider(), settings)
        # Start a background task to purge expired rate limit counters every RATE_COUNTER_PURGE_SECONDS 60 seconds.
        purge_task = asyncio.create_task(rate_limiter.purge_forever(RATE_COUNTER_PURGE_SECONDS))  
        logger.info("startup_complete", environment=settings.environment.value)
        try:
            yield
        finally:
            purge_task.cancel()
            with suppress(asyncio.CancelledError):
                await purge_task
            await verifier.aclose()
            await database.dispose()
            logger.info("shutdown_complete")

    app = FastAPI(
        title=settings.app_title,
        version=settings.app_version,
        description=(
            "Centralized Security API: the single controlled entry point for business "
            "applications that use LLMs."
        ),
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings
    app.state.metrics = Metrics()

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production)
    app.add_middleware(RequestContextMiddleware, metrics=app.state.metrics)

    register_exception_handlers(app)
    install_openapi(app)
    app.include_router(health.router)
    app.include_router(api_router)
    return app
