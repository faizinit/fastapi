"""Operational endpoints: liveness, readiness and metrics (unversioned)."""

import hmac
from typing import Annotated, Literal

from fastapi import APIRouter, Header, Response
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import DatabaseDep, MetricsDep, SettingsDep, VerifierDep
from app.core.exceptions import (
    DependencyUnavailableError,
    NotFoundError,
    UnauthorizedError,
    error_responses,
)

router = APIRouter(tags=["operations"])


class HealthResponse(BaseModel):
    status: Literal["ok"]


class ReadinessResponse(BaseModel):
    status: Literal["ready"]
    checks: dict[str, Literal["ok"]]


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    responses=error_responses(503),
)
async def ready(database: DatabaseDep, verifier: VerifierDep) -> ReadinessResponse:
    try:
        await database.ping()
    except SQLAlchemyError as exc:
        raise DependencyUnavailableError("The database is unavailable.") from exc
    await verifier.check_keys()
    return ReadinessResponse(status="ready", checks={"database": "ok", "identity_provider": "ok"})


@router.get(
    "/metrics",
    summary="Prometheus metrics",
    include_in_schema=False,
    responses=error_responses(401, 404),
)
async def metrics(
    settings: SettingsDep,
    metrics_registry: MetricsDep,
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    if not settings.metrics_enabled:
        raise NotFoundError("Metrics are disabled.")
    if settings.metrics_token is not None:
        expected = f"Bearer {settings.metrics_token.get_secret_value()}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise UnauthorizedError("A valid metrics token is required.")
    return Response(content=metrics_registry.render(), media_type=metrics_registry.content_type)
