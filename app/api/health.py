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



"""
/health always returns ok. Docker or Kubernetes use it to ask "is the process alive?"
/ready pings the database and checks the signing keys. If either fails, it returns 503 
and the load balancer stops sending traffic. 
It's like a restaurant that's open (alive) but whose kitchen has no gas (not ready).
/metrics exposes Prometheus counters. When a token is configured, it's checked with 
hmac.compare_digest, a comparison that always takes the same time, so an attacker can't
 guess the token one character at a time by measuring response times.

"""


""" 
Phase 3 summary
Routing is three nested routers that build the URL step by step (/api/v1 + /llm + /process).
deps.py is the toolbox. It pulls shared objects from app.state and defines the 
two security gates: PrincipalDep (valid token, with brute-force throttling) and 
AdminDep/AuditorDep/ReviewerDep (role checks).
Endpoints are thin. They parse input, inject dependencies, and call a service. 
No business rules live here
"""