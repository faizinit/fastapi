"""Shared FastAPI dependencies: settings, services, authentication and role checks."""

from collections.abc import Awaitable, Callable
from typing import Annotated, NoReturn

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings
from app.core.context import Actor, RequestMeta
from app.core.exceptions import (
    DependencyUnavailableError,
    ForbiddenError,
    RateLimitedError,
    UnauthorizedError,
)
from app.core.metrics import Metrics
from app.core.roles import Role
from app.core.security import Principal, TokenVerifier
from app.db.session import Database
from app.models.enums import SecurityEventType, Severity
from app.models.types import JSONValue
from app.schemas.common import PageParams, page_params
from app.services.audit import AuditService
from app.services.provider import ProviderGateway
from app.services.rate_limiter import Limit, RateLimiter
from app.services.security_events import SecurityEventRecorder

bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BearerAuth",
    description="JWT access token issued by the identity provider.",
)


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_database(request: Request) -> Database:
    database: Database = request.app.state.database
    return database


def get_metrics(request: Request) -> Metrics:
    metrics: Metrics = request.app.state.metrics
    return metrics


def get_verifier(request: Request) -> TokenVerifier:
    verifier: TokenVerifier = request.app.state.verifier
    return verifier


def get_recorder(request: Request) -> SecurityEventRecorder:
    recorder: SecurityEventRecorder = request.app.state.recorder
    return recorder


def get_rate_limiter(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.rate_limiter
    return limiter


def get_audit(request: Request) -> AuditService:
    audit: AuditService = request.app.state.audit
    return audit


def get_gateway(request: Request) -> ProviderGateway:
    gateway: ProviderGateway = request.app.state.provider_gateway
    return gateway


def get_request_meta(request: Request) -> RequestMeta:
    request_id = getattr(request.state, "request_id", "unknown")
    source_ip = request.client.host if request.client else None
    return RequestMeta(correlation_id=str(request_id), source_ip=source_ip)


SettingsDep = Annotated[Settings, Depends(get_settings)]
DatabaseDep = Annotated[Database, Depends(get_database)]
MetricsDep = Annotated[Metrics, Depends(get_metrics)]
VerifierDep = Annotated[TokenVerifier, Depends(get_verifier)]
RecorderDep = Annotated[SecurityEventRecorder, Depends(get_recorder)]
RateLimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
AuditDep = Annotated[AuditService, Depends(get_audit)]
MetaDep = Annotated[RequestMeta, Depends(get_request_meta)]
GatewayDep = Annotated[ProviderGateway, Depends(get_gateway)]


async def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    verifier: VerifierDep,
    limiter: RateLimiterDep,
    recorder: RecorderDep,
    settings: SettingsDep,
    meta: MetaDep,
) -> Principal:
    """Authenticate the bearer token on every request; repeated failures per IP are throttled."""
    if credentials is None:
        await _reject_unauthenticated(
            "Authentication is required.", "missing_credentials", limiter, recorder, settings, meta
        )
    try:
        principal = await verifier.verify(credentials.credentials)
    except UnauthorizedError as exc:
        await _reject_unauthenticated(
            exc.detail, "invalid_token", limiter, recorder, settings, meta
        )
        raise
    except DependencyUnavailableError:
        await recorder.try_record(
            SecurityEventType.DEPENDENCY_UNAVAILABLE,
            Severity.CRITICAL,
            correlation_id=meta.correlation_id,
            source_ip=meta.source_ip,
            details={"dependency": "identity_provider"},
        )
        raise
    request.state.principal_id = principal.subject
    return principal


async def _reject_unauthenticated(
    detail: str,
    reason: str,
    limiter: RateLimiter,
    recorder: SecurityEventRecorder,
    settings: Settings,
    meta: RequestMeta,
) -> NoReturn:
    decision = await limiter.consume(
        [
            Limit(
                f"authfail:{meta.source_ip or 'unknown'}",
                settings.auth_failure_limit_per_minute,
                60,
                "auth-failure",
            )
        ]
    )
    await recorder.try_record(
        SecurityEventType.AUTH_FAILED if decision.allowed else SecurityEventType.RATE_LIMITED,
        Severity.WARNING,
        correlation_id=meta.correlation_id,
        source_ip=meta.source_ip,
        details={"reason": reason},
    )
    if not decision.allowed:
        raise RateLimitedError(
            "Too many failed authentication attempts.",
            retry_after_seconds=decision.retry_after_seconds,
        )
    raise UnauthorizedError(detail)


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def require_roles(*roles: Role) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory: the verified token must carry at least one of `roles`."""

    async def dependency(
        principal: PrincipalDep, recorder: RecorderDep, meta: MetaDep
    ) -> Principal:
        if not principal.has_any_role(*roles):
            required: list[JSONValue] = [role.value for role in sorted(roles)]
            await recorder.try_record(
                SecurityEventType.ACCESS_DENIED,
                Severity.WARNING,
                correlation_id=meta.correlation_id,
                caller_sub=principal.subject,
                source_ip=meta.source_ip,
                details={"requiredRoles": required},
            )
            raise ForbiddenError("Your role does not permit this operation.")
        return principal

    return dependency


AdminDep = Annotated[Principal, Depends(require_roles(Role.GOVERNANCE_ADMIN))]
AuditorDep = Annotated[Principal, Depends(require_roles(Role.AUDIT_REVIEWER))]
ReviewerDep = Annotated[
    Principal, Depends(require_roles(Role.AUDIT_REVIEWER, Role.GOVERNANCE_ADMIN))
]


PageDep = Annotated[PageParams, Depends(page_params)]


def actor_for(principal: Principal, role: Role) -> Actor:
    """The audit actor for an authenticated principal acting in `role`."""
    return Actor(subject=principal.subject, role=role.value)
