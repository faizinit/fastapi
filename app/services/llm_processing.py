"""The secure processing pipeline behind POST /api/v1/llm/process.

Order of checks (each failure is a standard error plus a security event, and nothing reaches the
provider until all pass):

    identity registered and approved -> no identity override -> task and model recognised ->
    project granted the task and model -> payload size -> request rules -> rate limits and quotas
    -> requestId reserved -> prompt-injection policy -> provider call -> response validation ->
    audit record
"""

import asyncio
import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import NoReturn

from app.core.config import Settings
from app.core.context import Actor, RequestMeta
from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    PayloadTooLargeError,
    PolicyViolationError,
    RateLimitedError,
    ResponseValidationError,
    UpstreamTimeoutError,
)
from app.core.metrics import Metrics
from app.core.roles import Role
from app.core.security import Principal
from app.db.session import Database
from app.models.enums import (
    IdentityStatus,
    LLMRequestStatus,
    PolicyKind,
    ProjectStatus,
    QuotaKind,
    QuotaScope,
    SecurityEventType,
    Severity,
)
from app.models.llm_model import LLMModel
from app.models.llm_request import LLMRequest
from app.models.service_identity import ServiceIdentity
from app.models.task import Task
from app.models.types import JSONObject, JSONValue
from app.repositories.llm_model import LLMModelRepository
from app.repositories.llm_request import LLMRequestRepository
from app.repositories.policy import PolicyRepository
from app.repositories.project_grant import ProjectModelRepository, ProjectTaskRepository
from app.repositories.quota import QuotaRepository
from app.repositories.task import TaskRepository
from app.schemas.llm import LLMProcessRequest, LLMProcessResponse, LLMUsage
from app.services.audit import AuditService
from app.services.identity import IdentityResolver
from app.services.policy_engine import (
    check_request_rules,
    content_rules_from_policies,
    detect_injection,
    request_rules_from_policies,
    response_schemas_from_policies,
    rules_from_policies,
    validate_response,
)
from app.services.provider import GatewayError, ProviderGateway, ProviderRequest
from app.services.rate_limiter import Limit, RateLimiter
from app.services.security_events import SecurityEventRecorder

DENIED_MESSAGE = "The caller is not authorized for this operation."
REJECTED_MESSAGE = "The request was rejected by security policy."


@dataclass(frozen=True, slots=True)
class Context:
    """What the pipeline has established about the request so far."""

    principal: Principal
    meta: RequestMeta
    request: LLMProcessRequest
    identity: ServiceIdentity
    task: Task
    model: LLMModel
    payload_bytes: int
    payload_sha256: str


class LLMProcessingService:
    def __init__(
        self,
        *,
        database: Database,
        settings: Settings,
        recorder: SecurityEventRecorder,
        limiter: RateLimiter,
        gateway: ProviderGateway,
        audit: AuditService,
        metrics: Metrics,
    ) -> None:
        self._database = database
        self._settings = settings
        self._recorder = recorder
        self._limiter = limiter
        self._gateway = gateway
        self._audit = audit
        self._metrics = metrics

    async def process(
        self, principal: Principal, request: LLMProcessRequest, meta: RequestMeta
    ) -> LLMProcessResponse:
        started = time.perf_counter()
        identity = await self._authorize_identity(principal, request, meta)
        task, model = await self._authorize_task_and_model(principal, request, meta, identity)
        payload = request.input.encode("utf-8")
        context = Context(
            principal=principal,
            meta=meta,
            request=request,
            identity=identity,
            task=task,
            model=model,
            payload_bytes=len(payload),
            payload_sha256=hashlib.sha256(payload).hexdigest(),
        )
        await self._check_payload_and_rules(context)
        await self._enforce_limits(context)
        record_id = await self._reserve_request(context)
        await self._screen_for_injection(context, record_id, started)
        output, attempts = await self._call_provider(context, record_id, started)
        await self._validate_output(context, record_id, output, attempts, started)
        await self._finalize(
            context,
            record_id,
            LLMRequestStatus.SUCCEEDED,
            started,
            attempts=attempts,
            output=output,
        )
        return LLMProcessResponse(
            request_id=request.request_id,
            task=task.name,
            model=model.name,
            output=output,
            usage=LLMUsage(
                input_bytes=context.payload_bytes,
                output_bytes=len(output.encode("utf-8")),
                provider_attempts=attempts,
            ),
        )

    # -- authorization ---------------------------------------------------------------------

    async def _authorize_identity(
        self, principal: Principal, request: LLMProcessRequest, meta: RequestMeta
    ) -> ServiceIdentity:
        identity = await IdentityResolver(self._database).find(principal)
        if identity is None:
            await self._deny(principal, request, meta, "unregistered_identity")
        reason = self._identity_problem(identity)
        if reason is not None:
            await self._deny(principal, request, meta, reason, identity=identity)
        if self._overrides_identity(request, identity):
            await self._record(
                SecurityEventType.IDENTITY_OVERRIDE,
                Severity.CRITICAL,
                principal,
                request,
                meta,
                identity=identity,
                details={"suppliedProjectId": request.project_id, "suppliedTeam": request.team},
            )
            self._count("unknown", "rejected")
            raise ForbiddenError(DENIED_MESSAGE)
        return identity

    @staticmethod
    def _overrides_identity(request: LLMProcessRequest, identity: ServiceIdentity) -> bool:
        """True when the body names a different project or team than the trusted identity."""
        project = identity.project
        wrong_project = request.project_id not in (None, project.project_key, str(project.id))
        wrong_team = request.team not in (None, project.team)
        return wrong_project or wrong_team

    @staticmethod
    def _identity_problem(identity: ServiceIdentity) -> str | None:
        if identity.status is not IdentityStatus.APPROVED:
            return f"identity_{identity.status.value}"
        if Role.SERVICE.value not in identity.roles:
            return "missing_service_role"
        project = identity.project
        if project.deleted_at is not None or project.status is not ProjectStatus.ACTIVE:
            return "project_inactive"
        return None

    async def _authorize_task_and_model(
        self,
        principal: Principal,
        request: LLMProcessRequest,
        meta: RequestMeta,
        identity: ServiceIdentity,
    ) -> tuple[Task, LLMModel]:
        async with self._database.read_sessions() as session:
            task = await TaskRepository(session).get_by_name(request.task)
            model = await LLMModelRepository(session).get_by_name(request.model)
            task_granted = task is not None and await ProjectTaskRepository(session).is_granted(
                identity.project_id, task.id
            )
            model_granted = model is not None and await ProjectModelRepository(session).is_granted(
                identity.project_id, model.id
            )
        if task is None or not task.enabled:
            await self._invalid(
                principal,
                request,
                meta,
                identity,
                reason="unknown_task",
                message="The requested task is not recognised.",
            )
        if model is None or not model.enabled:
            await self._invalid(
                principal,
                request,
                meta,
                identity,
                reason="unknown_model",
                message="The requested model is not recognised.",
                task=task.name,
            )
        if not task_granted:
            await self._deny(principal, request, meta, "task_not_granted", identity=identity)
        if not model_granted:
            await self._deny(principal, request, meta, "model_not_granted", identity=identity)
        return task, model

    # -- request validation ----------------------------------------------------------------

    async def _check_payload_and_rules(self, context: Context) -> None:
        task = context.task
        if context.payload_bytes > task.max_payload_bytes:
            await self._record(
                SecurityEventType.PAYLOAD_TOO_LARGE,
                Severity.WARNING,
                context.principal,
                context.request,
                context.meta,
                identity=context.identity,
                details={"bytes": context.payload_bytes, "limit": task.max_payload_bytes},
            )
            self._count(task.name, "rejected")
            raise PayloadTooLargeError(
                f"The input exceeds the {task.max_payload_bytes}-byte limit for this task."
            )
        async with self._database.read_sessions() as session:
            policies = await PolicyRepository(session).active_for_task(
                task.id, PolicyKind.REQUEST_RULE
            )
        violations = check_request_rules(
            context.request.input, context.request.parameters, request_rules_from_policies(policies)
        )
        if violations:
            details: list[JSONValue] = list(violations)
            await self._record(
                SecurityEventType.INVALID_REQUEST,
                Severity.WARNING,
                context.principal,
                context.request,
                context.meta,
                identity=context.identity,
                details={"violations": details},
            )
            self._count(task.name, "rejected")
            raise PolicyViolationError("The request violates the rules for this task.")

    async def _enforce_limits(self, context: Context) -> None:
        identity, task = context.identity, context.task
        client_id = context.principal.client_id
        scopes = [
            (QuotaScope.CALLER, client_id),
            (QuotaScope.TEAM, identity.project.team),
            (QuotaScope.PROJECT, identity.project.project_key),
            (QuotaScope.TASK, task.name),
        ]
        async with self._database.read_sessions() as session:
            quotas = await QuotaRepository(session).enabled_for(scopes)
        limits = [
            Limit(
                f"{q.scope_type.value}:{q.scope_ref}:{q.kind.value}:{q.window_seconds}",
                q.limit_value,
                q.window_seconds,
                q.kind.value,
            )
            for q in quotas
        ]
        has_caller_rate = any(
            q.scope_type is QuotaScope.CALLER and q.kind is QuotaKind.RATE for q in quotas
        )
        if not has_caller_rate:
            limits.append(
                Limit(
                    f"default:caller:{client_id}",
                    self._settings.default_caller_rate_limit_per_minute,
                    60,
                    QuotaKind.RATE.value,
                )
            )
        decision = await self._limiter.consume(limits)
        if decision.allowed:
            return
        violated = decision.violated
        is_quota = violated is not None and violated.label == QuotaKind.QUOTA.value
        await self._record(
            SecurityEventType.QUOTA_EXCEEDED if is_quota else SecurityEventType.RATE_LIMITED,
            Severity.WARNING,
            context.principal,
            context.request,
            context.meta,
            identity=identity,
            details={"scope": violated.key if violated else None},
        )
        self._count(task.name, "rejected")
        raise RateLimitedError(retry_after_seconds=decision.retry_after_seconds)

    async def _reserve_request(self, context: Context) -> uuid.UUID:
        """Claim the requestId for this project; a repeat is a conflict."""
        record = LLMRequest(
            project_id=context.identity.project_id,
            service_identity_id=context.identity.id,
            request_id=context.request.request_id,
            correlation_id=context.meta.correlation_id,
            task_name=context.task.name,
            task_id=context.task.id,
            model_name=context.model.name,
            model_id=context.model.id,
            status=LLMRequestStatus.RECEIVED,
            request_bytes=context.payload_bytes,
            request_sha256=context.payload_sha256,
        )
        try:
            async with self._database.write_session() as session:
                await LLMRequestRepository(session).add(record)
        except ConflictError:
            await self._record(
                SecurityEventType.DUPLICATE_REQUEST,
                Severity.WARNING,
                context.principal,
                context.request,
                context.meta,
                identity=context.identity,
                details={},
            )
            self._count(context.task.name, "rejected")
            raise ConflictError(
                "A request with this requestId was already submitted for this project."
            ) from None
        return record.id

    # -- policy and provider ---------------------------------------------------------------

    async def _screen_for_injection(
        self, context: Context, record_id: uuid.UUID, started: float
    ) -> None:
        async with self._database.read_sessions() as session:
            policies = await PolicyRepository(session).active_for_task(
                context.task.id, PolicyKind.PROMPT_INJECTION
            )
        matched = await asyncio.to_thread(
            detect_injection, context.request.input, rules_from_policies(policies)
        )
        if not matched:
            return
        await self._finalize(
            context, record_id, LLMRequestStatus.REJECTED, started, error_code="prompt_injection"
        )
        rule_ids: list[JSONValue] = list(matched)
        await self._record(
            SecurityEventType.PROMPT_INJECTION,
            Severity.CRITICAL,
            context.principal,
            context.request,
            context.meta,
            identity=context.identity,
            llm_request_id=record_id,
            details={"ruleIds": rule_ids},
        )
        raise PolicyViolationError(REJECTED_MESSAGE)

    async def _call_provider(
        self, context: Context, record_id: uuid.UUID, started: float
    ) -> tuple[str, int]:
        parameters = context.request.parameters
        provider_request = ProviderRequest(
            model=context.model.name,
            task=context.task.name,
            text=context.request.input,
            temperature=parameters.temperature if parameters else None,
            max_tokens=parameters.max_tokens if parameters else None,
        )
        call_started = time.perf_counter()
        try:
            result = await self._gateway.complete(provider_request)
        except GatewayError as failure:
            self._metrics.provider_duration.observe(time.perf_counter() - call_started)
            await self._fail_provider(context, record_id, started, failure)
        self._metrics.provider_duration.observe(time.perf_counter() - call_started)
        return result.output, result.attempts

    async def _fail_provider(
        self, context: Context, record_id: uuid.UUID, started: float, failure: GatewayError
    ) -> NoReturn:
        timed_out = isinstance(failure.error, UpstreamTimeoutError)
        await self._finalize(
            context,
            record_id,
            LLMRequestStatus.TIMEOUT if timed_out else LLMRequestStatus.PROVIDER_ERROR,
            started,
            attempts=failure.attempts,
            error_code="upstream_timeout" if timed_out else "provider_unavailable",
        )
        await self._record(
            SecurityEventType.PROVIDER_FAILURE,
            Severity.WARNING,
            context.principal,
            context.request,
            context.meta,
            identity=context.identity,
            llm_request_id=record_id,
            details={"attempts": failure.attempts, "timedOut": timed_out},
        )
        raise failure.error

    async def _validate_output(
        self,
        context: Context,
        record_id: uuid.UUID,
        output: str,
        attempts: int,
        started: float,
    ) -> None:
        async with self._database.read_sessions() as session:
            policies = await PolicyRepository(session).active_for_task(
                context.task.id, PolicyKind.RESPONSE_SCHEMA, PolicyKind.CONTENT_SECURITY
            )
        schemas = response_schemas_from_policies(
            [p for p in policies if p.kind is PolicyKind.RESPONSE_SCHEMA]
        )
        content = content_rules_from_policies(
            [p for p in policies if p.kind is PolicyKind.CONTENT_SECURITY]
        )
        violations = await asyncio.to_thread(
            validate_response,
            output,
            schemas=schemas,
            content_rules=content,
            max_bytes=self._settings.max_response_bytes,
        )
        if not violations:
            return
        await self._finalize(
            context,
            record_id,
            LLMRequestStatus.RESPONSE_INVALID,
            started,
            attempts=attempts,
            error_code="response_invalid",
        )
        details: list[JSONValue] = list(violations)
        await self._record(
            SecurityEventType.RESPONSE_INVALID,
            Severity.WARNING,
            context.principal,
            context.request,
            context.meta,
            identity=context.identity,
            llm_request_id=record_id,
            details={"violations": details},
        )
        raise ResponseValidationError("The provider response failed validation.")

    # -- bookkeeping -----------------------------------------------------------------------

    async def _finalize(
        self,
        context: Context,
        record_id: uuid.UUID,
        status: LLMRequestStatus,
        started: float,
        *,
        attempts: int = 0,
        error_code: str | None = None,
        output: str | None = None,
    ) -> None:
        """Update the request record and append the audit entry in one transaction.

        If this cannot be persisted the request fails with 503 instead of returning an
        unaudited result.
        """
        latency_ms = int((time.perf_counter() - started) * 1000)
        async with self._database.write_session() as session:
            record = await LLMRequestRepository(session).get(record_id)
            if record is None:  # pragma: no cover - the row was just reserved
                raise DependencyUnavailableError("The request record is unavailable.")
            record.status = status
            record.error_code = error_code
            record.latency_ms = latency_ms
            record.provider_attempts = attempts
            if output is not None:
                encoded = output.encode("utf-8")
                record.response_bytes = len(encoded)
                record.response_sha256 = hashlib.sha256(encoded).hexdigest()
            await session.flush()
            await self._audit.append(
                session,
                actor=Actor(context.principal.subject, Role.SERVICE.value),
                action="llm.process",
                resource_type="llm_request",
                resource_id=str(record_id),
                outcome=status.value,
                meta=context.meta,
                request_id=context.request.request_id,
                details={
                    "project": context.identity.project.project_key,
                    "task": context.task.name,
                    "model": context.model.name,
                    "status": status.value,
                    "errorCode": error_code,
                    "latencyMs": latency_ms,
                    "attempts": attempts,
                },
            )
        self._count(context.task.name, status.value)

    async def _deny(
        self,
        principal: Principal,
        request: LLMProcessRequest,
        meta: RequestMeta,
        reason: str,
        *,
        identity: ServiceIdentity | None = None,
    ) -> NoReturn:
        await self._record(
            SecurityEventType.ACCESS_DENIED,
            Severity.WARNING,
            principal,
            request,
            meta,
            identity=identity,
            details={"reason": reason},
        )
        self._count("unknown", "rejected")
        raise ForbiddenError(DENIED_MESSAGE)

    async def _invalid(
        self,
        principal: Principal,
        request: LLMProcessRequest,
        meta: RequestMeta,
        identity: ServiceIdentity,
        *,
        reason: str,
        message: str,
        task: str = "unknown",
    ) -> NoReturn:
        await self._record(
            SecurityEventType.INVALID_REQUEST,
            Severity.WARNING,
            principal,
            request,
            meta,
            identity=identity,
            details={"reason": reason},
        )
        self._count(task, "rejected")
        raise BadRequestError(message)

    async def _record(
        self,
        event_type: SecurityEventType,
        severity: Severity,
        principal: Principal,
        request: LLMProcessRequest,
        meta: RequestMeta,
        *,
        identity: ServiceIdentity | None,
        details: JSONObject,
        llm_request_id: uuid.UUID | None = None,
    ) -> None:
        await self._recorder.try_record(
            event_type,
            severity,
            request_id=request.request_id,
            correlation_id=meta.correlation_id,
            llm_request_id=llm_request_id,
            project_id=identity.project_id if identity else None,
            service_identity_id=identity.id if identity else None,
            caller_sub=principal.subject,
            source_ip=meta.source_ip,
            details=details,
        )

    def _count(self, task: str, outcome: str) -> None:
        self._metrics.llm_requests.labels(task, outcome).inc()
