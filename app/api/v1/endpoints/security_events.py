from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import UUID4, AwareDatetime
from sqlalchemy import ColumnElement

from app.api.deps import AuditDep, DatabaseDep, MetaDep, PageDep, ReviewerDep, actor_for
from app.core.exceptions import ADMIN_ERROR_CODES, error_responses
from app.core.roles import Role
from app.models.enums import SecurityEventType, Severity
from app.models.security_event import SecurityEvent
from app.models.types import JSONObject
from app.schemas.audit import SecurityEventRead
from app.schemas.common import Page, build_page
from app.services.log_access import LogAccessService

router = APIRouter(prefix="/security-events", tags=["security-events"])


def get_log_access_service(database: DatabaseDep, audit: AuditDep) -> LogAccessService:
    return LogAccessService(database, audit)


ServiceDep = Annotated[LogAccessService, Depends(get_log_access_service)]


@router.get(
    "",
    response_model=Page[SecurityEventRead],
    status_code=200,
    summary="List security events",
    description="Newest first. Restricted to audit reviewers and governance admins.",
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def list_security_events(
    reviewer: ReviewerDep,
    service: ServiceDep,
    page: PageDep,
    meta: MetaDep,
    event_type: Annotated[SecurityEventType | None, Query(alias="eventType")] = None,
    severity: Severity | None = None,
    project_id: Annotated[UUID4 | None, Query(alias="projectId")] = None,
    request_id: Annotated[str | None, Query(alias="requestId", max_length=128)] = None,
    correlation_id: Annotated[str | None, Query(alias="correlationId", max_length=128)] = None,
    caller_sub: Annotated[str | None, Query(alias="callerSub", max_length=255)] = None,
    occurred_from: Annotated[AwareDatetime | None, Query(alias="occurredFrom")] = None,
    occurred_to: Annotated[AwareDatetime | None, Query(alias="occurredTo")] = None,
) -> Page[SecurityEventRead]:
    criteria: list[ColumnElement[bool]] = []
    filters: JSONObject = {}
    if event_type is not None:
        criteria.append(SecurityEvent.event_type == event_type)
        filters["eventType"] = event_type.value
    if severity is not None:
        criteria.append(SecurityEvent.severity == severity)
        filters["severity"] = severity.value
    if project_id is not None:
        criteria.append(SecurityEvent.project_id == project_id)
        filters["projectId"] = str(project_id)
    for label, column, value in (
        ("requestId", SecurityEvent.request_id, request_id),
        ("correlationId", SecurityEvent.correlation_id, correlation_id),
        ("callerSub", SecurityEvent.caller_sub, caller_sub),
    ):
        if value is not None:
            criteria.append(column == value)
            filters[label] = value
    if occurred_from is not None:
        criteria.append(SecurityEvent.occurred_at >= occurred_from)
        filters["occurredFrom"] = occurred_from.isoformat()
    if occurred_to is not None:
        criteria.append(SecurityEvent.occurred_at <= occurred_to)
        filters["occurredTo"] = occurred_to.isoformat()
    rows, total = await service.list_security_events(
        actor_for(reviewer, _reviewer_role(reviewer.has_any_role(Role.AUDIT_REVIEWER))),
        meta,
        criteria=criteria,
        limit=page.limit,
        offset=page.offset,
        filters=filters,
    )
    return build_page(SecurityEventRead, rows, total, page)


@router.get(
    "/{event_id}",
    response_model=SecurityEventRead,
    status_code=200,
    summary="Get a security event",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def get_security_event(
    event_id: UUID4, reviewer: ReviewerDep, service: ServiceDep, meta: MetaDep
) -> SecurityEventRead:
    event = await service.get_security_event(
        actor_for(reviewer, _reviewer_role(reviewer.has_any_role(Role.AUDIT_REVIEWER))),
        meta,
        event_id,
    )
    return SecurityEventRead.model_validate(event)


def _reviewer_role(is_auditor: bool) -> Role:
    return Role.AUDIT_REVIEWER if is_auditor else Role.GOVERNANCE_ADMIN
