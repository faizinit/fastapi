from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import UUID4, AwareDatetime
from sqlalchemy import ColumnElement

from app.api.deps import AuditDep, AuditorDep, DatabaseDep, MetaDep, PageDep, actor_for
from app.core.exceptions import ADMIN_ERROR_CODES, error_responses
from app.core.roles import Role
from app.models.audit_log import AuditLog
from app.models.types import JSONObject
from app.schemas.audit import AuditLogRead, AuditVerifyRead
from app.schemas.common import Page, build_page
from app.services.log_access import LogAccessService

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])

MAX_SEQ = 2**62


def get_log_access_service(database: DatabaseDep, audit: AuditDep) -> LogAccessService:
    return LogAccessService(database, audit)


ServiceDep = Annotated[LogAccessService, Depends(get_log_access_service)]


@router.get(
    "",
    response_model=Page[AuditLogRead],
    status_code=200,
    summary="List audit log entries",
    description="Newest first. Restricted to audit reviewers; each read is itself audited.",
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def list_audit_logs(
    reviewer: AuditorDep,
    service: ServiceDep,
    page: PageDep,
    meta: MetaDep,
    actor: Annotated[str | None, Query(max_length=255, description="Actor subject.")] = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    resource_type: Annotated[str | None, Query(alias="resourceType", max_length=50)] = None,
    resource_id: Annotated[str | None, Query(alias="resourceId", max_length=128)] = None,
    request_id: Annotated[str | None, Query(alias="requestId", max_length=128)] = None,
    correlation_id: Annotated[str | None, Query(alias="correlationId", max_length=128)] = None,
    occurred_from: Annotated[AwareDatetime | None, Query(alias="occurredFrom")] = None,
    occurred_to: Annotated[AwareDatetime | None, Query(alias="occurredTo")] = None,
) -> Page[AuditLogRead]:
    criteria: list[ColumnElement[bool]] = []
    filters: JSONObject = {}
    for label, column, value in (
        ("actor", AuditLog.actor_sub, actor),
        ("action", AuditLog.action, action),
        ("resourceType", AuditLog.resource_type, resource_type),
        ("resourceId", AuditLog.resource_id, resource_id),
        ("requestId", AuditLog.request_id, request_id),
        ("correlationId", AuditLog.correlation_id, correlation_id),
    ):
        if value is not None:
            criteria.append(column == value)
            filters[label] = value
    if occurred_from is not None:
        criteria.append(AuditLog.occurred_at >= occurred_from)
        filters["occurredFrom"] = occurred_from.isoformat()
    if occurred_to is not None:
        criteria.append(AuditLog.occurred_at <= occurred_to)
        filters["occurredTo"] = occurred_to.isoformat()
    rows, total = await service.list_audit_logs(
        actor_for(reviewer, Role.AUDIT_REVIEWER),
        meta,
        criteria=criteria,
        limit=page.limit,
        offset=page.offset,
        filters=filters,
    )
    return build_page(AuditLogRead, rows, total, page)


@router.get(
    "/verify",
    response_model=AuditVerifyRead,
    status_code=200,
    summary="Verify the audit hash chain",
    description=(
        "Recomputes entry hashes and links from `fromSeq`, checking at most 10,000 entries per "
        "call. A broken chain means an entry was altered, removed or inserted out of band."
    ),
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def verify_audit_logs(
    reviewer: AuditorDep,
    service: ServiceDep,
    meta: MetaDep,
    from_seq: Annotated[int, Query(alias="fromSeq", ge=1, le=MAX_SEQ)] = 1,
    to_seq: Annotated[int, Query(alias="toSeq", ge=1, le=MAX_SEQ)] = MAX_SEQ,
) -> AuditVerifyRead:
    result = await service.verify_audit_logs(
        actor_for(reviewer, Role.AUDIT_REVIEWER), meta, from_seq, to_seq
    )
    return AuditVerifyRead(
        valid=result.valid, checked=result.checked, first_broken_seq=result.first_broken_seq
    )


@router.get(
    "/{entry_id}",
    response_model=AuditLogRead,
    status_code=200,
    summary="Get an audit log entry",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def get_audit_log(
    entry_id: UUID4, reviewer: AuditorDep, service: ServiceDep, meta: MetaDep
) -> AuditLogRead:
    entry = await service.get_audit_log(actor_for(reviewer, Role.AUDIT_REVIEWER), meta, entry_id)
    return AuditLogRead.model_validate(entry)
