from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from pydantic import UUID4
from sqlalchemy import ColumnElement

from app.api.deps import AdminDep, AuditDep, DatabaseDep, MetaDep, PageDep, actor_for
from app.core.exceptions import ADMIN_ERROR_CODES, error_responses
from app.core.roles import Role
from app.models.enums import QuotaKind, QuotaScope
from app.models.quota import Quota
from app.schemas.common import Page, SortOrder, build_page
from app.schemas.quota import QuotaCreate, QuotaRead, QuotaUpdate
from app.services.quotas import QuotaService

router = APIRouter(prefix="/quotas", tags=["quotas"])


class QuotaSort(StrEnum):
    CREATED_AT = "createdAt"
    SCOPE_TYPE = "scopeType"
    SCOPE_REF = "scopeRef"
    LIMIT_VALUE = "limitValue"


def get_quota_service(database: DatabaseDep, audit: AuditDep) -> QuotaService:
    return QuotaService(database, audit)


ServiceDep = Annotated[QuotaService, Depends(get_quota_service)]


@router.get(
    "",
    response_model=Page[QuotaRead],
    status_code=200,
    summary="List quotas",
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def list_quotas(
    _: AdminDep,
    service: ServiceDep,
    page: PageDep,
    sort: Annotated[QuotaSort, Query(description="Sort field.")] = QuotaSort.CREATED_AT,
    order: Annotated[SortOrder, Query(description="Sort direction.")] = SortOrder.ASC,
    scope_type: Annotated[QuotaScope | None, Query(alias="scopeType")] = None,
    scope_ref: Annotated[str | None, Query(alias="scopeRef", max_length=255)] = None,
    kind: QuotaKind | None = None,
    enabled: bool | None = None,
) -> Page[QuotaRead]:
    criteria: list[ColumnElement[bool]] = []
    if scope_type is not None:
        criteria.append(Quota.scope_type == scope_type)
    if scope_ref:
        criteria.append(Quota.scope_ref == scope_ref)
    if kind is not None:
        criteria.append(Quota.kind == kind)
    if enabled is not None:
        criteria.append(Quota.enabled.is_(enabled))
    rows, total = await service.paginate(
        criteria=criteria,
        sort=sort.name.lower(),
        descending=order is SortOrder.DESC,
        limit=page.limit,
        offset=page.offset,
    )
    return build_page(QuotaRead, rows, total, page)


@router.post(
    "",
    response_model=QuotaRead,
    status_code=201,
    summary="Create quota",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 409),
)
async def create_quota(
    body: QuotaCreate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> QuotaRead:
    entity = await service.create(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, Quota(**body.model_dump())
    )
    return QuotaRead.model_validate(entity)


@router.get(
    "/{quota_id}",
    response_model=QuotaRead,
    status_code=200,
    summary="Get quota",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def get_quota(quota_id: UUID4, _: AdminDep, service: ServiceDep) -> QuotaRead:
    return QuotaRead.model_validate(await service.get(quota_id))


@router.patch(
    "/{quota_id}",
    response_model=QuotaRead,
    status_code=200,
    summary="Update quota",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def update_quota(
    quota_id: UUID4, body: QuotaUpdate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> QuotaRead:
    entity = await service.update(
        actor_for(admin, Role.GOVERNANCE_ADMIN),
        meta,
        quota_id,
        body.model_dump(exclude_unset=True),
    )
    return QuotaRead.model_validate(entity)


@router.delete(
    "/{quota_id}",
    status_code=204,
    summary="Delete quota",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def delete_quota(
    quota_id: UUID4, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> Response:
    await service.delete(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, quota_id)
    return Response(status_code=204)
