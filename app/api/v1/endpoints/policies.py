from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from pydantic import UUID4
from sqlalchemy import ColumnElement

from app.api.deps import AdminDep, AuditDep, DatabaseDep, MetaDep, PageDep, actor_for
from app.core.exceptions import ADMIN_ERROR_CODES, error_responses
from app.core.roles import Role
from app.models.enums import PolicyKind
from app.models.policy import Policy
from app.repositories.base import contains
from app.schemas.common import Page, SortOrder, build_page
from app.schemas.policy import PolicyCreate, PolicyRead, PolicyUpdate
from app.services.policies import PolicyService

router = APIRouter(prefix="/policies", tags=["policies"])


class PolicySort(StrEnum):
    CREATED_AT = "createdAt"
    NAME = "name"
    KIND = "kind"
    VERSION = "version"


def get_policy_service(database: DatabaseDep, audit: AuditDep) -> PolicyService:
    return PolicyService(database, audit)


ServiceDep = Annotated[PolicyService, Depends(get_policy_service)]


@router.get(
    "",
    response_model=Page[PolicyRead],
    status_code=200,
    summary="List policies",
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def list_policies(
    _: AdminDep,
    service: ServiceDep,
    page: PageDep,
    sort: Annotated[PolicySort, Query(description="Sort field.")] = PolicySort.CREATED_AT,
    order: Annotated[SortOrder, Query(description="Sort direction.")] = SortOrder.ASC,
    kind: PolicyKind | None = None,
    scope_task_id: Annotated[UUID4 | None, Query(alias="scopeTaskId")] = None,
    enabled: bool | None = None,
    q: Annotated[str | None, Query(max_length=100, description="Name contains.")] = None,
) -> Page[PolicyRead]:
    criteria: list[ColumnElement[bool]] = []
    if kind is not None:
        criteria.append(Policy.kind == kind)
    if scope_task_id is not None:
        criteria.append(Policy.scope_task_id == scope_task_id)
    if enabled is not None:
        criteria.append(Policy.enabled.is_(enabled))
    if q:
        criteria.append(contains(Policy.name, q))
    rows, total = await service.paginate(
        criteria=criteria,
        sort=sort.name.lower(),
        descending=order is SortOrder.DESC,
        limit=page.limit,
        offset=page.offset,
    )
    return build_page(PolicyRead, rows, total, page)


@router.post(
    "",
    response_model=PolicyRead,
    status_code=201,
    summary="Create policy",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 409),
)
async def create_policy(
    body: PolicyCreate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> PolicyRead:
    entity = await service.create(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, Policy(**body.model_dump())
    )
    return PolicyRead.model_validate(entity)


@router.get(
    "/{policy_id}",
    response_model=PolicyRead,
    status_code=200,
    summary="Get policy",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def get_policy(policy_id: UUID4, _: AdminDep, service: ServiceDep) -> PolicyRead:
    return PolicyRead.model_validate(await service.get(policy_id))


@router.patch(
    "/{policy_id}",
    response_model=PolicyRead,
    status_code=200,
    summary="Update policy",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def update_policy(
    policy_id: UUID4, body: PolicyUpdate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> PolicyRead:
    entity = await service.update(
        actor_for(admin, Role.GOVERNANCE_ADMIN),
        meta,
        policy_id,
        body.model_dump(exclude_unset=True),
    )
    return PolicyRead.model_validate(entity)


@router.delete(
    "/{policy_id}",
    status_code=204,
    summary="Delete policy",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def delete_policy(
    policy_id: UUID4, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> Response:
    await service.delete(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, policy_id)
    return Response(status_code=204)
