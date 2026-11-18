from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from pydantic import UUID4
from sqlalchemy import ColumnElement, or_

from app.api.deps import AdminDep, AuditDep, DatabaseDep, MetaDep, PageDep, actor_for
from app.core.exceptions import ADMIN_ERROR_CODES, error_responses
from app.core.roles import Role
from app.models.enums import IdentityStatus
from app.models.service_identity import ServiceIdentity
from app.repositories.base import contains
from app.schemas.common import Page, SortOrder, build_page
from app.schemas.service_identity import (
    IdentityTransition,
    ServiceIdentityCreate,
    ServiceIdentityRead,
    ServiceIdentityUpdate,
)
from app.services.service_identities import ServiceIdentityService

router = APIRouter(prefix="/service-identities", tags=["service-identities"])


class IdentitySort(StrEnum):
    CREATED_AT = "createdAt"
    DISPLAY_NAME = "displayName"
    CLIENT_ID = "clientId"
    STATUS = "status"


def get_identity_service(database: DatabaseDep, audit: AuditDep) -> ServiceIdentityService:
    return ServiceIdentityService(database, audit)


ServiceDep = Annotated[ServiceIdentityService, Depends(get_identity_service)]


@router.get(
    "",
    response_model=Page[ServiceIdentityRead],
    status_code=200,
    summary="List service identities",
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def list_service_identities(
    _: AdminDep,
    service: ServiceDep,
    page: PageDep,
    sort: Annotated[IdentitySort, Query(description="Sort field.")] = IdentitySort.CREATED_AT,
    order: Annotated[SortOrder, Query(description="Sort direction.")] = SortOrder.ASC,
    project_id: Annotated[UUID4 | None, Query(alias="projectId")] = None,
    status: IdentityStatus | None = None,
    q: Annotated[
        str | None, Query(max_length=100, description="Client id or name contains.")
    ] = None,
) -> Page[ServiceIdentityRead]:
    criteria: list[ColumnElement[bool]] = []
    if project_id is not None:
        criteria.append(ServiceIdentity.project_id == project_id)
    if status is not None:
        criteria.append(ServiceIdentity.status == status)
    if q:
        criteria.append(
            or_(contains(ServiceIdentity.client_id, q), contains(ServiceIdentity.display_name, q))
        )
    rows, total = await service.paginate(
        criteria=criteria,
        sort=sort.name.lower(),
        descending=order is SortOrder.DESC,
        limit=page.limit,
        offset=page.offset,
    )
    return build_page(ServiceIdentityRead, rows, total, page)


@router.post(
    "",
    response_model=ServiceIdentityRead,
    status_code=201,
    summary="Create service identity",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 409),
)
async def create_service_identity(
    body: ServiceIdentityCreate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> ServiceIdentityRead:
    entity = await service.create(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, ServiceIdentity(**body.model_dump())
    )
    return ServiceIdentityRead.model_validate(entity)


@router.get(
    "/{identity_id}",
    response_model=ServiceIdentityRead,
    status_code=200,
    summary="Get service identity",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def get_service_identity(
    identity_id: UUID4, _: AdminDep, service: ServiceDep
) -> ServiceIdentityRead:
    return ServiceIdentityRead.model_validate(await service.get(identity_id))


@router.patch(
    "/{identity_id}",
    response_model=ServiceIdentityRead,
    status_code=200,
    summary="Update service identity",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def update_service_identity(
    identity_id: UUID4,
    body: ServiceIdentityUpdate,
    admin: AdminDep,
    service: ServiceDep,
    meta: MetaDep,
) -> ServiceIdentityRead:
    entity = await service.update(
        actor_for(admin, Role.GOVERNANCE_ADMIN),
        meta,
        identity_id,
        body.model_dump(exclude_unset=True),
    )
    return ServiceIdentityRead.model_validate(entity)


@router.delete(
    "/{identity_id}",
    status_code=204,
    summary="Delete service identity",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def delete_service_identity(
    identity_id: UUID4, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> Response:
    await service.delete(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, identity_id)
    return Response(status_code=204)


@router.post(
    "/{identity_id}/approve",
    response_model=ServiceIdentityRead,
    status_code=200,
    summary="Approve a pending service identity",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def approve_service_identity(
    identity_id: UUID4, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> ServiceIdentityRead:
    identity = await service.approve(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, identity_id)
    return ServiceIdentityRead.model_validate(identity)


@router.post(
    "/{identity_id}/revoke",
    response_model=ServiceIdentityRead,
    status_code=200,
    summary="Revoke a service identity",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def revoke_service_identity(
    identity_id: UUID4,
    admin: AdminDep,
    service: ServiceDep,
    meta: MetaDep,
    body: IdentityTransition | None = None,
) -> ServiceIdentityRead:
    reason = body.reason if body else None
    identity = await service.revoke(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, identity_id, reason
    )
    return ServiceIdentityRead.model_validate(identity)
