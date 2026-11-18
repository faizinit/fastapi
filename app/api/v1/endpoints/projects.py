from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from pydantic import UUID4
from sqlalchemy import ColumnElement, or_

from app.api.deps import AdminDep, AuditDep, DatabaseDep, MetaDep, PageDep, actor_for
from app.core.exceptions import ADMIN_ERROR_CODES, error_responses
from app.core.roles import Role
from app.models.enums import ProjectStatus
from app.models.project import Project, ProjectModel, ProjectTask
from app.repositories.base import contains
from app.schemas.common import Page, SortOrder, build_page
from app.schemas.project import (
    ModelGrantCreate,
    ModelGrantRead,
    ProjectCreate,
    ProjectRead,
    ProjectUpdate,
    TaskGrantCreate,
    TaskGrantRead,
)
from app.services.projects import ProjectGrantService, ProjectService

router = APIRouter(prefix="/projects", tags=["projects"])


class ProjectSort(StrEnum):
    CREATED_AT = "createdAt"
    NAME = "name"
    PROJECT_KEY = "projectKey"
    TEAM = "team"


def get_project_service(database: DatabaseDep, audit: AuditDep) -> ProjectService:
    return ProjectService(database, audit)


ServiceDep = Annotated[ProjectService, Depends(get_project_service)]


@router.get(
    "",
    response_model=Page[ProjectRead],
    status_code=200,
    summary="List projects",
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def list_projects(
    _: AdminDep,
    service: ServiceDep,
    page: PageDep,
    sort: Annotated[ProjectSort, Query(description="Sort field.")] = ProjectSort.CREATED_AT,
    order: Annotated[SortOrder, Query(description="Sort direction.")] = SortOrder.ASC,
    team: Annotated[str | None, Query(max_length=100)] = None,
    status: ProjectStatus | None = None,
    q: Annotated[str | None, Query(max_length=100, description="Name or key contains.")] = None,
) -> Page[ProjectRead]:
    criteria: list[ColumnElement[bool]] = []
    if team:
        criteria.append(Project.team == team)
    if status is not None:
        criteria.append(Project.status == status)
    if q:
        criteria.append(or_(contains(Project.name, q), contains(Project.project_key, q)))
    rows, total = await service.paginate(
        criteria=criteria,
        sort=sort.name.lower(),
        descending=order is SortOrder.DESC,
        limit=page.limit,
        offset=page.offset,
    )
    return build_page(ProjectRead, rows, total, page)


@router.post(
    "",
    response_model=ProjectRead,
    status_code=201,
    summary="Create project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 409),
)
async def create_project(
    body: ProjectCreate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> ProjectRead:
    entity = await service.create(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, Project(**body.model_dump())
    )
    return ProjectRead.model_validate(entity)


@router.get(
    "/{project_id}",
    response_model=ProjectRead,
    status_code=200,
    summary="Get project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def get_project(project_id: UUID4, _: AdminDep, service: ServiceDep) -> ProjectRead:
    return ProjectRead.model_validate(await service.get(project_id))


@router.patch(
    "/{project_id}",
    response_model=ProjectRead,
    status_code=200,
    summary="Update project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def update_project(
    project_id: UUID4, body: ProjectUpdate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> ProjectRead:
    entity = await service.update(
        actor_for(admin, Role.GOVERNANCE_ADMIN),
        meta,
        project_id,
        body.model_dump(exclude_unset=True),
    )
    return ProjectRead.model_validate(entity)


@router.delete(
    "/{project_id}",
    status_code=204,
    summary="Delete project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def delete_project(
    project_id: UUID4, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> Response:
    await service.delete(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, project_id)
    return Response(status_code=204)


def get_grant_service(database: DatabaseDep, audit: AuditDep) -> ProjectGrantService:
    return ProjectGrantService(database, audit)


GrantServiceDep = Annotated[ProjectGrantService, Depends(get_grant_service)]


def _task_grant(grant: ProjectTask) -> TaskGrantRead:
    return TaskGrantRead(
        project_id=grant.project_id,
        task_id=grant.task_id,
        task_name=grant.task.name,
        granted_by=grant.granted_by,
        granted_at=grant.granted_at,
    )


def _model_grant(grant: ProjectModel) -> ModelGrantRead:
    return ModelGrantRead(
        project_id=grant.project_id,
        model_id=grant.model_id,
        model_name=grant.model.name,
        granted_by=grant.granted_by,
        granted_at=grant.granted_at,
    )


@router.get(
    "/{project_id}/tasks",
    response_model=Page[TaskGrantRead],
    status_code=200,
    summary="List tasks granted to a project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def list_project_tasks(
    project_id: UUID4, _: AdminDep, service: GrantServiceDep, page: PageDep
) -> Page[TaskGrantRead]:
    grants, total = await service.list_tasks(project_id, limit=page.limit, offset=page.offset)
    return Page(
        items=[_task_grant(g) for g in grants], total=total, limit=page.limit, offset=page.offset
    )


@router.post(
    "/{project_id}/tasks",
    response_model=TaskGrantRead,
    status_code=201,
    summary="Grant a task to a project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def grant_project_task(
    project_id: UUID4,
    body: TaskGrantCreate,
    admin: AdminDep,
    service: GrantServiceDep,
    meta: MetaDep,
) -> TaskGrantRead:
    grant = await service.grant_task(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, project_id, body.task_id
    )
    return _task_grant(grant)


@router.delete(
    "/{project_id}/tasks/{task_id}",
    status_code=204,
    summary="Revoke a task from a project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def revoke_project_task(
    project_id: UUID4, task_id: UUID4, admin: AdminDep, service: GrantServiceDep, meta: MetaDep
) -> Response:
    await service.revoke_task(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, project_id, task_id)
    return Response(status_code=204)


@router.get(
    "/{project_id}/models",
    response_model=Page[ModelGrantRead],
    status_code=200,
    summary="List models granted to a project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def list_project_models(
    project_id: UUID4, _: AdminDep, service: GrantServiceDep, page: PageDep
) -> Page[ModelGrantRead]:
    grants, total = await service.list_models(project_id, limit=page.limit, offset=page.offset)
    return Page(
        items=[_model_grant(g) for g in grants], total=total, limit=page.limit, offset=page.offset
    )


@router.post(
    "/{project_id}/models",
    response_model=ModelGrantRead,
    status_code=201,
    summary="Grant a model to a project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def grant_project_model(
    project_id: UUID4,
    body: ModelGrantCreate,
    admin: AdminDep,
    service: GrantServiceDep,
    meta: MetaDep,
) -> ModelGrantRead:
    grant = await service.grant_model(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, project_id, body.model_id
    )
    return _model_grant(grant)


@router.delete(
    "/{project_id}/models/{model_id}",
    status_code=204,
    summary="Revoke a model from a project",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def revoke_project_model(
    project_id: UUID4, model_id: UUID4, admin: AdminDep, service: GrantServiceDep, meta: MetaDep
) -> Response:
    await service.revoke_model(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, project_id, model_id)
    return Response(status_code=204)
