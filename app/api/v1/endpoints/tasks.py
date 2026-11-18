from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from pydantic import UUID4
from sqlalchemy import ColumnElement

from app.api.deps import AdminDep, AuditDep, DatabaseDep, MetaDep, PageDep, actor_for
from app.core.exceptions import ADMIN_ERROR_CODES, error_responses
from app.core.roles import Role
from app.models.task import Task
from app.repositories.base import contains
from app.schemas.common import Page, SortOrder, build_page
from app.schemas.task import TaskCreate, TaskRead, TaskUpdate
from app.services.tasks import TaskService

router = APIRouter(prefix="/tasks", tags=["tasks"])


class TaskSort(StrEnum):
    CREATED_AT = "createdAt"
    NAME = "name"


def get_task_service(database: DatabaseDep, audit: AuditDep) -> TaskService:
    return TaskService(database, audit)


ServiceDep = Annotated[TaskService, Depends(get_task_service)]


@router.get(
    "",
    response_model=Page[TaskRead],
    status_code=200,
    summary="List tasks",
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def list_tasks(
    _: AdminDep,
    service: ServiceDep,
    page: PageDep,
    sort: Annotated[TaskSort, Query(description="Sort field.")] = TaskSort.CREATED_AT,
    order: Annotated[SortOrder, Query(description="Sort direction.")] = SortOrder.ASC,
    enabled: bool | None = None,
    q: Annotated[str | None, Query(max_length=100, description="Name contains.")] = None,
) -> Page[TaskRead]:
    criteria: list[ColumnElement[bool]] = []
    if enabled is not None:
        criteria.append(Task.enabled.is_(enabled))
    if q:
        criteria.append(contains(Task.name, q))
    rows, total = await service.paginate(
        criteria=criteria,
        sort=sort.name.lower(),
        descending=order is SortOrder.DESC,
        limit=page.limit,
        offset=page.offset,
    )
    return build_page(TaskRead, rows, total, page)


@router.post(
    "",
    response_model=TaskRead,
    status_code=201,
    summary="Create task",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 409),
)
async def create_task(
    body: TaskCreate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> TaskRead:
    entity = await service.create(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, Task(**body.model_dump())
    )
    return TaskRead.model_validate(entity)


@router.get(
    "/{task_id}",
    response_model=TaskRead,
    status_code=200,
    summary="Get task",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def get_task(task_id: UUID4, _: AdminDep, service: ServiceDep) -> TaskRead:
    return TaskRead.model_validate(await service.get(task_id))


@router.patch(
    "/{task_id}",
    response_model=TaskRead,
    status_code=200,
    summary="Update task",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def update_task(
    task_id: UUID4, body: TaskUpdate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> TaskRead:
    entity = await service.update(
        actor_for(admin, Role.GOVERNANCE_ADMIN),
        meta,
        task_id,
        body.model_dump(exclude_unset=True),
    )
    return TaskRead.model_validate(entity)


@router.delete(
    "/{task_id}",
    status_code=204,
    summary="Delete task",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def delete_task(
    task_id: UUID4, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> Response:
    await service.delete(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, task_id)
    return Response(status_code=204)
