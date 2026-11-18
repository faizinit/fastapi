from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from pydantic import UUID4
from sqlalchemy import ColumnElement

from app.api.deps import AdminDep, AuditDep, DatabaseDep, MetaDep, PageDep, actor_for
from app.core.exceptions import ADMIN_ERROR_CODES, error_responses
from app.core.roles import Role
from app.models.llm_model import LLMModel
from app.repositories.base import contains
from app.schemas.common import Page, SortOrder, build_page
from app.schemas.llm_model import ModelCreate, ModelRead, ModelUpdate
from app.services.llm_models import LLMModelService

router = APIRouter(prefix="/models", tags=["models"])


class ModelSort(StrEnum):
    CREATED_AT = "createdAt"
    NAME = "name"
    PROVIDER = "provider"


def get_model_service(database: DatabaseDep, audit: AuditDep) -> LLMModelService:
    return LLMModelService(database, audit)


ServiceDep = Annotated[LLMModelService, Depends(get_model_service)]


@router.get(
    "",
    response_model=Page[ModelRead],
    status_code=200,
    summary="List models",
    responses=error_responses(*ADMIN_ERROR_CODES, 400),
)
async def list_models(
    _: AdminDep,
    service: ServiceDep,
    page: PageDep,
    sort: Annotated[ModelSort, Query(description="Sort field.")] = ModelSort.CREATED_AT,
    order: Annotated[SortOrder, Query(description="Sort direction.")] = SortOrder.ASC,
    enabled: bool | None = None,
    provider: Annotated[str | None, Query(max_length=100)] = None,
    q: Annotated[str | None, Query(max_length=100, description="Name contains.")] = None,
) -> Page[ModelRead]:
    criteria: list[ColumnElement[bool]] = []
    if enabled is not None:
        criteria.append(LLMModel.enabled.is_(enabled))
    if provider:
        criteria.append(LLMModel.provider == provider)
    if q:
        criteria.append(contains(LLMModel.name, q))
    rows, total = await service.paginate(
        criteria=criteria,
        sort=sort.name.lower(),
        descending=order is SortOrder.DESC,
        limit=page.limit,
        offset=page.offset,
    )
    return build_page(ModelRead, rows, total, page)


@router.post(
    "",
    response_model=ModelRead,
    status_code=201,
    summary="Create model",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 409),
)
async def create_model(
    body: ModelCreate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> ModelRead:
    entity = await service.create(
        actor_for(admin, Role.GOVERNANCE_ADMIN), meta, LLMModel(**body.model_dump())
    )
    return ModelRead.model_validate(entity)


@router.get(
    "/{model_id}",
    response_model=ModelRead,
    status_code=200,
    summary="Get model",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def get_model(model_id: UUID4, _: AdminDep, service: ServiceDep) -> ModelRead:
    return ModelRead.model_validate(await service.get(model_id))


@router.patch(
    "/{model_id}",
    response_model=ModelRead,
    status_code=200,
    summary="Update model",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404, 409),
)
async def update_model(
    model_id: UUID4, body: ModelUpdate, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> ModelRead:
    entity = await service.update(
        actor_for(admin, Role.GOVERNANCE_ADMIN),
        meta,
        model_id,
        body.model_dump(exclude_unset=True),
    )
    return ModelRead.model_validate(entity)


@router.delete(
    "/{model_id}",
    status_code=204,
    summary="Delete model",
    responses=error_responses(*ADMIN_ERROR_CODES, 400, 404),
)
async def delete_model(
    model_id: UUID4, admin: AdminDep, service: ServiceDep, meta: MetaDep
) -> Response:
    await service.delete(actor_for(admin, Role.GOVERNANCE_ADMIN), meta, model_id)
    return Response(status_code=204)
