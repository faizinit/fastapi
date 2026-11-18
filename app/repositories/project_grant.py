"""Access to the project-to-task and project-to-model grants."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager

from app.core.exceptions import ConflictError
from app.models.llm_model import LLMModel
from app.models.project import ProjectModel, ProjectTask
from app.models.task import Task


async def _flush(session: AsyncSession) -> None:
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError("The grant conflicts with an existing record.") from exc


class ProjectTaskRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, project_id: uuid.UUID, task_id: uuid.UUID) -> ProjectTask | None:
        return await self.session.get(ProjectTask, (project_id, task_id))

    async def is_granted(self, project_id: uuid.UUID, task_id: uuid.UUID) -> bool:
        return await self.get(project_id, task_id) is not None

    async def paginate(
        self, project_id: uuid.UUID, *, limit: int, offset: int
    ) -> tuple[list[ProjectTask], int]:
        live = (ProjectTask.project_id == project_id, Task.deleted_at.is_(None))
        total_statement = select(func.count()).select_from(ProjectTask).join(Task).where(*live)
        total = (await self.session.execute(total_statement)).scalar_one()
        statement = (
            select(ProjectTask)
            .join(Task)
            .options(contains_eager(ProjectTask.task))
            .where(*live)
            .order_by(Task.name)
            .limit(limit)
            .offset(offset)
        )
        return list((await self.session.execute(statement)).scalars().all()), total

    async def add(self, grant: ProjectTask) -> ProjectTask:
        self.session.add(grant)
        await _flush(self.session)
        await self.session.refresh(grant, attribute_names=["task"])
        return grant

    async def remove(self, grant: ProjectTask) -> None:
        await self.session.delete(grant)
        await _flush(self.session)


class ProjectModelRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, project_id: uuid.UUID, model_id: uuid.UUID) -> ProjectModel | None:
        return await self.session.get(ProjectModel, (project_id, model_id))

    async def is_granted(self, project_id: uuid.UUID, model_id: uuid.UUID) -> bool:
        return await self.get(project_id, model_id) is not None

    async def paginate(
        self, project_id: uuid.UUID, *, limit: int, offset: int
    ) -> tuple[list[ProjectModel], int]:
        live = (ProjectModel.project_id == project_id, LLMModel.deleted_at.is_(None))
        total_statement = select(func.count()).select_from(ProjectModel).join(LLMModel).where(*live)
        total = (await self.session.execute(total_statement)).scalar_one()
        statement = (
            select(ProjectModel)
            .join(LLMModel)
            .options(contains_eager(ProjectModel.model))
            .where(*live)
            .order_by(LLMModel.name)
            .limit(limit)
            .offset(offset)
        )
        return list((await self.session.execute(statement)).scalars().all()), total

    async def add(self, grant: ProjectModel) -> ProjectModel:
        self.session.add(grant)
        await _flush(self.session)
        await self.session.refresh(grant, attribute_names=["model"])
        return grant

    async def remove(self, grant: ProjectModel) -> None:
        await self.session.delete(grant)
        await _flush(self.session)
