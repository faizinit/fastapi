import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Actor, RequestMeta
from app.core.exceptions import ConflictError, NotFoundError
from app.db.session import Database
from app.models.project import Project, ProjectModel, ProjectTask
from app.models.types import JSONObject
from app.repositories.base import BaseRepository
from app.repositories.llm_model import LLMModelRepository
from app.repositories.project import ProjectRepository
from app.repositories.project_grant import ProjectModelRepository, ProjectTaskRepository
from app.repositories.task import TaskRepository
from app.services.audit import AuditService
from app.services.resource import ResourceService


class ProjectService(ResourceService[Project]):
    resource_type = "project"

    def _repository(self, session: AsyncSession) -> BaseRepository[Project]:
        return ProjectRepository(session)

    def _audit_details(self, entity: Project) -> JSONObject:
        return {"projectKey": entity.project_key}


class ProjectGrantService:
    """Grants and revokes the tasks and models a project may use."""

    def __init__(self, database: Database, audit: AuditService) -> None:
        self._database = database
        self._audit = audit

    async def list_tasks(
        self, project_id: uuid.UUID, *, limit: int, offset: int
    ) -> tuple[list[ProjectTask], int]:
        async with self._database.read_sessions() as session:
            await self._require_project(session, project_id)
            return await ProjectTaskRepository(session).paginate(
                project_id, limit=limit, offset=offset
            )

    async def grant_task(
        self, actor: Actor, meta: RequestMeta, project_id: uuid.UUID, task_id: uuid.UUID
    ) -> ProjectTask:
        async with self._database.write_session() as session:
            await self._require_project(session, project_id)
            task = await TaskRepository(session).get(task_id)
            if task is None:
                raise NotFoundError("Task not found.")
            repository = ProjectTaskRepository(session)
            if await repository.is_granted(project_id, task_id):
                raise ConflictError("The task is already granted to this project.")
            grant = await repository.add(
                ProjectTask(project_id=project_id, task_id=task_id, granted_by=actor.subject)
            )
            await self._audit.append(
                session,
                actor=actor,
                action="project_task.grant",
                resource_type="project",
                resource_id=str(project_id),
                meta=meta,
                details={"taskId": str(task_id), "taskName": task.name},
            )
        return grant

    async def revoke_task(
        self, actor: Actor, meta: RequestMeta, project_id: uuid.UUID, task_id: uuid.UUID
    ) -> None:
        async with self._database.write_session() as session:
            await self._require_project(session, project_id)
            repository = ProjectTaskRepository(session)
            grant = await repository.get(project_id, task_id)
            if grant is None:
                raise NotFoundError("The task is not granted to this project.")
            await repository.remove(grant)
            await self._audit.append(
                session,
                actor=actor,
                action="project_task.revoke",
                resource_type="project",
                resource_id=str(project_id),
                meta=meta,
                details={"taskId": str(task_id)},
            )

    async def list_models(
        self, project_id: uuid.UUID, *, limit: int, offset: int
    ) -> tuple[list[ProjectModel], int]:
        async with self._database.read_sessions() as session:
            await self._require_project(session, project_id)
            return await ProjectModelRepository(session).paginate(
                project_id, limit=limit, offset=offset
            )

    async def grant_model(
        self, actor: Actor, meta: RequestMeta, project_id: uuid.UUID, model_id: uuid.UUID
    ) -> ProjectModel:
        async with self._database.write_session() as session:
            await self._require_project(session, project_id)
            model = await LLMModelRepository(session).get(model_id)
            if model is None:
                raise NotFoundError("Model not found.")
            repository = ProjectModelRepository(session)
            if await repository.is_granted(project_id, model_id):
                raise ConflictError("The model is already granted to this project.")
            grant = await repository.add(
                ProjectModel(project_id=project_id, model_id=model_id, granted_by=actor.subject)
            )
            await self._audit.append(
                session,
                actor=actor,
                action="project_model.grant",
                resource_type="project",
                resource_id=str(project_id),
                meta=meta,
                details={"modelId": str(model_id), "modelName": model.name},
            )
        return grant

    async def revoke_model(
        self, actor: Actor, meta: RequestMeta, project_id: uuid.UUID, model_id: uuid.UUID
    ) -> None:
        async with self._database.write_session() as session:
            await self._require_project(session, project_id)
            repository = ProjectModelRepository(session)
            grant = await repository.get(project_id, model_id)
            if grant is None:
                raise NotFoundError("The model is not granted to this project.")
            await repository.remove(grant)
            await self._audit.append(
                session,
                actor=actor,
                action="project_model.revoke",
                resource_type="project",
                resource_id=str(project_id),
                meta=meta,
                details={"modelId": str(model_id)},
            )

    @staticmethod
    async def _require_project(session: AsyncSession, project_id: uuid.UUID) -> Project:
        project = await ProjectRepository(session).get(project_id)
        if project is None:
            raise NotFoundError("Project not found.")
        return project
