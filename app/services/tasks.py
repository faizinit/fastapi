from sqlalchemy.ext.asyncio import AsyncSession

from app.models.task import Task
from app.models.types import JSONObject
from app.repositories.base import BaseRepository
from app.repositories.task import TaskRepository
from app.services.resource import ResourceService


class TaskService(ResourceService[Task]):
    resource_type = "task"

    def _repository(self, session: AsyncSession) -> BaseRepository[Task]:
        return TaskRepository(session)

    def _audit_details(self, entity: Task) -> JSONObject:
        return {"name": entity.name}
