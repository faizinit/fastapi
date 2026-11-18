from typing import ClassVar

from app.models.task import Task
from app.repositories.base import SoftDeleteRepository, SortMap


class TaskRepository(SoftDeleteRepository[Task]):
    model = Task
    sortable: ClassVar[SortMap] = {"created_at": Task.created_at, "name": Task.name}

    async def get_by_name(self, name: str) -> Task | None:
        return await self.find_one(Task.name == name)
