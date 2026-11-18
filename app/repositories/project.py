from typing import ClassVar

from app.models.project import Project
from app.repositories.base import SoftDeleteRepository, SortMap


class ProjectRepository(SoftDeleteRepository[Project]):
    model = Project
    sortable: ClassVar[SortMap] = {
        "created_at": Project.created_at,
        "name": Project.name,
        "project_key": Project.project_key,
        "team": Project.team,
    }
