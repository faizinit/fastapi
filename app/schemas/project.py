import uuid
from datetime import datetime

from pydantic import Field

from app.models.enums import ProjectStatus
from app.schemas.common import ApiModel, Timestamped, UpdateModel

PROJECT_KEY_PATTERN = r"^[A-Z][A-Z0-9_]{2,63}$"


class ProjectCreate(ApiModel):
    project_key: str = Field(pattern=PROJECT_KEY_PATTERN, examples=["COE_1"])
    name: str = Field(min_length=1, max_length=200)
    team: str = Field(min_length=1, max_length=100)
    status: ProjectStatus = ProjectStatus.ACTIVE


class ProjectUpdate(UpdateModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    team: str | None = Field(default=None, min_length=1, max_length=100)
    status: ProjectStatus | None = None


class ProjectRead(Timestamped):
    id: uuid.UUID
    project_key: str
    name: str
    team: str
    status: ProjectStatus


class TaskGrantCreate(ApiModel):
    task_id: uuid.UUID


class TaskGrantRead(ApiModel):
    project_id: uuid.UUID
    task_id: uuid.UUID
    task_name: str
    granted_by: str
    granted_at: datetime


class ModelGrantCreate(ApiModel):
    model_id: uuid.UUID


class ModelGrantRead(ApiModel):
    project_id: uuid.UUID
    model_id: uuid.UUID
    model_name: str
    granted_by: str
    granted_at: datetime
