import uuid

from pydantic import Field

from app.schemas.common import ApiModel, Timestamped, UpdateModel

TASK_NAME_PATTERN = r"^[a-z][a-z0-9_]{0,99}$"


class TaskCreate(ApiModel):
    name: str = Field(pattern=TASK_NAME_PATTERN, examples=["summarize_document"])
    description: str = Field(default="", max_length=2000)
    max_payload_bytes: int = Field(default=65_536, ge=1, le=10_485_760)
    enabled: bool = True


class TaskUpdate(UpdateModel):
    description: str | None = Field(default=None, max_length=2000)
    max_payload_bytes: int | None = Field(default=None, ge=1, le=10_485_760)
    enabled: bool | None = None


class TaskRead(Timestamped):
    id: uuid.UUID
    name: str
    description: str
    max_payload_bytes: int
    enabled: bool
