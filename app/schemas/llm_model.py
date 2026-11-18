import uuid

from pydantic import Field

from app.schemas.common import ApiModel, Timestamped, UpdateModel

MODEL_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$"


class ModelCreate(ApiModel):
    name: str = Field(pattern=MODEL_NAME_PATTERN, examples=["gpt-4o"])
    provider: str = Field(min_length=1, max_length=100)
    enabled: bool = True


class ModelUpdate(UpdateModel):
    provider: str | None = Field(default=None, min_length=1, max_length=100)
    enabled: bool | None = None


class ModelRead(Timestamped):
    id: uuid.UUID
    name: str
    provider: str
    enabled: bool
