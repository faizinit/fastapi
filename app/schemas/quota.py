import re
import uuid
from typing import Self

from pydantic import Field, model_validator

from app.models.enums import QuotaKind, QuotaScope
from app.schemas.common import ApiModel, Timestamped, UpdateModel
from app.schemas.project import PROJECT_KEY_PATTERN
from app.schemas.task import TASK_NAME_PATTERN

MAX_LIMIT = 1_000_000_000
MAX_WINDOW_SECONDS = 31_536_000


class QuotaCreate(ApiModel):
    scope_type: QuotaScope
    scope_ref: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^\S(.*\S)?$",
        description="Caller client id, team name, project key or task name, per `scopeType`.",
    )
    kind: QuotaKind
    limit_value: int = Field(ge=1, le=MAX_LIMIT)
    window_seconds: int = Field(ge=1, le=MAX_WINDOW_SECONDS)
    enabled: bool = True

    @model_validator(mode="after")
    def _scope_ref_matches_scope(self) -> Self:
        patterns = {QuotaScope.PROJECT: PROJECT_KEY_PATTERN, QuotaScope.TASK: TASK_NAME_PATTERN}
        pattern = patterns.get(self.scope_type)
        if pattern and not re.fullmatch(pattern, self.scope_ref):
            raise ValueError(f"scopeRef is not a valid {self.scope_type.value} identifier")
        return self


class QuotaUpdate(UpdateModel):
    limit_value: int | None = Field(default=None, ge=1, le=MAX_LIMIT)
    window_seconds: int | None = Field(default=None, ge=1, le=MAX_WINDOW_SECONDS)
    enabled: bool | None = None


class QuotaRead(Timestamped):
    id: uuid.UUID
    scope_type: QuotaScope
    scope_ref: str
    kind: QuotaKind
    limit_value: int
    window_seconds: int
    enabled: bool
