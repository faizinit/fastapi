import uuid
from datetime import datetime
from typing import Annotated

from pydantic import Field, field_validator

from app.core.roles import Role
from app.models.enums import IdentityStatus
from app.schemas.common import ApiModel, Timestamped, UpdateModel

ClientId = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^\S+$")]


def _only_service_role(roles: list[Role] | None) -> list[Role] | None:
    if roles is None:
        return roles
    if not roles or set(roles) != {Role.SERVICE}:
        raise ValueError("a service identity can only hold the 'service' role")
    return [Role.SERVICE]


class ServiceIdentityCreate(ApiModel):
    project_id: uuid.UUID
    client_id: ClientId = Field(description="The `client_id` claim the application's tokens carry.")
    display_name: str = Field(min_length=1, max_length=200)
    roles: list[Role] = Field(default_factory=lambda: [Role.SERVICE])

    _roles = field_validator("roles")(_only_service_role)


class ServiceIdentityUpdate(UpdateModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    roles: list[Role] | None = None

    _roles = field_validator("roles")(_only_service_role)


class ServiceIdentityRead(Timestamped):
    id: uuid.UUID
    project_id: uuid.UUID
    project_key: str
    client_id: str
    display_name: str
    roles: list[Role]
    status: IdentityStatus
    approved_by: str | None
    approved_at: datetime | None
    revoked_by: str | None
    revoked_at: datetime | None
    revocation_reason: str | None


class IdentityTransition(ApiModel):
    reason: str | None = Field(default=None, max_length=500)
