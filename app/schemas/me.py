import uuid

from app.core.roles import Role
from app.models.enums import IdentityStatus, ProjectStatus
from app.schemas.common import ApiModel


class RegisteredIdentity(ApiModel):
    identity_id: uuid.UUID
    project_id: uuid.UUID
    project_key: str
    team: str
    project_status: ProjectStatus
    status: IdentityStatus
    roles: list[str]


class MeRead(ApiModel):
    """The caller as established by the verified token and the identity registry."""

    subject: str
    client_id: str
    token_roles: list[Role]
    identity: RegisteredIdentity | None = None
