from fastapi import APIRouter

from app.api.deps import DatabaseDep, PrincipalDep
from app.core.exceptions import error_responses
from app.schemas.me import MeRead, RegisteredIdentity
from app.services.identity import IdentityResolver

router = APIRouter(prefix="/me", tags=["identity"])


@router.get(
    "",
    response_model=MeRead,
    status_code=200,
    summary="Describe the calling identity",
    responses=error_responses(401, 429, 503),
)
async def read_me(principal: PrincipalDep, database: DatabaseDep) -> MeRead:
    """Return what the platform knows about the caller. Nothing is taken from the request body."""
    identity = await IdentityResolver(database).find(principal)
    registered = (
        RegisteredIdentity(
            identity_id=identity.id,
            project_id=identity.project_id,
            project_key=identity.project.project_key,
            team=identity.project.team,
            project_status=identity.project.status,
            status=identity.status,
            roles=list(identity.roles),
        )
        if identity is not None
        else None
    )
    return MeRead(
        subject=principal.subject,
        client_id=principal.client_id,
        token_roles=sorted(principal.roles),
        identity=registered,
    )
