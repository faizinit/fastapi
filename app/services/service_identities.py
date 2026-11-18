import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Actor, RequestMeta
from app.core.exceptions import ConflictError, NotFoundError
from app.db.base import utcnow
from app.models.enums import IdentityStatus
from app.models.service_identity import ServiceIdentity
from app.models.types import JSONObject
from app.repositories.base import BaseRepository
from app.repositories.project import ProjectRepository
from app.repositories.service_identity import ServiceIdentityRepository
from app.services.resource import ResourceService


class ServiceIdentityService(ResourceService[ServiceIdentity]):
    """Onboarding and access review of registered applications."""

    resource_type = "service_identity"

    def _repository(self, session: AsyncSession) -> BaseRepository[ServiceIdentity]:
        return ServiceIdentityRepository(session)

    def _audit_details(self, entity: ServiceIdentity) -> JSONObject:
        return {"clientId": entity.client_id, "projectId": str(entity.project_id)}

    async def _before_create(self, session: AsyncSession, entity: ServiceIdentity) -> None:
        project = await ProjectRepository(session).get(entity.project_id)
        if project is None:
            raise NotFoundError("Project not found.")
        entity.project = project

    async def approve(
        self, actor: Actor, meta: RequestMeta, identity_id: uuid.UUID
    ) -> ServiceIdentity:
        """Move a pending identity to approved. Revoked identities must be re-registered."""
        async with self._database.write_session() as session:
            repository = ServiceIdentityRepository(session)
            identity = await self._get_or_404(repository, identity_id)
            if identity.status is not IdentityStatus.PENDING:
                raise ConflictError(f"A {identity.status.value} identity cannot be approved.")
            identity.status = IdentityStatus.APPROVED
            identity.approved_by = actor.subject
            identity.approved_at = utcnow()
            await repository.flush()
            await self._record(session, actor, meta, "approve", identity)
        return identity

    async def revoke(
        self, actor: Actor, meta: RequestMeta, identity_id: uuid.UUID, reason: str | None
    ) -> ServiceIdentity:
        """Revoke access immediately; the next request from the application is refused."""
        async with self._database.write_session() as session:
            repository = ServiceIdentityRepository(session)
            identity = await self._get_or_404(repository, identity_id)
            if identity.status is IdentityStatus.REVOKED:
                raise ConflictError("The identity is already revoked.")
            identity.status = IdentityStatus.REVOKED
            identity.revoked_by = actor.subject
            identity.revoked_at = utcnow()
            identity.revocation_reason = reason
            await repository.flush()
            await self._record(session, actor, meta, "revoke", identity, extra={"reason": reason})
        return identity
