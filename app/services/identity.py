"""Resolves a verified principal to its registered service identity."""

from app.core.security import Principal
from app.db.session import Database
from app.models.service_identity import ServiceIdentity
from app.repositories.service_identity import ServiceIdentityRepository


class IdentityResolver:
    def __init__(self, database: Database) -> None:
        self._database = database

    async def find(self, principal: Principal) -> ServiceIdentity | None:
        """The registered identity for the token's client id, whatever its approval status."""
        async with self._database.read_sessions() as session:
            return await ServiceIdentityRepository(session).get_by_client_id(principal.client_id)
