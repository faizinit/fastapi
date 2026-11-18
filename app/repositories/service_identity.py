from typing import ClassVar

from app.models.service_identity import ServiceIdentity
from app.repositories.base import SoftDeleteRepository, SortMap


class ServiceIdentityRepository(SoftDeleteRepository[ServiceIdentity]):
    model = ServiceIdentity
    sortable: ClassVar[SortMap] = {
        "created_at": ServiceIdentity.created_at,
        "display_name": ServiceIdentity.display_name,
        "client_id": ServiceIdentity.client_id,
        "status": ServiceIdentity.status,
    }

    async def get_by_client_id(self, client_id: str) -> ServiceIdentity | None:
        return await self.find_one(ServiceIdentity.client_id == client_id)
