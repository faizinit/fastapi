from sqlalchemy.ext.asyncio import AsyncSession

from app.models.quota import Quota
from app.models.types import JSONObject
from app.repositories.base import BaseRepository
from app.repositories.quota import QuotaRepository
from app.services.resource import ResourceService


class QuotaService(ResourceService[Quota]):
    resource_type = "quota"

    def _repository(self, session: AsyncSession) -> BaseRepository[Quota]:
        return QuotaRepository(session)

    def _audit_details(self, entity: Quota) -> JSONObject:
        return {
            "scopeType": entity.scope_type.value,
            "scopeRef": entity.scope_ref,
            "kind": entity.kind.value,
        }
