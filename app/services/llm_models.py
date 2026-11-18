from sqlalchemy.ext.asyncio import AsyncSession

from app.models.llm_model import LLMModel
from app.models.types import JSONObject
from app.repositories.base import BaseRepository
from app.repositories.llm_model import LLMModelRepository
from app.services.resource import ResourceService


class LLMModelService(ResourceService[LLMModel]):
    resource_type = "llm_model"

    def _repository(self, session: AsyncSession) -> BaseRepository[LLMModel]:
        return LLMModelRepository(session)

    def _audit_details(self, entity: LLMModel) -> JSONObject:
        return {"name": entity.name}
