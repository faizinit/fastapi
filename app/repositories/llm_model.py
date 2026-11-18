from typing import ClassVar

from app.models.llm_model import LLMModel
from app.repositories.base import SoftDeleteRepository, SortMap


class LLMModelRepository(SoftDeleteRepository[LLMModel]):
    model = LLMModel
    sortable: ClassVar[SortMap] = {
        "created_at": LLMModel.created_at,
        "name": LLMModel.name,
        "provider": LLMModel.provider,
    }

    async def get_by_name(self, name: str) -> LLMModel | None:
        return await self.find_one(LLMModel.name == name)
