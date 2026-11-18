from typing import ClassVar

from app.models.llm_request import LLMRequest
from app.repositories.base import BaseRepository, SortMap


class LLMRequestRepository(BaseRepository[LLMRequest]):
    model = LLMRequest
    sortable: ClassVar[SortMap] = {"created_at": LLMRequest.created_at}
