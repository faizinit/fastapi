from typing import cast

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestError, NotFoundError
from app.models.policy import Policy
from app.models.types import JSONObject
from app.repositories.base import BaseRepository
from app.repositories.policy import PolicyRepository
from app.repositories.task import TaskRepository
from app.schemas.policy import normalize_definition
from app.services.resource import ResourceService


class PolicyService(ResourceService[Policy]):
    resource_type = "policy"

    def _repository(self, session: AsyncSession) -> BaseRepository[Policy]:
        return PolicyRepository(session)

    def _audit_details(self, entity: Policy) -> JSONObject:
        return {"name": entity.name, "kind": entity.kind.value, "version": entity.version}

    async def _before_create(self, session: AsyncSession, entity: Policy) -> None:
        scope = entity.scope_task_id
        if scope is not None and await TaskRepository(session).get(scope) is None:
            raise NotFoundError("Task not found.")

    async def _before_update(
        self, session: AsyncSession, entity: Policy, changes: dict[str, object]
    ) -> None:
        """Re-validate a changed definition against the policy's kind and bump its version."""
        if "definition" not in changes:
            return
        raw = changes["definition"]
        try:
            changes["definition"] = normalize_definition(entity.kind, cast(JSONObject, raw))
        except ValueError as exc:
            raise BadRequestError(str(exc)) from exc
        changes["version"] = entity.version + 1
