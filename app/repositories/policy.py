import uuid
from typing import ClassVar

from sqlalchemy import or_, select

from app.models.enums import PolicyKind
from app.models.policy import Policy
from app.repositories.base import BaseRepository, SortMap


class PolicyRepository(BaseRepository[Policy]):
    model = Policy
    sortable: ClassVar[SortMap] = {
        "created_at": Policy.created_at,
        "name": Policy.name,
        "kind": Policy.kind,
        "version": Policy.version,
    }

    async def active_for_task(self, task_id: uuid.UUID, *kinds: PolicyKind) -> list[Policy]:
        """Enabled policies of `kinds` that are global or scoped to `task_id`."""
        statement = (
            select(Policy)
            .where(
                Policy.enabled.is_(True),
                Policy.kind.in_(kinds),
                or_(Policy.scope_task_id.is_(None), Policy.scope_task_id == task_id),
            )
            .order_by(Policy.created_at, Policy.id)
        )
        return list((await self.session.execute(statement)).scalars().all())
