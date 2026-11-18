from collections.abc import Sequence
from typing import ClassVar

from sqlalchemy import and_, or_, select

from app.models.enums import QuotaScope
from app.models.quota import Quota
from app.repositories.base import BaseRepository, SortMap


class QuotaRepository(BaseRepository[Quota]):
    model = Quota
    sortable: ClassVar[SortMap] = {
        "created_at": Quota.created_at,
        "scope_type": Quota.scope_type,
        "scope_ref": Quota.scope_ref,
        "limit_value": Quota.limit_value,
    }

    async def enabled_for(self, scopes: Sequence[tuple[QuotaScope, str]]) -> list[Quota]:
        """Enabled quotas whose (scope type, scope ref) is any of `scopes`."""
        if not scopes:
            return []
        matches = or_(
            *(and_(Quota.scope_type == kind, Quota.scope_ref == ref) for kind, ref in scopes)
        )
        statement = select(Quota).where(Quota.enabled.is_(True), matches).order_by(Quota.id)
        return list((await self.session.execute(statement)).scalars().all())
