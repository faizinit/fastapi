import uuid
from collections.abc import Sequence

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_event import SecurityEvent


class SecurityEventRepository:
    """Append-only access to security events."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, event: SecurityEvent) -> SecurityEvent:
        self.session.add(event)
        await self.session.flush()
        return event

    async def get(self, event_id: uuid.UUID) -> SecurityEvent | None:
        return await self.session.get(SecurityEvent, event_id)

    async def paginate(
        self, *, criteria: Sequence[ColumnElement[bool]] = (), limit: int, offset: int
    ) -> tuple[list[SecurityEvent], int]:
        total_statement = select(func.count()).select_from(SecurityEvent).where(*criteria)
        total = (await self.session.execute(total_statement)).scalar_one()
        statement = (
            select(SecurityEvent)
            .where(*criteria)
            .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id)
            .limit(limit)
            .offset(offset)
        )
        return list((await self.session.execute(statement)).scalars().all()), total
