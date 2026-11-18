import uuid
from collections.abc import Sequence

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError
from app.models.audit_log import AuditLog


class AuditLogRepository:
    """Append-only access to the audit chain."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def last(self) -> AuditLog | None:
        statement = select(AuditLog).order_by(AuditLog.seq.desc()).limit(1)
        return (await self.session.execute(statement)).scalar_one_or_none()

    async def get_by_seq(self, seq: int) -> AuditLog | None:
        statement = select(AuditLog).where(AuditLog.seq == seq)
        return (await self.session.execute(statement)).scalar_one_or_none()

    async def get(self, entry_id: uuid.UUID) -> AuditLog | None:
        return await self.session.get(AuditLog, entry_id)

    async def add(self, entry: AuditLog) -> AuditLog:
        self.session.add(entry)
        try:
            await self.session.flush()
        except IntegrityError as exc:
            raise ConflictError("Concurrent audit append detected.") from exc
        return entry

    async def paginate(
        self, *, criteria: Sequence[ColumnElement[bool]] = (), limit: int, offset: int
    ) -> tuple[list[AuditLog], int]:
        total_statement = select(func.count()).select_from(AuditLog).where(*criteria)
        total = (await self.session.execute(total_statement)).scalar_one()
        statement = (
            select(AuditLog)
            .where(*criteria)
            .order_by(AuditLog.seq.desc())
            .limit(limit)
            .offset(offset)
        )
        return list((await self.session.execute(statement)).scalars().all()), total

    async def range(self, from_seq: int, to_seq: int) -> list[AuditLog]:
        statement = (
            select(AuditLog)
            .where(AuditLog.seq >= from_seq, AuditLog.seq <= to_seq)
            .order_by(AuditLog.seq.asc())
        )
        return list((await self.session.execute(statement)).scalars().all())
