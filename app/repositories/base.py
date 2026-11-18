"""Generic repositories holding all common database access."""

import uuid
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from app.core.exceptions import ConflictError
from app.db.base import Entity, SoftDeletableEntity, utcnow


def contains(column: InstrumentedAttribute[str], text: str) -> ColumnElement[bool]:
    """Case-insensitive substring match with LIKE wildcards escaped."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column.ilike(f"%{escaped}%", escape="\\")


type SortMap = Mapping[str, InstrumentedAttribute[Any]]  # Any: column value types vary.


class BaseRepository[ModelT: Entity]:
    """CRUD and pagination for one aggregate.

    Subclasses set `model` and `sortable`, an allow-list mapping API sort keys to columns.
    """

    model: type[ModelT]
    sortable: ClassVar[SortMap] = {}

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _live(self) -> list[ColumnElement[bool]]:
        """Row filters applied to every read."""
        return []

    async def get(self, entity_id: uuid.UUID) -> ModelT | None:
        statement = select(self.model).where(self.model.id == entity_id, *self._live())
        return (await self.session.execute(statement)).unique().scalar_one_or_none()

    async def find_one(self, *criteria: ColumnElement[bool]) -> ModelT | None:
        statement = select(self.model).where(*criteria, *self._live()).limit(1)
        return (await self.session.execute(statement)).unique().scalar_one_or_none()

    async def exists(self, *criteria: ColumnElement[bool]) -> bool:
        statement = select(func.count()).select_from(self.model).where(*criteria, *self._live())
        return bool((await self.session.execute(statement)).scalar_one())

    async def paginate(
        self,
        *,
        criteria: Sequence[ColumnElement[bool]] = (),
        sort: str | None = None,
        descending: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ModelT], int]:
        """Return a page of rows and the total number of matching rows."""
        where = [*criteria, *self._live()]
        total_statement = select(func.count()).select_from(self.model).where(*where)
        total = (await self.session.execute(total_statement)).scalar_one()

        column = self._sort_column(sort)
        ordering = column.desc() if descending else column.asc()
        statement = (
            select(self.model)
            .where(*where)
            .order_by(ordering, self.model.id)
            .limit(limit)
            .offset(offset)
        )
        rows = (await self.session.execute(statement)).unique().scalars().all()
        return list(rows), total

    def _sort_column(self, sort: str | None) -> InstrumentedAttribute[Any]:
        if sort is None:
            return self.model.created_at
        try:
            return self.sortable[sort]
        except KeyError as exc:
            raise ValueError(f"sort key {sort!r} is not allowed") from exc

    async def add(self, entity: ModelT) -> ModelT:
        self.session.add(entity)
        await self.flush()
        return entity

    async def delete(self, entity: ModelT) -> None:
        await self.session.delete(entity)
        await self.flush()

    async def remove(self, entity: ModelT) -> None:
        """Remove an aggregate the way this repository removes it (hard delete here)."""
        await self.delete(entity)

    async def flush(self) -> None:
        """Flush pending changes, translating constraint violations into conflicts."""
        try:
            await self.session.flush()
        except IntegrityError as exc:
            raise ConflictError(
                "The change conflicts with an existing record or a referenced resource."
            ) from exc


class SoftDeleteRepository[ModelT: SoftDeletableEntity](BaseRepository[ModelT]):
    """A repository whose reads hide soft-deleted rows."""

    def _live(self) -> list[ColumnElement[bool]]:
        return [self.model.deleted_at.is_(None)]

    async def soft_delete(self, entity: ModelT) -> None:
        entity.deleted_at = utcnow()
        await self.flush()

    async def remove(self, entity: ModelT) -> None:
        await self.soft_delete(entity)
