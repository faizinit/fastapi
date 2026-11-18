"""Generic, audited CRUD for administrative resources."""

import uuid
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar, cast

from sqlalchemy import ColumnElement
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Actor, RequestMeta
from app.core.exceptions import NotFoundError
from app.db.base import Entity
from app.db.session import Database
from app.models.types import JSONObject, JSONValue
from app.repositories.base import BaseRepository
from app.services.audit import AuditService


class ResourceService[ModelT: Entity](ABC):
    """Template for list/get/create/update/delete with audit entries in the same transaction.

    Subclasses provide the repository and may override the validation hooks.
    """

    resource_type: ClassVar[str]

    def __init__(self, database: Database, audit: AuditService) -> None:
        self._database = database
        self._audit = audit

    @abstractmethod
    def _repository(self, session: AsyncSession) -> BaseRepository[ModelT]: ...

    def _audit_details(self, entity: ModelT) -> JSONObject:
        """Non-sensitive identifying data stored with the audit entry."""
        return {}

    async def _before_create(self, session: AsyncSession, entity: ModelT) -> None:
        """Validate a new entity inside the write transaction."""
        return

    async def _before_update(
        self, session: AsyncSession, entity: ModelT, changes: dict[str, object]
    ) -> None:
        """Validate or adjust an entity before `changes` are applied."""
        return

    async def _before_delete(self, session: AsyncSession, entity: ModelT) -> None:
        """Validate that an entity may be removed."""
        return

    async def paginate(
        self,
        *,
        criteria: Sequence[ColumnElement[bool]] = (),
        sort: str | None = None,
        descending: bool = False,
        limit: int,
        offset: int,
    ) -> tuple[list[ModelT], int]:
        async with self._database.read_sessions() as session:
            return await self._repository(session).paginate(
                criteria=criteria, sort=sort, descending=descending, limit=limit, offset=offset
            )

    async def get(self, entity_id: uuid.UUID) -> ModelT:
        async with self._database.read_sessions() as session:
            return await self._get_or_404(self._repository(session), entity_id)

    async def create(self, actor: Actor, meta: RequestMeta, entity: ModelT) -> ModelT:
        async with self._database.write_session() as session:
            await self._before_create(session, entity)
            await self._repository(session).add(entity)
            await self._record(session, actor, meta, "create", entity)
        return entity

    async def update(
        self, actor: Actor, meta: RequestMeta, entity_id: uuid.UUID, changes: dict[str, object]
    ) -> ModelT:
        async with self._database.write_session() as session:
            repository = self._repository(session)
            entity = await self._get_or_404(repository, entity_id)
            await self._before_update(session, entity, changes)
            for name, value in changes.items():
                setattr(entity, name, value)
            await repository.flush()
            changed = cast(list[JSONValue], sorted(changes))
            await self._record(session, actor, meta, "update", entity, extra={"changed": changed})
        return entity

    async def delete(self, actor: Actor, meta: RequestMeta, entity_id: uuid.UUID) -> None:
        async with self._database.write_session() as session:
            repository = self._repository(session)
            entity = await self._get_or_404(repository, entity_id)
            await self._before_delete(session, entity)
            await repository.remove(entity)
            await self._record(session, actor, meta, "delete", entity)

    async def _get_or_404(self, repository: BaseRepository[ModelT], entity_id: uuid.UUID) -> ModelT:
        entity = await repository.get(entity_id)
        if entity is None:
            raise NotFoundError(f"{self.resource_type.replace('_', ' ').capitalize()} not found.")
        return entity

    async def _record(
        self,
        session: AsyncSession,
        actor: Actor,
        meta: RequestMeta,
        verb: str,
        entity: ModelT,
        *,
        extra: JSONObject | None = None,
    ) -> None:
        await self._audit.append(
            session,
            actor=actor,
            action=f"{self.resource_type}.{verb}",
            resource_type=self.resource_type,
            resource_id=str(entity.id),
            meta=meta,
            details={**self._audit_details(entity), **(extra or {})},
        )
