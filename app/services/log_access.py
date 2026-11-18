"""Controlled read access to audit logs and security events. Every access is itself audited."""

import uuid
from collections.abc import Sequence

from sqlalchemy import ColumnElement
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Actor, RequestMeta
from app.core.exceptions import NotFoundError
from app.db.session import Database
from app.models.audit_log import AuditLog
from app.models.security_event import SecurityEvent
from app.models.types import JSONObject
from app.repositories.audit_log import AuditLogRepository
from app.repositories.security_event import SecurityEventRepository
from app.services.audit import AuditService, VerifyResult


class LogAccessService:
    def __init__(self, database: Database, audit: AuditService) -> None:
        self._database = database
        self._audit = audit

    async def list_audit_logs(
        self,
        actor: Actor,
        meta: RequestMeta,
        *,
        criteria: Sequence[ColumnElement[bool]],
        limit: int,
        offset: int,
        filters: JSONObject,
    ) -> tuple[list[AuditLog], int]:
        async with self._database.write_session() as session:
            rows, total = await AuditLogRepository(session).paginate(
                criteria=criteria, limit=limit, offset=offset
            )
            await self._record(session, actor, meta, "audit_logs.read", None, filters)
        return rows, total

    async def get_audit_log(self, actor: Actor, meta: RequestMeta, entry_id: uuid.UUID) -> AuditLog:
        async with self._database.write_session() as session:
            entry = await AuditLogRepository(session).get(entry_id)
            if entry is None:
                raise NotFoundError("Audit log entry not found.")
            await self._record(session, actor, meta, "audit_logs.read", str(entry_id), {})
        return entry

    async def verify_audit_logs(
        self, actor: Actor, meta: RequestMeta, from_seq: int, to_seq: int
    ) -> VerifyResult:
        async with self._database.write_session() as session:
            result = await self._audit.verify(session, from_seq, to_seq)
            await self._record(
                session,
                actor,
                meta,
                "audit_logs.verify",
                None,
                {"fromSeq": from_seq, "toSeq": to_seq, "valid": result.valid},
            )
        return result

    async def list_security_events(
        self,
        actor: Actor,
        meta: RequestMeta,
        *,
        criteria: Sequence[ColumnElement[bool]],
        limit: int,
        offset: int,
        filters: JSONObject,
    ) -> tuple[list[SecurityEvent], int]:
        async with self._database.write_session() as session:
            rows, total = await SecurityEventRepository(session).paginate(
                criteria=criteria, limit=limit, offset=offset
            )
            await self._record(session, actor, meta, "security_events.read", None, filters)
        return rows, total

    async def get_security_event(
        self, actor: Actor, meta: RequestMeta, event_id: uuid.UUID
    ) -> SecurityEvent:
        async with self._database.write_session() as session:
            event = await SecurityEventRepository(session).get(event_id)
            if event is None:
                raise NotFoundError("Security event not found.")
            await self._record(session, actor, meta, "security_events.read", str(event_id), {})
        return event

    async def _record(
        self,
        session: AsyncSession,
        actor: Actor,
        meta: RequestMeta,
        action: str,
        resource_id: str | None,
        details: JSONObject,
    ) -> None:
        resource_type = action.split(".", maxsplit=1)[0]
        await self._audit.append(
            session,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            meta=meta,
            details=details,
        )
