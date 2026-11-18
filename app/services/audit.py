"""Tamper-evident audit trail: a hash chain over append-only rows."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Actor, RequestMeta
from app.core.logging import mask_value
from app.db.base import utcnow
from app.db.session import Database
from app.models.audit_log import GENESIS_HASH, AuditLog
from app.models.types import JSONObject
from app.repositories.audit_log import AuditLogRepository

MAX_VERIFY_SPAN = 10_000


@dataclass(frozen=True, slots=True)
class VerifyResult:
    valid: bool
    checked: int
    first_broken_seq: int | None


def compute_row_hash(
    *,
    seq: int,
    prev_hash: str,
    actor_sub: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    request_id: str | None,
    correlation_id: str | None,
    outcome: str,
    metadata: JSONObject,
    occurred_at: datetime,
) -> str:
    payload = json.dumps(
        {
            "seq": seq,
            "prev_hash": prev_hash,
            "actor_sub": actor_sub,
            "actor_role": actor_role,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "request_id": request_id,
            "correlation_id": correlation_id,
            "outcome": outcome,
            "metadata": metadata,
            "occurred_at": occurred_at.astimezone(UTC).isoformat(timespec="microseconds"),
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _entry_hash(entry: AuditLog) -> str:
    return compute_row_hash(
        seq=entry.seq,
        prev_hash=entry.prev_hash,
        actor_sub=entry.actor_sub,
        actor_role=entry.actor_role,
        action=entry.action,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        request_id=entry.request_id,
        correlation_id=entry.correlation_id,
        outcome=entry.outcome,
        metadata=entry.event_metadata,
        occurred_at=entry.occurred_at,
    )


class AuditService:
    """Appends and verifies audit entries.

    `append` must run inside the caller's write unit of work so the entry commits atomically with
    the change it describes. Write transactions are `BEGIN IMMEDIATE`, which serialises chain
    extension across processes.
    """

    def __init__(self, database: Database) -> None:
        self._database = database

    async def append(
        self,
        session: AsyncSession,
        *,
        actor: Actor,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        outcome: str = "success",
        meta: RequestMeta,
        request_id: str | None = None,
        details: JSONObject | None = None,
    ) -> AuditLog:
        repository = AuditLogRepository(session)
        previous = await repository.last()
        seq = 1 if previous is None else previous.seq + 1
        prev_hash = GENESIS_HASH if previous is None else previous.row_hash
        occurred_at = utcnow()
        metadata: JSONObject = _sanitized(details or {})
        row_hash = compute_row_hash(
            seq=seq,
            prev_hash=prev_hash,
            actor_sub=actor.subject,
            actor_role=actor.role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            correlation_id=meta.correlation_id,
            outcome=outcome,
            metadata=metadata,
            occurred_at=occurred_at,
        )
        entry = AuditLog(
            seq=seq,
            actor_sub=actor.subject,
            actor_role=actor.role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            correlation_id=meta.correlation_id,
            outcome=outcome,
            event_metadata=metadata,
            prev_hash=prev_hash,
            row_hash=row_hash,
            occurred_at=occurred_at,
        )
        return await repository.add(entry)

    async def record(
        self,
        *,
        actor: Actor,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        outcome: str = "success",
        meta: RequestMeta,
        request_id: str | None = None,
        details: JSONObject | None = None,
    ) -> AuditLog:
        """Append an entry in its own transaction."""
        async with self._database.write_session() as session:
            return await self.append(
                session,
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome=outcome,
                meta=meta,
                request_id=request_id,
                details=details,
            )

    async def verify(self, session: AsyncSession, from_seq: int, to_seq: int) -> VerifyResult:
        """Recompute hashes and links for `from_seq..to_seq`, reporting the first break."""
        repository = AuditLogRepository(session)
        expected_prev = await self._expected_prev_hash(repository, from_seq)
        expected_seq = from_seq
        rows = await repository.range(from_seq, min(to_seq, from_seq + MAX_VERIFY_SPAN - 1))
        for entry in rows:
            intact = (
                entry.seq == expected_seq
                and entry.prev_hash == expected_prev
                and entry.row_hash == _entry_hash(entry)
            )
            if not intact:
                return VerifyResult(False, expected_seq - from_seq, expected_seq)
            expected_prev = entry.row_hash
            expected_seq += 1
        return VerifyResult(True, len(rows), None)

    @staticmethod
    async def _expected_prev_hash(repository: AuditLogRepository, from_seq: int) -> str:
        if from_seq <= 1:
            return GENESIS_HASH
        previous = await repository.get_by_seq(from_seq - 1)
        return previous.row_hash if previous is not None else GENESIS_HASH


def _sanitized(details: JSONObject) -> JSONObject:
    masked = mask_value(details)
    return masked if isinstance(masked, dict) else {}
