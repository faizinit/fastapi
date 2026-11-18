import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.session import Database
from app.models import AuditLog, LLMRequest, Project, RateCounter, SecurityEvent
from app.models.enums import (
    LLMRequestStatus,
    ProjectStatus,
    QuotaKind,
    QuotaScope,
    SecurityEventType,
    Severity,
)
from tests import factories


async def _add_nested(session: AsyncSession, entity: object) -> None:
    """Add an entity inside a savepoint so a constraint failure leaves the session usable."""
    async with session.begin_nested():
        session.add(entity)
        await session.flush()


async def test_timestamps_are_timezone_aware_utc(session: AsyncSession) -> None:
    project = await factories.make_project(session)
    await session.flush()
    session.expire_all()
    stored = (await session.execute(select(Project))).scalar_one()
    assert stored.created_at.tzinfo is UTC
    assert stored.updated_at >= stored.created_at
    assert stored.id == project.id


async def test_naive_datetimes_are_rejected(session: AsyncSession) -> None:
    project = await factories.make_project(session)
    project.deleted_at = datetime(2026, 1, 1)
    with pytest.raises(StatementError, match="naive datetime"):
        await session.flush()


async def test_aware_datetimes_round_trip(session: AsyncSession) -> None:
    project = await factories.make_project(session)
    moment = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    project.deleted_at = moment
    await session.flush()
    await session.refresh(project)
    assert project.deleted_at == moment


async def test_project_key_unique_among_active_only(session: AsyncSession) -> None:
    first = await factories.make_project(session, project_key="COE_1")
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await factories.make_project(session, project_key="COE_1")
    first.deleted_at = utcnow()
    await session.flush()
    again = await factories.make_project(session, project_key="COE_1")
    assert again.id != first.id


async def test_enum_values_are_validated(session: AsyncSession) -> None:
    with pytest.raises(StatementError):
        await factories.make_project(session, status="exploded")


async def test_check_constraints(session: AsyncSession) -> None:
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await factories.make_task(session, max_payload_bytes=0)
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await factories.make_quota(session, limit_value=0)
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await factories.make_quota(session, window_seconds=0)
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await factories.make_policy(session, version=0)


async def test_quota_scope_is_unique_per_kind(session: AsyncSession) -> None:
    await factories.make_quota(session, scope_ref="COE_1")
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            await factories.make_quota(session, scope_ref="COE_1")
    other = await factories.make_quota(session, scope_ref="COE_1", kind=QuotaKind.QUOTA)
    assert other.scope_type is QuotaScope.PROJECT


async def test_foreign_keys_are_enforced(session: AsyncSession) -> None:
    with pytest.raises(IntegrityError):
        await factories.make_identity(session, project=Project(id=uuid.uuid4()))


async def test_grants_cascade_when_project_removed(session: AsyncSession) -> None:
    project = await factories.make_project(session)
    task = await factories.make_task(session)
    model = await factories.make_model(session)
    await factories.grant_task(session, project, task)
    await factories.grant_model(session, project, model)
    await session.execute(delete(Project).where(Project.id == project.id))
    remaining = await session.execute(text("SELECT count(*) FROM project_tasks"))
    assert remaining.scalar_one() == 0


async def test_identity_defaults_and_project_relationship(session: AsyncSession) -> None:
    project = await factories.make_project(session, status=ProjectStatus.SUSPENDED)
    identity = await factories.make_identity(session, project)
    assert identity.project.status is ProjectStatus.SUSPENDED
    assert identity.roles == ["service"]


def _llm_request(identity_id: uuid.UUID, project_id: uuid.UUID, request_id: str) -> LLMRequest:
    return LLMRequest(
        project_id=project_id,
        service_identity_id=identity_id,
        request_id=request_id,
        correlation_id="corr",
        task_name="summarize",
        model_name="m",
        request_sha256="0" * 64,
    )


async def test_llm_request_id_is_unique_per_project(session: AsyncSession) -> None:
    identity = await factories.make_identity(session)
    session.add(_llm_request(identity.id, identity.project_id, "r1"))
    await session.flush()
    with pytest.raises(IntegrityError):
        await _add_nested(session, _llm_request(identity.id, identity.project_id, "r1"))
    other_project = await factories.make_project(session)
    session.add(_llm_request(identity.id, other_project.id, "r1"))
    await session.flush()


async def test_llm_request_defaults(session: AsyncSession) -> None:
    identity = await factories.make_identity(session)
    row = _llm_request(identity.id, identity.project_id, "r")
    session.add(row)
    await session.flush()
    assert row.status is LLMRequestStatus.RECEIVED
    assert row.provider_attempts == 0


async def test_security_events_are_append_only(session: AsyncSession) -> None:
    event = SecurityEvent(
        event_type=SecurityEventType.ACCESS_DENIED, severity=Severity.WARNING, details={"k": 1}
    )
    session.add(event)
    await session.flush()
    with pytest.raises(DBAPIError, match="append-only"):
        await session.execute(update(SecurityEvent).values(severity=Severity.INFO))
    with pytest.raises(DBAPIError, match="append-only"):
        await session.execute(delete(SecurityEvent))


async def test_audit_logs_are_append_only(session: AsyncSession) -> None:
    row = AuditLog(
        seq=1,
        actor_sub="s",
        actor_role="governance_admin",
        action="project.create",
        resource_type="project",
        outcome="success",
        prev_hash="0" * 64,
        row_hash="1" * 64,
    )
    session.add(row)
    await session.flush()
    assert row.event_metadata == {}
    with pytest.raises(DBAPIError, match="append-only"):
        await session.execute(update(AuditLog).values(action="x"))
    with pytest.raises(DBAPIError, match="append-only"):
        await session.execute(delete(AuditLog))


async def test_rate_counter_composite_key(session: AsyncSession) -> None:
    session.add(RateCounter(key="k", window_start=0, hits=1, expires_at=60))
    session.add(RateCounter(key="k", window_start=60, hits=1, expires_at=120))
    await session.flush()
    with pytest.raises(IntegrityError):
        await _add_nested(session, RateCounter(key="k", window_start=0, hits=1, expires_at=60))


async def test_database_uses_wal_and_foreign_keys(database: Database) -> None:
    async with database.write_engine.connect() as connection:
        assert (await connection.execute(text("PRAGMA journal_mode"))).scalar_one() == "wal"
        assert (await connection.execute(text("PRAGMA foreign_keys"))).scalar_one() == 1
    async with database.read_engine.connect() as connection:
        assert (await connection.execute(text("PRAGMA foreign_keys"))).scalar_one() == 1
