"""Audit chain, rate limiter and security-event recorder."""

import asyncio

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Actor, RequestMeta
from app.core.metrics import Metrics
from app.db.session import Database
from app.models import RateCounter, SecurityEvent
from app.models.audit_log import GENESIS_HASH, AuditLog
from app.models.enums import SecurityEventType, Severity
from app.services.audit import AuditService
from app.services.rate_limiter import Limit, RateLimiter
from app.services.security_events import (
    MAX_DETAIL_STRING,
    SecurityEventRecorder,
    sanitize_details,
)

ACTOR = Actor(subject="admin-1", role="governance_admin")
META = RequestMeta(correlation_id="corr-1", source_ip="10.0.0.1")


@pytest.fixture
def audit(database: Database) -> AuditService:
    return AuditService(database)


@pytest.fixture
def recorder(database: Database) -> SecurityEventRecorder:
    return SecurityEventRecorder(database, Metrics())


class Clock:
    def __init__(self, now: float = 10_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


async def test_audit_entries_form_a_valid_chain(audit: AuditService, database: Database) -> None:
    first = await audit.record(
        actor=ACTOR, action="project.create", resource_type="project", meta=META
    )
    second = await audit.record(
        actor=ACTOR,
        action="project.update",
        resource_type="project",
        resource_id="p1",
        request_id="req-9",
        details={"changed": ["name"], "token": "abc"},
        meta=META,
    )
    assert (first.seq, second.seq) == (1, 2)
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.row_hash
    assert second.event_metadata == {"changed": ["name"], "token": "***"}
    async with database.read_sessions() as session:
        result = await audit.verify(session, 1, 100)
    assert (result.valid, result.checked, result.first_broken_seq) == (True, 2, None)


async def test_empty_chain_verifies(audit: AuditService, database: Database) -> None:
    async with database.read_sessions() as session:
        assert (await audit.verify(session, 1, 10)).valid


async def test_concurrent_appends_stay_contiguous(audit: AuditService, database: Database) -> None:
    await asyncio.gather(
        *(
            audit.record(actor=ACTOR, action=f"a{i}", resource_type="project", meta=META)
            for i in range(15)
        )
    )
    async with database.read_sessions() as session:
        seqs = (await session.execute(select(AuditLog.seq).order_by(AuditLog.seq))).scalars().all()
        result = await audit.verify(session, 1, 100)
    assert list(seqs) == list(range(1, 16))
    assert result.valid
    assert result.checked == 15


async def test_verify_from_middle_of_chain(audit: AuditService, database: Database) -> None:
    for index in range(4):
        await audit.record(actor=ACTOR, action=f"a{index}", resource_type="x", meta=META)
    async with database.read_sessions() as session:
        result = await audit.verify(session, 3, 4)
    assert (result.valid, result.checked) == (True, 2)


async def _tamper(database: Database, statement: str) -> None:
    """Bypass the append-only triggers the way a privileged attacker with file access could."""
    async with database.write_session() as session:
        await session.execute(text("DROP TRIGGER trg_audit_logs_no_update"))
        await session.execute(text("DROP TRIGGER trg_audit_logs_no_delete"))
        await session.execute(text(statement))


async def test_modified_entry_is_detected(audit: AuditService, database: Database) -> None:
    for index in range(3):
        await audit.record(actor=ACTOR, action=f"a{index}", resource_type="x", meta=META)
    await _tamper(database, "UPDATE audit_logs SET outcome = 'forged' WHERE seq = 2")
    async with database.read_sessions() as session:
        result = await audit.verify(session, 1, 3)
    assert (result.valid, result.first_broken_seq, result.checked) == (False, 2, 1)


async def test_deleted_entry_is_detected(audit: AuditService, database: Database) -> None:
    for index in range(3):
        await audit.record(actor=ACTOR, action=f"a{index}", resource_type="x", meta=META)
    await _tamper(database, "DELETE FROM audit_logs WHERE seq = 2")
    async with database.read_sessions() as session:
        result = await audit.verify(session, 1, 3)
    assert (result.valid, result.first_broken_seq) == (False, 2)


async def test_audit_rows_cannot_be_changed_normally(
    audit: AuditService, database: Database
) -> None:
    await audit.record(actor=ACTOR, action="a", resource_type="x", meta=META)
    async with database.write_session() as session:
        with pytest.raises(IntegrityError, match="append-only"):
            await session.execute(text("UPDATE audit_logs SET outcome = 'forged'"))


async def test_audit_append_rolls_back_with_caller_transaction(
    audit: AuditService, database: Database
) -> None:
    async def failing_unit() -> None:
        async with database.write_session() as session:
            await audit.append(session, actor=ACTOR, action="a", resource_type="x", meta=META)
            raise RuntimeError("business failure")

    with pytest.raises(RuntimeError):
        await failing_unit()
    async with database.read_sessions() as session:
        assert (await session.execute(select(AuditLog))).scalars().all() == []


async def test_rate_limit_allows_up_to_limit_then_denies(database: Database) -> None:
    clock = Clock(10_000)
    limiter = RateLimiter(database, clock)
    limit = Limit("caller:a", 3, 60)
    for _ in range(3):
        assert (await limiter.consume([limit])).allowed
    denied = await limiter.consume([limit])
    assert not denied.allowed
    assert denied.violated == limit
    assert 1 <= denied.retry_after_seconds <= 60


async def test_rate_limit_window_rolls_over(database: Database) -> None:
    clock = Clock(10_050)
    limiter = RateLimiter(database, clock)
    limit = Limit("k", 1, 60)
    assert (await limiter.consume([limit])).allowed
    denied = await limiter.consume([limit])
    assert denied.retry_after_seconds == 30
    clock.now += 31
    assert (await limiter.consume([limit])).allowed


async def test_denied_consume_takes_nothing_from_other_limits(database: Database) -> None:
    limiter = RateLimiter(database, Clock())
    tight = Limit("tight", 1, 60)
    loose = Limit("loose", 10, 60)
    assert (await limiter.consume([tight, loose])).allowed
    assert not (await limiter.consume([loose, tight])).allowed
    async with database.read_sessions() as session:
        hits = {row.key: row.hits for row in (await session.execute(select(RateCounter))).scalars()}
    assert hits == {"tight": 1, "loose": 1}


async def test_limits_are_independent_per_key(database: Database) -> None:
    limiter = RateLimiter(database, Clock())
    assert (await limiter.consume([Limit("a", 1, 60)])).allowed
    assert (await limiter.consume([Limit("b", 1, 60)])).allowed


async def test_no_limits_is_allowed(database: Database) -> None:
    assert (await RateLimiter(database).consume([])).allowed


async def test_concurrent_consumption_never_exceeds_limit(database: Database) -> None:
    limiter = RateLimiter(database, Clock())
    results = await asyncio.gather(*(limiter.consume([Limit("c", 5, 60)]) for _ in range(20)))
    assert sum(1 for r in results if r.allowed) == 5


async def test_purge_removes_only_expired_counters(database: Database) -> None:
    clock = Clock(10_000)
    limiter = RateLimiter(database, clock)
    await limiter.consume([Limit("short", 5, 10)])
    await limiter.consume([Limit("long", 5, 3600)])
    clock.now += 30
    assert await limiter.purge_expired() == 1
    async with database.read_sessions() as session:
        keys = (await session.execute(select(RateCounter.key))).scalars().all()
    assert list(keys) == ["long"]


async def test_purge_loop_runs_and_is_cancellable(database: Database) -> None:
    clock = Clock(10_000)
    limiter = RateLimiter(database, clock)
    await limiter.consume([Limit("short", 5, 10)])
    clock.now += 30
    task = asyncio.create_task(limiter.purge_forever(0.01))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with database.read_sessions() as session:
        assert (await session.execute(select(RateCounter))).scalars().all() == []


async def test_purge_loop_survives_database_errors(
    database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    limiter = RateLimiter(database)

    async def failing() -> int:
        raise OperationalError("DELETE", {}, Exception("locked"))

    monkeypatch.setattr(limiter, "purge_expired", failing)
    task = asyncio.create_task(limiter.purge_forever(0.01))
    await asyncio.sleep(0.05)
    assert not task.done()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_security_event_is_persisted_and_counted(
    database: Database, session: AsyncSession
) -> None:
    metrics = Metrics()
    recorder = SecurityEventRecorder(database, metrics)
    await recorder.record(
        SecurityEventType.ACCESS_DENIED,
        Severity.WARNING,
        request_id="r1",
        correlation_id="c1",
        caller_sub="sub",
        source_ip="10.0.0.9",
        details={"reason": "role", "password": "hunter2"},
    )
    async with database.read_sessions() as reader:
        event = (await reader.execute(select(SecurityEvent))).scalar_one()
    assert event.event_type is SecurityEventType.ACCESS_DENIED
    assert event.details == {"reason": "role", "password": "***"}
    assert event.caller_sub == "sub"
    assert b'security_events_total{event_type="access_denied"} 1.0' in metrics.render()


async def test_try_record_swallows_database_failures(
    database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = SecurityEventRecorder(database, Metrics())

    def broken() -> None:
        raise OperationalError("INSERT", {}, Exception("db down"))

    monkeypatch.setattr(database, "write_session", broken)
    await recorder.try_record(SecurityEventType.AUTH_FAILED, Severity.WARNING)
    with pytest.raises(OperationalError):
        await recorder.record(SecurityEventType.AUTH_FAILED, Severity.WARNING)


async def test_try_record_persists_on_success(
    recorder: SecurityEventRecorder, database: Database
) -> None:
    await recorder.try_record(SecurityEventType.RATE_LIMITED, Severity.INFO, request_id="r")
    async with database.read_sessions() as reader:
        assert (await reader.execute(select(SecurityEvent))).scalar_one().request_id == "r"


def test_sanitize_details_masks_and_truncates() -> None:
    cleaned = sanitize_details(
        {"long": "x" * 900, "api_key": "k", "n": 1, "nested": {"secret": "s"}}
    )
    assert cleaned["api_key"] == "***"
    assert cleaned["n"] == 1
    assert cleaned["nested"] == {"secret": "***"}
    assert isinstance(cleaned["long"], str)
    assert len(cleaned["long"]) == MAX_DETAIL_STRING + 3
