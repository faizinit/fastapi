"""Fixed-window rate limits and quotas backed by SQLite, shared by all workers on a host."""

import asyncio
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, cast

import structlog
from sqlalchemy import CursorResult, delete
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import Database
from app.models.quota import RateCounter

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Limit:
    """At most `limit` hits per `window_seconds` for `key`."""

    key: str
    limit: int
    window_seconds: int
    label: str = ""


@dataclass(frozen=True, slots=True)
class LimitDecision:
    allowed: bool
    violated: Limit | None = None
    retry_after_seconds: int = 0


class RateLimiter:
    def __init__(self, database: Database, clock: Callable[[], float] = time.time) -> None:
        self._database = database
        self._clock = clock

    async def consume(self, limits: Sequence[Limit]) -> LimitDecision:
        """Atomically consume one hit from every limit, or consume nothing if any is exhausted."""
        if not limits:
            return LimitDecision(allowed=True)
        now = int(self._clock())
        async with self._database.write_session() as session:
            counters: list[tuple[Limit, int, RateCounter | None]] = []
            for limit in limits:
                window_start = now - now % limit.window_seconds
                counter = await session.get(RateCounter, (limit.key, window_start))
                hits = counter.hits if counter else 0
                if hits + 1 > limit.limit:
                    retry_after = window_start + limit.window_seconds - now
                    return LimitDecision(False, limit, max(1, retry_after))
                counters.append((limit, window_start, counter))
            for limit, window_start, counter in counters:
                if counter is None:
                    session.add(
                        RateCounter(
                            key=limit.key,
                            window_start=window_start,
                            hits=1,
                            expires_at=window_start + limit.window_seconds,
                        )
                    )
                else:
                    counter.hits += 1
        return LimitDecision(allowed=True)

    async def purge_expired(self) -> int:
        async with self._database.write_session() as session:
            result = await session.execute(
                delete(RateCounter).where(RateCounter.expires_at <= int(self._clock()))
            )
            return cast(CursorResult[Any], result).rowcount  # Any: row type is irrelevant.

    async def purge_forever(self, interval_seconds: float) -> None:
        """Background loop; cancelled on shutdown."""
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                await self.purge_expired()
            except SQLAlchemyError:
                logger.error("rate_counter_purge_failed")
