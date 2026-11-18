"""Database engines and session factories.

SQLite allows a single writer. Reads use a default engine; every write unit of work uses a
second engine whose transactions begin with ``BEGIN IMMEDIATE`` so that a writer never
upgrades a stale read snapshot (which SQLite would reject with SQLITE_BUSY_SNAPSHOT).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import ConnectionPoolEntry

from app.core.config import Settings


def _engine_kwargs(settings: Settings) -> dict[str, Any]:
    return {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_timeout": settings.db_pool_timeout_seconds,
        "pool_pre_ping": True,
    }


def _configure_sqlite(engine: AsyncEngine, *, busy_timeout_ms: int, immediate: bool) -> None:
    sync_engine = engine.sync_engine

    @event.listens_for(sync_engine, "connect")
    def _on_connect(dbapi_connection: Any, _: ConnectionPoolEntry) -> None:
        if immediate:
            dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        cursor.close()

    if immediate:

        @event.listens_for(sync_engine, "begin")
        def _on_begin(conn: Any) -> None:
            conn.exec_driver_sql("BEGIN IMMEDIATE")


class Database:
    """Owns the read and write engines for the lifetime of the application."""

    def __init__(self, settings: Settings) -> None:
        url = make_url(settings.database_url)
        if url.get_backend_name() != "sqlite":
            raise ValueError("only SQLite database URLs are supported")
        if url.database in (None, "", ":memory:"):
            raise ValueError("in-memory SQLite is not supported; use a file database")
        kwargs = _engine_kwargs(settings)
        self.read_engine = create_async_engine(settings.database_url, **kwargs)
        self.write_engine = create_async_engine(settings.database_url, **kwargs)
        _configure_sqlite(
            self.read_engine, busy_timeout_ms=settings.db_busy_timeout_ms, immediate=False
        )
        _configure_sqlite(
            self.write_engine, busy_timeout_ms=settings.db_busy_timeout_ms, immediate=True
        )
        self.read_sessions = async_sessionmaker(self.read_engine, expire_on_commit=False)
        self.write_sessions = async_sessionmaker(self.write_engine, expire_on_commit=False)

    @asynccontextmanager
    async def write_session(self) -> AsyncIterator[AsyncSession]:
        """A write unit of work: commits on success, rolls back on error."""
        async with self.write_sessions() as session, session.begin():
            yield session

    async def ping(self) -> None:
        async with self.read_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    async def dispose(self) -> None:
        await self.read_engine.dispose()
        await self.write_engine.dispose()
