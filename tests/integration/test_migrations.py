import asyncio
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

import app.models  # noqa: F401
from app.db.base import Base

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_TABLES = {
    "audit_logs",
    "llm_models",
    "llm_requests",
    "policies",
    "project_models",
    "project_tasks",
    "projects",
    "quotas",
    "rate_counters",
    "security_events",
    "service_identities",
    "tasks",
}


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "migrate.db"


@pytest.fixture
def alembic_cfg(db_path: Path) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path.as_posix()}")
    return cfg


def objects(db_path: Path, kind: str) -> set[str]:
    connection = sqlite3.connect(db_path)
    try:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = ?", (kind,))
        return {row[0] for row in rows.fetchall()}
    finally:
        connection.close()


async def test_upgrade_creates_schema_and_triggers(alembic_cfg: Config, db_path: Path) -> None:
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")
    assert objects(db_path, "table") >= EXPECTED_TABLES
    assert objects(db_path, "trigger") == {
        "trg_audit_logs_no_update",
        "trg_audit_logs_no_delete",
        "trg_security_events_no_update",
        "trg_security_events_no_delete",
    }


async def test_migrated_schema_matches_models(alembic_cfg: Config, db_path: Path) -> None:
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection, opts={"compare_type": True})
            assert compare_metadata(context, Base.metadata) == []
    finally:
        engine.dispose()


async def test_downgrade_removes_everything_and_reupgrade_works(
    alembic_cfg: Config, db_path: Path
) -> None:
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")
    await asyncio.to_thread(command.downgrade, alembic_cfg, "base")
    assert objects(db_path, "table") <= {"alembic_version"}
    assert objects(db_path, "trigger") == set()
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")
    assert objects(db_path, "table") >= EXPECTED_TABLES


async def test_offline_sql_generation(
    alembic_cfg: Config, capsys: pytest.CaptureFixture[str]
) -> None:
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head", sql=True)
    assert "CREATE TABLE projects" in capsys.readouterr().out


async def test_migration_triggers_make_audit_logs_append_only(
    alembic_cfg: Config, db_path: Path
) -> None:
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "INSERT INTO audit_logs (id, seq, actor_sub, actor_role, action, resource_type,"
            " outcome, metadata, prev_hash, row_hash, occurred_at) VALUES"
            " ('a', 1, 's', 'r', 'x', 't', 'ok', '{}', 'p', 'h', '2026-01-01')"
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE audit_logs SET action = 'y'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM audit_logs")
    finally:
        connection.close()
