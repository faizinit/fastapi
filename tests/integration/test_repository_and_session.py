import asyncio
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError
from app.db.session import Database
from app.models import Project, RateCounter
from app.models.enums import ProjectStatus
from app.repositories.base import BaseRepository
from app.repositories.project import ProjectRepository
from tests import factories
from tests.conftest import build_settings


@pytest.fixture
def repo(session: AsyncSession) -> ProjectRepository:
    return ProjectRepository(session)


async def test_add_and_get(repo: ProjectRepository) -> None:
    project = await repo.add(Project(project_key="COE_1", name="One", team="COE"))
    assert (await repo.get(project.id)) is project
    assert await repo.get(uuid.uuid4()) is None


async def test_add_translates_integrity_error_to_conflict(repo: ProjectRepository) -> None:
    await repo.add(Project(project_key="COE_1", name="One", team="COE"))
    with pytest.raises(ConflictError):
        await repo.add(Project(project_key="COE_1", name="Dup", team="COE"))


async def test_soft_delete_hides_rows(repo: ProjectRepository, session: AsyncSession) -> None:
    project = await factories.make_project(session)
    await repo.soft_delete(project)
    assert project.deleted_at is not None
    assert await repo.get(project.id) is None
    assert await repo.find_one(Project.id == project.id) is None
    assert not await repo.exists(Project.id == project.id)
    assert (await repo.paginate())[1] == 0
    still_stored = (await session.execute(select(Project))).scalars().all()
    assert len(still_stored) == 1


async def test_find_one_and_exists(repo: ProjectRepository, session: AsyncSession) -> None:
    await factories.make_project(session, project_key="COE_9")
    assert (await repo.find_one(Project.project_key == "COE_9")) is not None
    assert await repo.exists(Project.project_key == "COE_9")
    assert not await repo.exists(Project.project_key == "NOPE")


async def test_list_paginates_with_total(repo: ProjectRepository, session: AsyncSession) -> None:
    for index in range(5):
        await factories.make_project(session, name=f"p{index}")
    page, total = await repo.paginate(sort="name", limit=2, offset=1)
    assert total == 5
    assert [p.name for p in page] == ["p1", "p2"]


async def test_list_sorts_descending_and_filters(
    repo: ProjectRepository, session: AsyncSession
) -> None:
    await factories.make_project(session, name="a", team="X")
    await factories.make_project(session, name="b", team="Y")
    await factories.make_project(session, name="c", team="X")
    rows, total = await repo.paginate(criteria=[Project.team == "X"], sort="name", descending=True)
    assert total == 2
    assert [p.name for p in rows] == ["c", "a"]


async def test_list_default_sort_is_created_at(
    repo: ProjectRepository, session: AsyncSession
) -> None:
    first = await factories.make_project(session)
    second = await factories.make_project(session)
    rows, _ = await repo.paginate()
    assert {p.id for p in rows} == {first.id, second.id}


async def test_unknown_sort_key_is_rejected(repo: ProjectRepository) -> None:
    with pytest.raises(ValueError, match="not allowed"):
        await repo.paginate(sort="password")


async def test_delete_removes_row(session: AsyncSession) -> None:
    class Plain(BaseRepository[Project]):
        model = Project

    repository = Plain(session)
    project = await factories.make_project(session, status=ProjectStatus.ACTIVE)
    await repository.delete(project)
    assert await repository.get(project.id) is None


async def test_concurrent_write_units_are_serialised(database: Database) -> None:
    async def write(key: str) -> None:
        async with database.write_session() as session:
            session.add(RateCounter(key=key, window_start=0, hits=1, expires_at=1))
            await session.flush()
            await asyncio.sleep(0.05)

    await asyncio.gather(*(write(f"k{i}") for i in range(8)))
    async with database.read_sessions() as reader:
        assert len((await reader.execute(select(RateCounter))).scalars().all()) == 8


async def test_write_session_rolls_back_on_error(database: Database) -> None:
    async def failing_unit_of_work() -> None:
        async with database.write_session() as session:
            session.add(RateCounter(key="gone", window_start=0, hits=1, expires_at=1))
            await session.flush()
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await failing_unit_of_work()
    async with database.read_sessions() as reader:
        assert (await reader.execute(select(RateCounter))).scalars().all() == []


def test_non_sqlite_urls_are_rejected(tmp_path: Path) -> None:
    settings = build_settings(tmp_path, database_url="postgresql+asyncpg://u:p@h/db")
    with pytest.raises(ValueError, match="only SQLite"):
        Database(settings)


@pytest.mark.parametrize("url", ["sqlite+aiosqlite://", "sqlite+aiosqlite:///:memory:"])
def test_in_memory_sqlite_is_rejected(tmp_path: Path, url: str) -> None:
    with pytest.raises(ValueError, match="in-memory"):
        Database(build_settings(tmp_path, database_url=url))
