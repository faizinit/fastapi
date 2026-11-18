from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

import app.models as _models  # noqa: F401
from app.core.config import Environment, Settings
from app.db.base import Base
from app.db.session import Database
from app.main import create_app
from tests.tokens import KeyPair


def build_settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": Environment.TEST,
        "database_url": f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}",
        "log_level": "WARNING",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


@pytest.fixture(scope="session")
def keys() -> KeyPair:
    return KeyPair()


@pytest.fixture
def settings(tmp_path: Path, keys: KeyPair) -> Settings:
    return build_settings(tmp_path, jwt_public_key=SecretStr(keys.public_pem))


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def create_schema(application: FastAPI) -> None:
    async with application.state.database.write_engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


@pytest.fixture
async def app(settings: Settings) -> AsyncIterator[FastAPI]:
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        await create_schema(application)
        yield application


@pytest.fixture
def database(app: FastAPI) -> Database:
    db: Database = app.state.database
    return db


@pytest.fixture
async def session(database: Database) -> AsyncIterator[AsyncSession]:
    """A write session for arranging test data; committed on exit."""
    async with database.write_session() as active:
        yield active


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


@pytest.fixture
def admin(keys: KeyPair) -> dict[str, str]:
    return bearer(keys.mint(client_id="admin-1", roles=["governance_admin"]))


@pytest.fixture
def auditor(keys: KeyPair) -> dict[str, str]:
    return bearer(keys.mint(client_id="auditor-1", roles=["audit_reviewer"]))


@pytest.fixture
def outsider(keys: KeyPair) -> dict[str, str]:
    """A valid token that carries no administrative role."""
    return bearer(keys.mint(client_id="outsider-1", roles=["service"]))
