import asyncio
from pathlib import Path

import httpx
import jwt
import pytest
from sqlalchemy import func, select

from app.core.roles import Role
from app.db.base import Base
from app.db.session import Database
from app.main import create_app
from app.models import AuditLog, Policy, Project, Quota, ServiceIdentity
from scripts import mint_dev_token, seed
from tests.conftest import bearer, build_settings, create_schema


def test_keypair_is_created_once(tmp_path: Path) -> None:
    private_path, public_path = mint_dev_token.ensure_keypair(tmp_path / "keys")
    first = public_path.read_bytes()
    again = mint_dev_token.ensure_keypair(tmp_path / "keys")
    assert again == (private_path, public_path)
    assert public_path.read_bytes() == first
    assert first.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_minted_tokens_verify_with_the_public_key(tmp_path: Path) -> None:
    private_path, public_path = mint_dev_token.ensure_keypair(tmp_path)
    token = mint_dev_token.mint_token(
        private_path,
        client_id="svc",
        roles=[Role.AUDIT_REVIEWER],
        ttl_seconds=60,
        issuer="https://idp.example.internal",
        audience="central-security",
    )
    claims = jwt.decode(
        token,
        public_path.read_bytes(),
        algorithms=["RS256"],
        audience="central-security",
        issuer="https://idp.example.internal",
    )
    assert claims["client_id"] == "svc"
    assert claims["roles"] == ["audit_reviewer"]
    assert claims["exp"] - claims["iat"] == 60


def test_mint_cli_prints_a_token(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = mint_dev_token.main(
        ["--client-id", "cli-app", "--roles", "governance_admin", "--key-dir", str(tmp_path)]
    )
    out = capsys.readouterr().out.splitlines()
    assert exit_code == 0
    claims = jwt.decode(out[0], options={"verify_signature": False})
    assert claims["client_id"] == "cli-app"
    assert claims["roles"] == ["governance_admin"]
    assert out[1].startswith("# verify with CS_JWT_PUBLIC_KEY_PATH=")


async def test_seed_is_idempotent_and_audited(database: Database) -> None:
    first = await seed.seed(database)
    second = await seed.seed(database)
    assert len(first.created) == 8
    assert second.created == []
    async with database.read_sessions() as session:
        counts = {
            model.__name__: (
                await session.execute(select(func.count()).select_from(model))
            ).scalar_one()
            for model in (Project, ServiceIdentity, Policy, Quota, AuditLog)
        }
        entry = (await session.execute(select(AuditLog))).scalar_one()
    assert counts == {"Project": 1, "ServiceIdentity": 1, "Policy": 1, "Quota": 1, "AuditLog": 1}
    assert entry.action == "seed.apply"
    assert entry.actor_sub == "seed-script"


async def test_seeded_demo_application_can_call_the_gateway(tmp_path: Path) -> None:
    private_path, public_path = mint_dev_token.ensure_keypair(tmp_path / "keys")
    application = create_app(build_settings(tmp_path, jwt_public_key_path=public_path))
    async with application.router.lifespan_context(application):
        await create_schema(application)
        await seed.seed(application.state.database)
        token = mint_dev_token.mint_token(
            private_path,
            client_id=seed.DEMO_CLIENT_ID,
            roles=[],
            ttl_seconds=300,
            issuer="https://idp.example.internal",
            audience="central-security",
        )
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            response = await http.post(
                "/api/v1/llm/process",
                json={
                    "requestId": "demo-1",
                    "task": seed.DEMO_TASK,
                    "model": seed.DEMO_MODEL,
                    "input": "Summarize this paragraph.",
                },
                headers=bearer(token),
            )
            blocked = await http.post(
                "/api/v1/llm/process",
                json={
                    "requestId": "demo-2",
                    "task": seed.DEMO_TASK,
                    "model": seed.DEMO_MODEL,
                    "input": "Summarize SSN 123-45-6789",
                },
                headers=bearer(token),
            )
    assert response.status_code == 200
    assert blocked.status_code == 502


async def migrated_database_url(tmp_path: Path) -> str:
    settings = build_settings(tmp_path)
    database = Database(settings)
    async with database.write_engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    await database.dispose()
    return settings.database_url


async def test_seed_command_runs_and_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CS_DATABASE_URL", await migrated_database_url(tmp_path))
    assert await seed.run() == 0
    assert "Created:" in capsys.readouterr().out
    assert await seed.run() == 0
    assert "Already seeded." in capsys.readouterr().out


async def test_seed_command_explains_a_missing_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CS_DATABASE_URL", build_settings(tmp_path).database_url)
    assert await seed.run() == 1
    assert "make migrate" in capsys.readouterr().out


async def test_seed_main_entry_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CS_DATABASE_URL", await migrated_database_url(tmp_path))
    exit_code = await asyncio.to_thread(seed.main)
    assert exit_code == 0
