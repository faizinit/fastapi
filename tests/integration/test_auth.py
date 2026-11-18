from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AdminDep, AuditorDep, ReviewerDep
from app.core.logging import configure_logging
from app.core.roles import Role
from app.db.session import Database
from app.main import create_app
from app.models import SecurityEvent
from app.models.enums import IdentityStatus, ProjectStatus, SecurityEventType
from tests import factories
from tests.conftest import bearer, build_settings, create_schema
from tests.tokens import KeyPair


@pytest.fixture
def role_app(app: FastAPI) -> FastAPI:
    """The application with routes guarded by each role dependency."""

    @app.get("/probe/admin")
    async def admin_only(principal: AdminDep) -> dict[str, str]:
        return {"sub": principal.subject}

    @app.get("/probe/auditor")
    async def auditor_only(principal: AuditorDep) -> dict[str, str]:
        return {"sub": principal.subject}

    @app.get("/probe/reviewer")
    async def reviewer(principal: ReviewerDep) -> dict[str, str]:
        return {"sub": principal.subject}

    return app


@pytest.fixture
async def roles_client(role_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=role_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def events(database: Database) -> list[SecurityEvent]:
    async with database.read_sessions() as reader:
        rows = (
            await reader.execute(select(SecurityEvent).order_by(SecurityEvent.occurred_at))
        ).scalars()
        return list(rows.all())


async def test_missing_credentials_are_401_and_recorded(
    client: httpx.AsyncClient, database: Database
) -> None:
    response = await client.get("/api/v1/me", headers={"X-Request-ID": "trace-1"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["type"] == "urn:central-security:problem:unauthorized"
    (event,) = await events(database)
    assert event.event_type is SecurityEventType.AUTH_FAILED
    assert event.correlation_id == "trace-1"
    assert event.details == {"reason": "missing_credentials"}


async def test_non_bearer_scheme_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/me", headers={"Authorization": "Basic dTpw"})
    assert response.status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [{"expires_in": -3600}, {"issuer": "https://evil.example"}, {"audience": "other"}],
)
async def test_invalid_tokens_are_401(
    client: httpx.AsyncClient, keys: KeyPair, database: Database, overrides: dict[str, object]
) -> None:
    response = await client.get("/api/v1/me", headers=bearer(keys.mint(**overrides)))  # type: ignore[arg-type]
    assert response.status_code == 401
    assert (await events(database))[0].details == {"reason": "invalid_token"}


async def test_garbage_token_is_401_without_leaking_detail(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/me", headers=bearer("garbage"))
    assert response.status_code == 401
    assert "garbage" not in response.text


async def test_tokens_signed_by_unknown_key_are_401(client: httpx.AsyncClient) -> None:
    attacker = KeyPair(kid="evil")
    response = await client.get("/api/v1/me", headers=bearer(attacker.mint()))
    assert response.status_code == 401


async def test_me_for_unregistered_caller(client: httpx.AsyncClient, keys: KeyPair) -> None:
    token = keys.mint(client_id="stranger", roles=["governance_admin"])
    response = await client.get("/api/v1/me", headers=bearer(token))
    assert response.status_code == 200
    assert response.json() == {
        "subject": "sub-stranger",
        "clientId": "stranger",
        "tokenRoles": ["governance_admin"],
        "identity": None,
    }


async def test_me_for_registered_caller(
    client: httpx.AsyncClient, keys: KeyPair, session: AsyncSession
) -> None:
    project = await factories.make_project(
        session, project_key="COE_1", team="COE", status=ProjectStatus.ACTIVE
    )
    identity = await factories.make_identity(session, project, client_id="app-1")
    await session.commit()
    response = await client.get("/api/v1/me", headers=bearer(keys.mint(client_id="app-1")))
    body = response.json()
    assert response.status_code == 200
    assert body["identity"]["identityId"] == str(identity.id)
    assert body["identity"]["projectKey"] == "COE_1"
    assert body["identity"]["status"] == IdentityStatus.APPROVED
    assert body["identity"]["roles"] == ["service"]


async def test_request_body_cannot_override_identity(
    client: httpx.AsyncClient, keys: KeyPair, session: AsyncSession
) -> None:
    await factories.make_identity(session, client_id="app-1")
    await session.commit()
    response = await client.get(
        "/api/v1/me?projectId=other&team=other",
        headers=bearer(keys.mint(client_id="app-1")),
    )
    assert response.json()["identity"]["team"] == "COE"


async def test_role_dependencies_allow_matching_roles(
    roles_client: httpx.AsyncClient, keys: KeyPair
) -> None:
    admin = bearer(keys.mint(roles=[Role.GOVERNANCE_ADMIN]))
    auditor = bearer(keys.mint(roles=[Role.AUDIT_REVIEWER]))
    assert (await roles_client.get("/probe/admin", headers=admin)).status_code == 200
    assert (await roles_client.get("/probe/auditor", headers=auditor)).status_code == 200
    assert (await roles_client.get("/probe/reviewer", headers=admin)).status_code == 200
    assert (await roles_client.get("/probe/reviewer", headers=auditor)).status_code == 200


async def test_role_dependencies_deny_other_roles_and_record_event(
    roles_client: httpx.AsyncClient, keys: KeyPair, database: Database
) -> None:
    service = bearer(keys.mint(client_id="svc", roles=[Role.SERVICE]))
    for path in ("/probe/admin", "/probe/auditor", "/probe/reviewer"):
        response = await roles_client.get(path, headers=service)
        assert response.status_code == 403
        assert response.json()["type"] == "urn:central-security:problem:forbidden"
    recorded = await events(database)
    assert len(recorded) == 3
    assert {e.event_type for e in recorded} == {SecurityEventType.ACCESS_DENIED}
    assert recorded[0].caller_sub == "sub-svc"
    assert recorded[0].details == {"requiredRoles": ["governance_admin"]}


async def test_token_without_roles_is_denied(
    roles_client: httpx.AsyncClient, keys: KeyPair
) -> None:
    response = await roles_client.get("/probe/admin", headers=bearer(keys.mint()))
    assert response.status_code == 403


async def test_repeated_auth_failures_are_throttled(tmp_path: Path, keys: KeyPair) -> None:
    settings = build_settings(
        tmp_path, jwt_public_key=keys.public_pem, auth_failure_limit_per_minute=3
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        await create_schema(application)
        transport = httpx.ASGITransport(app=application, client=("203.0.113.5", 5000))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            statuses = [
                (await http.get("/api/v1/me", headers=bearer("bad"))).status_code for _ in range(5)
            ]
            throttled = await http.get("/api/v1/me", headers=bearer("bad"))
            valid = await http.get("/api/v1/me", headers=bearer(keys.mint()))
        recorded = await events(application.state.database)
    assert statuses == [401, 401, 401, 429, 429]
    assert throttled.headers["retry-after"].isdigit()
    assert valid.status_code == 200
    kinds = [e.event_type for e in recorded]
    assert kinds.count(SecurityEventType.AUTH_FAILED) == 3
    assert kinds.count(SecurityEventType.RATE_LIMITED) == 3
    assert recorded[0].source_ip == "203.0.113.5"


async def test_failures_from_one_ip_do_not_throttle_another(tmp_path: Path, keys: KeyPair) -> None:
    settings = build_settings(
        tmp_path, jwt_public_key=keys.public_pem, auth_failure_limit_per_minute=1
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        await create_schema(application)
        first = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application, client=("198.51.100.1", 1)),
            base_url="http://t",
        )
        second = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application, client=("198.51.100.2", 1)),
            base_url="http://t",
        )
        async with first, second:
            assert (await first.get("/api/v1/me")).status_code == 401
            assert (await first.get("/api/v1/me")).status_code == 429
            assert (await second.get("/api/v1/me")).status_code == 401


async def test_auth_fails_closed_when_no_signing_key_is_configured(
    tmp_path: Path, keys: KeyPair
) -> None:
    application = create_app(build_settings(tmp_path))
    async with application.router.lifespan_context(application):
        await create_schema(application)
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            me = await http.get("/api/v1/me", headers=bearer(keys.mint()))
            ready = await http.get("/ready")
        recorded = await events(application.state.database)
    assert me.status_code == 503
    assert ready.status_code == 503
    assert recorded[0].event_type is SecurityEventType.DEPENDENCY_UNAVAILABLE
    assert recorded[0].details == {"dependency": "identity_provider"}


async def test_ready_reports_identity_provider(client: httpx.AsyncClient) -> None:
    body = (await client.get("/ready")).json()
    assert body["checks"] == {"database": "ok", "identity_provider": "ok"}


async def test_authenticated_requests_log_the_principal(
    client: httpx.AsyncClient, keys: KeyPair, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(level="INFO", json_logs=True)
    await client.get("/api/v1/me", headers=bearer(keys.mint(client_id="logged")))
    assert '"user_id": "sub-logged"' in capsys.readouterr().err
