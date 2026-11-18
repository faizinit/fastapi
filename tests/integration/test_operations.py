from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.core.exceptions import (
    DependencyUnavailableError,
    RateLimitedError,
    UnauthorizedError,
)
from app.main import create_app
from tests.conftest import build_settings


class Item(BaseModel):
    name: str = Field(min_length=3)
    count: int


@pytest.fixture
def probe_app(app: FastAPI) -> FastAPI:
    """The application with extra routes that exercise error handling."""

    @app.post("/probe/validate")
    async def validate(item: Item) -> Item:
        return item

    @app.get("/probe/boom")
    async def boom() -> None:
        raise RuntimeError("internal detail that must not leak")

    @app.get("/probe/limited")
    async def limited() -> None:
        raise RateLimitedError(retry_after_seconds=7)

    @app.get("/probe/unauthorized")
    async def unauthorized() -> None:
        raise UnauthorizedError

    @app.get("/probe/db-down")
    async def db_down() -> None:
        raise OperationalError("SELECT 1", {}, Exception("unable to open database file"))

    @app.get("/probe/dependency")
    async def dependency() -> None:
        raise DependencyUnavailableError("down")

    return app


@pytest.fixture
async def probe(probe_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=probe_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def test_health(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_ready_checks_database(client: httpx.AsyncClient) -> None:
    response = await client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"database": "ok", "identity_provider": "ok"},
    }


async def test_ready_reports_503_when_database_down(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def failing_ping() -> None:
        raise OperationalError("SELECT 1", {}, Exception("down"))

    monkeypatch.setattr(app.state.database, "ping", failing_ping)
    response = await client.get("/ready")
    assert response.status_code == 503
    assert response.headers["content-type"].startswith("application/problem+json")
    assert "down" not in response.json()["detail"]


async def test_request_id_is_generated(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert len(response.headers["x-request-id"]) == 36


async def test_valid_request_id_is_echoed(client: httpx.AsyncClient) -> None:
    response = await client.get("/health", headers={"X-Request-ID": "abc-123.x_y"})
    assert response.headers["x-request-id"] == "abc-123.x_y"


async def test_invalid_request_id_is_replaced(client: httpx.AsyncClient) -> None:
    response = await client.get("/health", headers={"X-Request-ID": "bad id\twith spaces"})
    assert response.headers["x-request-id"] != "bad id\twith spaces"
    assert len(response.headers["x-request-id"]) == 36


async def test_security_headers_present(client: httpx.AsyncClient) -> None:
    headers = (await client.get("/health")).headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert "default-src 'none'" in headers["content-security-policy"]
    assert "strict-transport-security" not in headers


async def test_docs_skip_strict_csp_and_work(client: httpx.AsyncClient) -> None:
    response = await client.get("/docs")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers


async def test_hsts_in_production(tmp_path: Path) -> None:
    settings = build_settings(
        tmp_path,
        environment="production",
        docs_enabled=False,
        jwt_jwks_url="https://idp.example.internal/jwks",
    )
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            response = await http.get("/health")
            assert "max-age=31536000" in response.headers["strict-transport-security"]
            assert (await http.get("/docs")).status_code == 404
            assert (await http.get("/openapi.json")).status_code == 404


async def test_cors_preflight_allows_configured_origin(tmp_path: Path) -> None:
    settings = build_settings(tmp_path, cors_origins=["https://app.example.internal"])
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            allowed = await http.options(
                "/health",
                headers={
                    "Origin": "https://app.example.internal",
                    "Access-Control-Request-Method": "GET",
                },
            )
            denied = await http.options(
                "/health",
                headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
            )
    assert allowed.headers["access-control-allow-origin"] == "https://app.example.internal"
    assert "access-control-allow-origin" not in denied.headers
    assert allowed.headers["x-request-id"]


async def test_unknown_route_is_problem_json(client: httpx.AsyncClient) -> None:
    response = await client.get("/nope")
    body = response.json()
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    assert body["type"] == "urn:central-security:problem:not-found"
    assert body["instance"] == "/nope"
    assert body["requestId"] == response.headers["x-request-id"]


async def test_method_not_allowed_is_problem_json(client: httpx.AsyncClient) -> None:
    response = await client.post("/health")
    assert response.status_code == 405
    assert response.json()["title"] == "Method Not Allowed"


async def test_validation_errors_are_400_with_field_errors(probe: httpx.AsyncClient) -> None:
    response = await probe.post("/probe/validate", json={"name": "x", "count": "many", "extra": 1})
    body = response.json()
    assert response.status_code == 400
    assert body["type"] == "urn:central-security:problem:validation-failed"
    fields = {error["field"] for error in body["errors"]}
    assert {"name", "count"} <= fields
    assert "many" not in response.text


async def test_malformed_json_is_400(probe: httpx.AsyncClient) -> None:
    response = await probe.post(
        "/probe/validate", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400


async def test_unhandled_exception_returns_generic_500(probe: httpx.AsyncClient) -> None:
    response = await probe.get("/probe/boom")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    assert "internal detail" not in response.text
    assert response.headers["x-request-id"]


async def test_rate_limited_error_sets_retry_after(probe: httpx.AsyncClient) -> None:
    response = await probe.get("/probe/limited")
    assert response.status_code == 429
    assert response.headers["retry-after"] == "7"


async def test_unauthorized_error_sets_authenticate_header(probe: httpx.AsyncClient) -> None:
    response = await probe.get("/probe/unauthorized")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_database_errors_map_to_503(probe: httpx.AsyncClient) -> None:
    response = await probe.get("/probe/db-down")
    assert response.status_code == 503
    assert "unable to open" not in response.text
    assert response.headers["retry-after"] == "5"


async def test_dependency_unavailable_maps_to_503(probe: httpx.AsyncClient) -> None:
    response = await probe.get("/probe/dependency")
    assert response.status_code == 503


async def test_declared_oversize_body_is_413(tmp_path: Path) -> None:
    application = create_app(build_settings(tmp_path, max_request_body_bytes=10))
    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            response = await http.post("/health", content=b"x" * 11)
    assert response.status_code == 413
    assert response.headers["x-request-id"]
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_streamed_oversize_body_is_413(tmp_path: Path) -> None:
    application = create_app(build_settings(tmp_path, max_request_body_bytes=10))

    @application.post("/probe/echo")
    async def echo(item: Item) -> Item:
        return item

    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"name": "abcdef", '
        yield b'"count": 1}'

    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            response = await http.post(
                "/probe/echo", content=chunks(), headers={"Content-Type": "application/json"}
            )
    assert response.status_code == 413


async def test_small_body_passes_size_limit(probe: httpx.AsyncClient) -> None:
    response = await probe.post("/probe/validate", json={"name": "abc", "count": 1})
    assert response.status_code == 200


async def test_metrics_are_exposed(client: httpx.AsyncClient) -> None:
    await client.get("/health")
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert 'http_requests_total{method="GET",route="/health",status="200"}' in response.text
    assert 'route="unmatched"' not in response.text


async def test_metrics_require_token_when_configured(tmp_path: Path) -> None:
    settings: Settings = build_settings(tmp_path, metrics_token=SecretStr("s3cret"))
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            missing = await http.get("/metrics")
            wrong = await http.get("/metrics", headers={"Authorization": "Bearer nope"})
            good = await http.get("/metrics", headers={"Authorization": "Bearer s3cret"})
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert good.status_code == 200


async def test_metrics_can_be_disabled(tmp_path: Path) -> None:
    application = create_app(build_settings(tmp_path, metrics_enabled=False))
    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            assert (await http.get("/metrics")).status_code == 404
