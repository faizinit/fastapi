from typing import Any

import httpx
import pytest

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
PUBLIC_PATHS = {"/health", "/ready"}


@pytest.fixture
async def schema(client: httpx.AsyncClient) -> dict[str, Any]:
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    document: dict[str, Any] = response.json()
    return document


def operations(schema: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    return [
        (method, path, op)
        for path, item in schema["paths"].items()
        for method, op in item.items()
        if method in HTTP_METHODS
    ]


async def test_every_operation_is_fully_documented(schema: dict[str, Any]) -> None:
    for method, path, op in operations(schema):
        label = f"{method.upper()} {path}"
        assert op.get("summary"), label
        assert op.get("tags"), label
        success = [code for code in op["responses"] if code.startswith("2")]
        assert success, label
        assert "422" not in op["responses"], label


async def test_documented_status_codes_follow_the_spec(schema: dict[str, Any]) -> None:
    process = schema["paths"]["/api/v1/llm/process"]["post"]["responses"]
    assert {"200", "400", "401", "403", "409", "413", "429", "502", "503", "504"} <= set(process)
    assert "422" not in process
    create = schema["paths"]["/api/v1/tasks"]["post"]["responses"]
    assert "201" in create
    delete = schema["paths"]["/api/v1/tasks/{task_id}"]["delete"]["responses"]
    assert "204" in delete


async def test_error_responses_use_problem_details(schema: dict[str, Any]) -> None:
    forbidden = schema["paths"]["/api/v1/tasks"]["get"]["responses"]["403"]
    ref = forbidden["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("/ProblemDetail")
    problem = schema["components"]["schemas"]["ProblemDetail"]
    assert {"type", "title", "status", "detail", "instance", "requestId", "errors"} <= set(
        problem["properties"]
    )
    assert "HTTPValidationError" not in schema["components"]["schemas"]


async def test_list_endpoints_use_the_pagination_envelope(schema: dict[str, Any]) -> None:
    page = schema["components"]["schemas"]["Page_TaskRead_"]
    assert set(page["properties"]) == {"items", "total", "limit", "offset"}


async def test_authentication_is_declared_on_protected_operations(schema: dict[str, Any]) -> None:
    assert "BearerAuth" in schema["components"]["securitySchemes"]
    for method, path, op in operations(schema):
        if path in PUBLIC_PATHS:
            assert "security" not in op, path
        else:
            assert op.get("security"), f"{method.upper()} {path}"


async def test_wire_format_is_camel_case(schema: dict[str, Any]) -> None:
    properties = schema["components"]["schemas"]["LLMProcessRequest"]["properties"]
    assert {"requestId", "projectId"} <= set(properties)
    assert "request_id" not in properties


async def test_docs_and_redoc_are_served(client: httpx.AsyncClient) -> None:
    assert (await client.get("/docs")).status_code == 200
    assert (await client.get("/redoc")).status_code == 200
