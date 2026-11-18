"""Task and model catalogs share behaviour; these tests run against both."""

import uuid
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from app.db.session import Database
from app.models import AuditLog


@dataclass(frozen=True)
class Catalog:
    path: str
    audit_prefix: str
    create: dict[str, Any]
    second: dict[str, Any]
    patch: dict[str, Any]
    invalid_create: dict[str, Any]
    filter_query: str


TASKS = Catalog(
    path="/api/v1/tasks",
    audit_prefix="task",
    create={"name": "summarize", "description": "Summaries", "maxPayloadBytes": 1000},
    second={"name": "classify"},
    patch={"description": "Changed", "maxPayloadBytes": 2000, "enabled": False},
    invalid_create={"name": "Bad Name!", "maxPayloadBytes": 0},
    filter_query="enabled=false",
)
MODELS = Catalog(
    path="/api/v1/models",
    audit_prefix="llm_model",
    create={"name": "gpt-4o", "provider": "openai"},
    second={"name": "claude-x", "provider": "anthropic"},
    patch={"provider": "azure", "enabled": False},
    invalid_create={"name": "-bad name", "provider": ""},
    filter_query="enabled=false",
)

catalogs = pytest.mark.parametrize("catalog", [TASKS, MODELS], ids=["tasks", "models"])


async def audit_actions(database: Database) -> list[str]:
    async with database.read_sessions() as session:
        rows = await session.execute(select(AuditLog.action).order_by(AuditLog.seq))
        return list(rows.scalars().all())


@catalogs
async def test_create_returns_201_and_resource(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    response = await client.post(catalog.path, json=catalog.create, headers=admin)
    body = response.json()
    assert response.status_code == 201
    assert uuid.UUID(body["id"])
    assert body["name"] == catalog.create["name"]
    assert body["enabled"] is True
    assert body["createdAt"].endswith("Z") or "+00:00" in body["createdAt"]
    assert "createdAt" in body
    assert body["updatedAt"]


@catalogs
async def test_duplicate_name_is_409(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    await client.post(catalog.path, json=catalog.create, headers=admin)
    response = await client.post(catalog.path, json=catalog.create, headers=admin)
    assert response.status_code == 409
    assert response.json()["type"] == "urn:central-security:problem:conflict"


@catalogs
async def test_invalid_create_is_400_with_field_errors(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    response = await client.post(catalog.path, json=catalog.invalid_create, headers=admin)
    body = response.json()
    assert response.status_code == 400
    assert body["type"] == "urn:central-security:problem:validation-failed"
    assert {e["field"] for e in body["errors"]} >= {"name"}


@catalogs
async def test_unknown_fields_are_rejected(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    response = await client.post(
        catalog.path, json={**catalog.create, "isAdmin": True}, headers=admin
    )
    assert response.status_code == 400


@catalogs
async def test_get_and_not_found(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    created = (await client.post(catalog.path, json=catalog.create, headers=admin)).json()
    found = await client.get(f"{catalog.path}/{created['id']}", headers=admin)
    assert found.status_code == 200
    assert found.json() == created
    missing = await client.get(f"{catalog.path}/{uuid.uuid4()}", headers=admin)
    assert missing.status_code == 404
    assert missing.json()["instance"] == f"{catalog.path}/{missing.url.path.rsplit('/', 1)[1]}"
    malformed = await client.get(f"{catalog.path}/not-a-uuid", headers=admin)
    assert malformed.status_code == 400


@catalogs
async def test_patch_updates_only_given_fields(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    created = (await client.post(catalog.path, json=catalog.create, headers=admin)).json()
    response = await client.patch(
        f"{catalog.path}/{created['id']}", json=catalog.patch, headers=admin
    )
    body = response.json()
    assert response.status_code == 200
    assert body["name"] == created["name"]
    assert body["enabled"] is False
    assert body["updatedAt"] >= created["updatedAt"]
    one_field = next(iter(catalog.patch))
    again = await client.patch(
        f"{catalog.path}/{created['id']}", json={"enabled": True}, headers=admin
    )
    assert again.json()[one_field] == body[one_field]
    assert again.json()["enabled"] is True


@catalogs
@pytest.mark.parametrize("payload", [{}, {"enabled": None}, {"name": "renamed"}])
async def test_invalid_patches_are_400(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog, payload: dict[str, Any]
) -> None:
    created = (await client.post(catalog.path, json=catalog.create, headers=admin)).json()
    response = await client.patch(f"{catalog.path}/{created['id']}", json=payload, headers=admin)
    assert response.status_code == 400


@catalogs
async def test_patch_unknown_id_is_404(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    response = await client.patch(
        f"{catalog.path}/{uuid.uuid4()}", json={"enabled": False}, headers=admin
    )
    assert response.status_code == 404


@catalogs
async def test_delete_is_soft_and_frees_the_name(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    created = (await client.post(catalog.path, json=catalog.create, headers=admin)).json()
    deleted = await client.delete(f"{catalog.path}/{created['id']}", headers=admin)
    assert deleted.status_code == 204
    assert deleted.content == b""
    assert (await client.get(f"{catalog.path}/{created['id']}", headers=admin)).status_code == 404
    assert (
        await client.delete(f"{catalog.path}/{created['id']}", headers=admin)
    ).status_code == 404
    recreated = await client.post(catalog.path, json=catalog.create, headers=admin)
    assert recreated.status_code == 201
    assert recreated.json()["id"] != created["id"]


@catalogs
async def test_list_envelope_pagination_sorting_filtering(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    for payload in (catalog.create, catalog.second):
        await client.post(catalog.path, json=payload, headers=admin)
    full = (await client.get(catalog.path, headers=admin)).json()
    assert set(full) == {"items", "total", "limit", "offset"}
    assert (full["total"], full["limit"], full["offset"]) == (2, 50, 0)

    first_page = (await client.get(f"{catalog.path}?limit=1&sort=name", headers=admin)).json()
    second_page = (
        await client.get(f"{catalog.path}?limit=1&offset=1&sort=name", headers=admin)
    ).json()
    names = sorted(p["name"] for p in (catalog.create, catalog.second))
    assert [first_page["items"][0]["name"], second_page["items"][0]["name"]] == names
    assert first_page["total"] == 2

    descending = (await client.get(f"{catalog.path}?sort=name&order=desc", headers=admin)).json()
    assert [i["name"] for i in descending["items"]] == names[::-1]

    created = full["items"][0]
    await client.patch(f"{catalog.path}/{created['id']}", json={"enabled": False}, headers=admin)
    filtered = (await client.get(f"{catalog.path}?{catalog.filter_query}", headers=admin)).json()
    assert [i["id"] for i in filtered["items"]] == [created["id"]]

    searched = (await client.get(f"{catalog.path}?q={names[0][:3]}", headers=admin)).json()
    assert [i["name"] for i in searched["items"]] == [names[0]]


@catalogs
async def test_search_escapes_like_wildcards(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog
) -> None:
    await client.post(catalog.path, json=catalog.create, headers=admin)
    for wildcard in ("%", "_"):
        body = (await client.get(f"{catalog.path}?q={wildcard}", headers=admin)).json()
        assert body["total"] == 0


@catalogs
@pytest.mark.parametrize(
    "query", ["sort=password", "order=sideways", "limit=0", "limit=201", "offset=-1"]
)
async def test_invalid_list_parameters_are_400(
    client: httpx.AsyncClient, admin: dict[str, str], catalog: Catalog, query: str
) -> None:
    response = await client.get(f"{catalog.path}?{query}", headers=admin)
    assert response.status_code == 400


@catalogs
async def test_authentication_and_roles_are_enforced(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    auditor: dict[str, str],
    outsider: dict[str, str],
    catalog: Catalog,
) -> None:
    created = (await client.post(catalog.path, json=catalog.create, headers=admin)).json()
    item = f"{catalog.path}/{created['id']}"
    calls = [
        ("GET", catalog.path, None),
        ("POST", catalog.path, catalog.second),
        ("GET", item, None),
        ("PATCH", item, {"enabled": False}),
        ("DELETE", item, None),
    ]
    for method, path, payload in calls:
        anonymous = await client.request(method, path, json=payload)
        assert anonymous.status_code == 401, (method, path)
        for headers in (auditor, outsider):
            denied = await client.request(method, path, json=payload, headers=headers)
            assert denied.status_code == 403, (method, path)
    assert (await client.get(item, headers=admin)).json()["enabled"] is True


@catalogs
async def test_mutations_are_audited_atomically(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    database: Database,
    catalog: Catalog,
) -> None:
    created = (await client.post(catalog.path, json=catalog.create, headers=admin)).json()
    await client.patch(f"{catalog.path}/{created['id']}", json={"enabled": False}, headers=admin)
    await client.delete(f"{catalog.path}/{created['id']}", headers=admin)
    await client.post(catalog.path, json=catalog.create, headers=admin)
    await client.post(catalog.path, json=catalog.create, headers=admin)
    prefix = catalog.audit_prefix
    assert await audit_actions(database) == [
        f"{prefix}.create",
        f"{prefix}.update",
        f"{prefix}.delete",
        f"{prefix}.create",
    ]
    async with database.read_sessions() as session:
        first = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().first()
    assert first is not None
    assert first.actor_sub == "sub-admin-1"
    assert first.actor_role == "governance_admin"
    assert first.resource_id == created["id"]
    assert first.correlation_id
