import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from app.db.session import Database
from app.models import AuditLog

PROJECTS = "/api/v1/projects"
PAYLOAD = {"projectKey": "COE_1", "name": "Center of Excellence", "team": "COE"}


async def make_project(
    client: httpx.AsyncClient, admin: dict[str, str], **overrides: Any
) -> dict[str, Any]:
    response = await client.post(PROJECTS, json={**PAYLOAD, **overrides}, headers=admin)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def test_create_and_read_project(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    created = await make_project(client, admin)
    assert created["projectKey"] == "COE_1"
    assert created["status"] == "active"
    fetched = await client.get(f"{PROJECTS}/{created['id']}", headers=admin)
    assert fetched.json() == created


@pytest.mark.parametrize(
    "overrides",
    [
        {"projectKey": "coe_1"},
        {"projectKey": "A"},
        {"projectKey": "1ABC"},
        {"projectKey": "HAS SPACE"},
        {"name": ""},
        {"team": "x" * 101},
        {"status": "archived"},
    ],
)
async def test_invalid_project_is_400(
    client: httpx.AsyncClient, admin: dict[str, str], overrides: dict[str, Any]
) -> None:
    response = await client.post(PROJECTS, json={**PAYLOAD, **overrides}, headers=admin)
    assert response.status_code == 400


async def test_duplicate_project_key_is_409_until_deleted(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    created = await make_project(client, admin)
    assert (await client.post(PROJECTS, json=PAYLOAD, headers=admin)).status_code == 409
    await client.delete(f"{PROJECTS}/{created['id']}", headers=admin)
    assert (await client.post(PROJECTS, json=PAYLOAD, headers=admin)).status_code == 201


async def test_patch_project_cannot_change_key(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    created = await make_project(client, admin)
    ok = await client.patch(
        f"{PROJECTS}/{created['id']}", json={"status": "suspended", "team": "NEW"}, headers=admin
    )
    assert ok.json()["status"] == "suspended"
    assert ok.json()["team"] == "NEW"
    assert ok.json()["projectKey"] == "COE_1"
    bad = await client.patch(
        f"{PROJECTS}/{created['id']}", json={"projectKey": "OTHER_1"}, headers=admin
    )
    assert bad.status_code == 400


async def test_list_filters_and_search(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    await make_project(client, admin)
    await make_project(client, admin, projectKey="DATA_1", name="Data Platform", team="DATA")
    suspended = await make_project(client, admin, projectKey="OPS_1", name="Ops", team="OPS")
    await client.patch(f"{PROJECTS}/{suspended['id']}", json={"status": "suspended"}, headers=admin)

    by_team = (await client.get(f"{PROJECTS}?team=DATA", headers=admin)).json()
    assert [p["projectKey"] for p in by_team["items"]] == ["DATA_1"]
    by_status = (await client.get(f"{PROJECTS}?status=suspended", headers=admin)).json()
    assert [p["projectKey"] for p in by_status["items"]] == ["OPS_1"]
    by_key = (await client.get(f"{PROJECTS}?q=data_", headers=admin)).json()
    assert by_key["total"] == 1
    by_name = (await client.get(f"{PROJECTS}?q=excellence", headers=admin)).json()
    assert [p["projectKey"] for p in by_name["items"]] == ["COE_1"]
    ordered = (await client.get(f"{PROJECTS}?sort=projectKey&order=desc", headers=admin)).json()
    assert [p["projectKey"] for p in ordered["items"]] == ["OPS_1", "DATA_1", "COE_1"]
    assert (await client.get(f"{PROJECTS}?status=nope", headers=admin)).status_code == 400


async def test_projects_require_admin(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str]
) -> None:
    created = await make_project(client, admin)
    assert (await client.get(PROJECTS)).status_code == 401
    assert (await client.get(PROJECTS, headers=auditor)).status_code == 403
    assert (await client.delete(f"{PROJECTS}/{created['id']}", headers=auditor)).status_code == 403


async def test_get_update_delete_unknown_project_is_404(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    missing = f"{PROJECTS}/{uuid.uuid4()}"
    assert (await client.get(missing, headers=admin)).status_code == 404
    assert (await client.patch(missing, json={"name": "x"}, headers=admin)).status_code == 404
    assert (await client.delete(missing, headers=admin)).status_code == 404


async def make_task(client: httpx.AsyncClient, admin: dict[str, str], name: str) -> dict[str, Any]:
    response = await client.post("/api/v1/tasks", json={"name": name}, headers=admin)
    body: dict[str, Any] = response.json()
    return body


async def make_model(client: httpx.AsyncClient, admin: dict[str, str], name: str) -> dict[str, Any]:
    response = await client.post(
        "/api/v1/models", json={"name": name, "provider": "local"}, headers=admin
    )
    body: dict[str, Any] = response.json()
    return body


@pytest.mark.parametrize(
    ("segment", "key", "name_field", "make"),
    [("tasks", "taskId", "taskName", make_task), ("models", "modelId", "modelName", make_model)],
)
class TestGrants:
    async def test_grant_list_and_revoke(
        self,
        client: httpx.AsyncClient,
        admin: dict[str, str],
        segment: str,
        key: str,
        name_field: str,
        make: Any,
    ) -> None:
        project = await make_project(client, admin)
        first = await make(client, admin, "alpha")
        second = await make(client, admin, "beta")
        base = f"{PROJECTS}/{project['id']}/{segment}"
        granted = await client.post(base, json={key: first["id"]}, headers=admin)
        assert granted.status_code == 201
        assert granted.json()[name_field] == "alpha"
        assert granted.json()["grantedBy"] == "sub-admin-1"
        assert granted.json()["projectId"] == project["id"]
        await client.post(base, json={key: second["id"]}, headers=admin)
        listing = (await client.get(base, headers=admin)).json()
        assert [i[name_field] for i in listing["items"]] == ["alpha", "beta"]
        assert listing["total"] == 2
        page = (await client.get(f"{base}?limit=1&offset=1", headers=admin)).json()
        assert [i[name_field] for i in page["items"]] == ["beta"]
        assert page["total"] == 2

        revoked = await client.delete(f"{base}/{first['id']}", headers=admin)
        assert revoked.status_code == 204
        remaining = (await client.get(base, headers=admin)).json()
        assert [i[name_field] for i in remaining["items"]] == ["beta"]

    async def test_duplicate_grant_is_409(
        self,
        client: httpx.AsyncClient,
        admin: dict[str, str],
        segment: str,
        key: str,
        name_field: str,
        make: Any,
    ) -> None:
        project = await make_project(client, admin)
        target = await make(client, admin, "alpha")
        base = f"{PROJECTS}/{project['id']}/{segment}"
        await client.post(base, json={key: target["id"]}, headers=admin)
        assert (await client.post(base, json={key: target["id"]}, headers=admin)).status_code == 409

    async def test_unknown_references_are_404(
        self,
        client: httpx.AsyncClient,
        admin: dict[str, str],
        segment: str,
        key: str,
        name_field: str,
        make: Any,
    ) -> None:
        project = await make_project(client, admin)
        target = await make(client, admin, "alpha")
        unknown_project = f"{PROJECTS}/{uuid.uuid4()}/{segment}"
        base = f"{PROJECTS}/{project['id']}/{segment}"
        assert (await client.get(unknown_project, headers=admin)).status_code == 404
        post = await client.post(unknown_project, json={key: target["id"]}, headers=admin)
        assert post.status_code == 404
        assert (
            await client.post(base, json={key: str(uuid.uuid4())}, headers=admin)
        ).status_code == 404
        assert (await client.delete(f"{base}/{target['id']}", headers=admin)).status_code == 404
        assert (
            await client.delete(f"{unknown_project}/{target['id']}", headers=admin)
        ).status_code == 404

    async def test_deleted_targets_cannot_be_granted_and_are_hidden(
        self,
        client: httpx.AsyncClient,
        admin: dict[str, str],
        segment: str,
        key: str,
        name_field: str,
        make: Any,
    ) -> None:
        project = await make_project(client, admin)
        target = await make(client, admin, "alpha")
        base = f"{PROJECTS}/{project['id']}/{segment}"
        await client.post(base, json={key: target["id"]}, headers=admin)
        await client.delete(f"/api/v1/{segment}/{target['id']}", headers=admin)
        assert (await client.get(base, headers=admin)).json()["total"] == 0
        regrant = await client.post(base, json={key: target["id"]}, headers=admin)
        assert regrant.status_code == 404

    async def test_grants_require_admin_and_valid_body(
        self,
        client: httpx.AsyncClient,
        admin: dict[str, str],
        auditor: dict[str, str],
        segment: str,
        key: str,
        name_field: str,
        make: Any,
    ) -> None:
        project = await make_project(client, admin)
        base = f"{PROJECTS}/{project['id']}/{segment}"
        assert (await client.get(base)).status_code == 401
        assert (
            await client.post(base, json={key: str(uuid.uuid4())}, headers=auditor)
        ).status_code == 403
        assert (await client.post(base, json={key: "not-a-uuid"}, headers=admin)).status_code == 400
        assert (await client.post(base, json={}, headers=admin)).status_code == 400


async def test_project_and_grant_changes_are_audited(
    client: httpx.AsyncClient, admin: dict[str, str], database: Database
) -> None:
    project = await make_project(client, admin)
    task = await make_task(client, admin, "alpha")
    model = await make_model(client, admin, "m1")
    await client.post(
        f"{PROJECTS}/{project['id']}/tasks", json={"taskId": task["id"]}, headers=admin
    )
    await client.delete(f"{PROJECTS}/{project['id']}/tasks/{task['id']}", headers=admin)
    await client.post(
        f"{PROJECTS}/{project['id']}/models", json={"modelId": model["id"]}, headers=admin
    )
    await client.delete(f"{PROJECTS}/{project['id']}/models/{model['id']}", headers=admin)
    async with database.read_sessions() as session:
        rows = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
    actions = [r.action for r in rows]
    assert actions == [
        "project.create",
        "task.create",
        "llm_model.create",
        "project_task.grant",
        "project_task.revoke",
        "project_model.grant",
        "project_model.revoke",
    ]
    assert rows[0].event_metadata == {"projectKey": "COE_1"}
    assert rows[3].event_metadata["taskName"] == "alpha"
