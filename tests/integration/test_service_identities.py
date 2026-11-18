import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from app.db.session import Database
from app.models import AuditLog
from tests.conftest import bearer
from tests.tokens import KeyPair

IDENTITIES = "/api/v1/service-identities"


async def make_project(client: httpx.AsyncClient, admin: dict[str, str], key: str = "COE_1") -> str:
    response = await client.post(
        "/api/v1/projects", json={"projectKey": key, "name": key, "team": "COE"}, headers=admin
    )
    project_id: str = response.json()["id"]
    return project_id


async def make_identity(
    client: httpx.AsyncClient, admin: dict[str, str], project_id: str, **overrides: Any
) -> dict[str, Any]:
    payload = {
        "projectId": project_id,
        "clientId": "app-1",
        "displayName": "Billing App",
        **overrides,
    }
    response = await client.post(IDENTITIES, json=payload, headers=admin)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def test_new_identity_is_pending_with_default_role(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    project_id = await make_project(client, admin)
    created = await make_identity(client, admin, project_id)
    assert created["status"] == "pending"
    assert created["roles"] == ["service"]
    assert created["projectKey"] == "COE_1"
    assert created["approvedBy"] is None
    assert (await client.get(f"{IDENTITIES}/{created['id']}", headers=admin)).json() == created


async def test_unknown_project_is_404(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    response = await client.post(
        IDENTITIES,
        json={"projectId": str(uuid.uuid4()), "clientId": "x", "displayName": "X"},
        headers=admin,
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Project not found."


async def test_deleted_project_is_404(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    project_id = await make_project(client, admin)
    await client.delete(f"/api/v1/projects/{project_id}", headers=admin)
    response = await client.post(
        IDENTITIES,
        json={"projectId": project_id, "clientId": "x", "displayName": "X"},
        headers=admin,
    )
    assert response.status_code == 404


async def test_duplicate_client_id_is_409(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    project_id = await make_project(client, admin)
    other_project = await make_project(client, admin, "COE_2")
    await make_identity(client, admin, project_id)
    duplicate = await client.post(
        IDENTITIES,
        json={"projectId": other_project, "clientId": "app-1", "displayName": "Dup"},
        headers=admin,
    )
    assert duplicate.status_code == 409


@pytest.mark.parametrize(
    "overrides",
    [
        {"clientId": ""},
        {"clientId": "has space"},
        {"displayName": ""},
        {"roles": []},
        {"roles": ["governance_admin"]},
        {"roles": ["service", "audit_reviewer"]},
        {"roles": ["superuser"]},
        {"projectId": "nope"},
        {"status": "approved"},
    ],
)
async def test_invalid_identity_payloads_are_400(
    client: httpx.AsyncClient, admin: dict[str, str], overrides: dict[str, Any]
) -> None:
    project_id = await make_project(client, admin)
    payload = {"projectId": project_id, "clientId": "app-1", "displayName": "App", **overrides}
    assert (await client.post(IDENTITIES, json=payload, headers=admin)).status_code == 400


async def test_approve_then_revoke_lifecycle(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    created = await make_identity(client, admin, await make_project(client, admin))
    approved = await client.post(f"{IDENTITIES}/{created['id']}/approve", headers=admin)
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["approvedBy"] == "sub-admin-1"
    assert approved.json()["approvedAt"]

    again = await client.post(f"{IDENTITIES}/{created['id']}/approve", headers=admin)
    assert again.status_code == 409

    revoked = await client.post(
        f"{IDENTITIES}/{created['id']}/revoke", json={"reason": "contract ended"}, headers=admin
    )
    assert revoked.status_code == 200
    body = revoked.json()
    assert (body["status"], body["revokedBy"], body["revocationReason"]) == (
        "revoked",
        "sub-admin-1",
        "contract ended",
    )
    assert (
        await client.post(f"{IDENTITIES}/{created['id']}/revoke", headers=admin)
    ).status_code == 409
    assert (
        await client.post(f"{IDENTITIES}/{created['id']}/approve", headers=admin)
    ).status_code == 409


async def test_pending_identity_can_be_revoked_without_body(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    created = await make_identity(client, admin, await make_project(client, admin))
    revoked = await client.post(f"{IDENTITIES}/{created['id']}/revoke", headers=admin)
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revocationReason"] is None


async def test_transition_on_unknown_identity_is_404(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    unknown = uuid.uuid4()
    assert (await client.post(f"{IDENTITIES}/{unknown}/approve", headers=admin)).status_code == 404
    assert (await client.post(f"{IDENTITIES}/{unknown}/revoke", headers=admin)).status_code == 404


async def test_revocation_takes_effect_on_the_next_request(
    client: httpx.AsyncClient, admin: dict[str, str], keys: KeyPair
) -> None:
    created = await make_identity(client, admin, await make_project(client, admin))
    await client.post(f"{IDENTITIES}/{created['id']}/approve", headers=admin)
    caller = bearer(keys.mint(client_id="app-1"))
    before = (await client.get("/api/v1/me", headers=caller)).json()
    assert before["identity"]["status"] == "approved"
    await client.post(f"{IDENTITIES}/{created['id']}/revoke", headers=admin)
    after = (await client.get("/api/v1/me", headers=caller)).json()
    assert after["identity"]["status"] == "revoked"


async def test_patch_identity(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    project_id = await make_project(client, admin)
    created = await make_identity(client, admin, project_id)
    updated = await client.patch(
        f"{IDENTITIES}/{created['id']}", json={"displayName": "Renamed"}, headers=admin
    )
    assert updated.json()["displayName"] == "Renamed"
    assert updated.json()["clientId"] == "app-1"
    for forbidden in ({"clientId": "x"}, {"projectId": project_id}, {"status": "approved"}, {}):
        response = await client.patch(
            f"{IDENTITIES}/{created['id']}", json=forbidden, headers=admin
        )
        assert response.status_code == 400
    bad_roles = await client.patch(
        f"{IDENTITIES}/{created['id']}", json={"roles": ["audit_reviewer"]}, headers=admin
    )
    assert bad_roles.status_code == 400
    assert (
        await client.patch(f"{IDENTITIES}/{uuid.uuid4()}", json={"displayName": "x"}, headers=admin)
    ).status_code == 404


async def test_delete_identity_frees_client_id(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    project_id = await make_project(client, admin)
    created = await make_identity(client, admin, project_id)
    assert (await client.delete(f"{IDENTITIES}/{created['id']}", headers=admin)).status_code == 204
    assert (await client.get(f"{IDENTITIES}/{created['id']}", headers=admin)).status_code == 404
    again = await make_identity(client, admin, project_id)
    assert again["id"] != created["id"]
    assert (await client.delete(f"{IDENTITIES}/{uuid.uuid4()}", headers=admin)).status_code == 404


async def test_list_filters(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    first_project = await make_project(client, admin)
    second_project = await make_project(client, admin, "COE_2")
    one = await make_identity(client, admin, first_project, clientId="alpha", displayName="Alpha")
    await make_identity(client, admin, second_project, clientId="beta", displayName="Beta")
    await client.post(f"{IDENTITIES}/{one['id']}/approve", headers=admin)

    by_project = (await client.get(f"{IDENTITIES}?projectId={first_project}", headers=admin)).json()
    assert [i["clientId"] for i in by_project["items"]] == ["alpha"]
    by_status = (await client.get(f"{IDENTITIES}?status=pending", headers=admin)).json()
    assert [i["clientId"] for i in by_status["items"]] == ["beta"]
    by_search = (await client.get(f"{IDENTITIES}?q=ALP", headers=admin)).json()
    assert [i["clientId"] for i in by_search["items"]] == ["alpha"]
    ordered = (await client.get(f"{IDENTITIES}?sort=clientId&order=desc", headers=admin)).json()
    assert [i["clientId"] for i in ordered["items"]] == ["beta", "alpha"]


async def test_identity_endpoints_require_admin(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    auditor: dict[str, str],
    outsider: dict[str, str],
) -> None:
    created = await make_identity(client, admin, await make_project(client, admin))
    item = f"{IDENTITIES}/{created['id']}"
    for method, path in [
        ("GET", IDENTITIES),
        ("GET", item),
        ("POST", f"{item}/approve"),
        ("POST", f"{item}/revoke"),
        ("DELETE", item),
    ]:
        assert (await client.request(method, path)).status_code == 401
        for headers in (auditor, outsider):
            assert (await client.request(method, path, headers=headers)).status_code == 403
    assert (await client.get(item, headers=admin)).json()["status"] == "pending"


async def test_identity_lifecycle_is_audited(
    client: httpx.AsyncClient, admin: dict[str, str], database: Database
) -> None:
    created = await make_identity(client, admin, await make_project(client, admin))
    await client.post(f"{IDENTITIES}/{created['id']}/approve", headers=admin)
    await client.post(
        f"{IDENTITIES}/{created['id']}/revoke", json={"reason": "audit finding"}, headers=admin
    )
    async with database.read_sessions() as session:
        rows = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
    assert [r.action for r in rows][1:] == [
        "service_identity.create",
        "service_identity.approve",
        "service_identity.revoke",
    ]
    assert rows[-1].event_metadata["reason"] == "audit finding"
    assert rows[-1].event_metadata["clientId"] == "app-1"
