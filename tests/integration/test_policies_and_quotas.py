import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from app.db.session import Database
from app.models import AuditLog

POLICIES = "/api/v1/policies"
QUOTAS = "/api/v1/quotas"

INJECTION = {"rules": [{"id": "no-secret", "pattern": "secret\\s+word", "description": "x"}]}
REQUEST_RULE = {"minInputLength": 5, "maxInputLength": 500, "allowedParameters": ["temperature"]}
RESPONSE_SCHEMA = {
    "schema": {"type": "object", "required": ["echo"], "properties": {"echo": {"type": "string"}}}
}
CONTENT = {
    "denyPatterns": [{"id": "ssn", "pattern": "\\d{3}-\\d{2}-\\d{4}"}],
    "maxOutputChars": 5000,
}

KINDS = [
    ("prompt_injection", INJECTION),
    ("request_rule", REQUEST_RULE),
    ("response_schema", RESPONSE_SCHEMA),
    ("content_security", CONTENT),
]


def policy(
    kind: str = "prompt_injection", definition: Any = INJECTION, **extra: Any
) -> dict[str, Any]:
    return {
        "name": f"policy-{uuid.uuid4().hex[:6]}",
        "kind": kind,
        "definition": definition,
        **extra,
    }


@pytest.mark.parametrize(("kind", "definition"), KINDS)
async def test_create_each_policy_kind(
    client: httpx.AsyncClient, admin: dict[str, str], kind: str, definition: dict[str, Any]
) -> None:
    response = await client.post(POLICIES, json=policy(kind, definition), headers=admin)
    body = response.json()
    assert response.status_code == 201, response.text
    assert body["kind"] == kind
    assert body["version"] == 1
    assert body["enabled"] is True
    assert body["scopeTaskId"] is None
    assert body["definition"].keys() == definition.keys()


@pytest.mark.parametrize(
    ("kind", "definition"),
    [
        ("prompt_injection", {}),
        ("prompt_injection", {"rules": []}),
        ("prompt_injection", {"rules": [{"id": "a", "pattern": "("}]}),
        ("prompt_injection", {"rules": [{"id": "a", "pattern": "(a+)+$"}]}),
        ("prompt_injection", {"rules": [{"id": "bad id", "pattern": "x"}]}),
        ("prompt_injection", {"rules": [{"id": "a", "pattern": "x" * 501}]}),
        ("prompt_injection", {"rules": [{"id": "a", "pattern": "x"}], "extra": 1}),
        ("request_rule", {}),
        ("request_rule", {"minInputLength": 10, "maxInputLength": 5}),
        ("request_rule", {"allowedParameters": ["top_p"]}),
        ("response_schema", {}),
        ("response_schema", {"schema": {"type": "not-a-type"}}),
        ("content_security", {}),
        ("content_security", {"denyPatterns": [{"id": "a", "pattern": "["}]}),
    ],
)
async def test_invalid_definitions_are_400(
    client: httpx.AsyncClient, admin: dict[str, str], kind: str, definition: dict[str, Any]
) -> None:
    response = await client.post(POLICIES, json=policy(kind, definition), headers=admin)
    assert response.status_code == 400
    assert "definition" in response.text


async def test_invalid_policy_fields_are_400(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    for payload in (
        policy(kind="nonsense"),
        {**policy(), "name": ""},
        {k: v for k, v in policy().items() if k != "definition"},
        {**policy(), "version": 9},
    ):
        assert (await client.post(POLICIES, json=payload, headers=admin)).status_code == 400


async def test_duplicate_policy_name_is_409(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    payload = policy()
    assert (await client.post(POLICIES, json=payload, headers=admin)).status_code == 201
    assert (await client.post(POLICIES, json=payload, headers=admin)).status_code == 409


async def test_task_scoped_policy(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    task = (await client.post("/api/v1/tasks", json={"name": "summarize"}, headers=admin)).json()
    created = await client.post(POLICIES, json=policy(scopeTaskId=task["id"]), headers=admin)
    assert created.status_code == 201
    assert created.json()["scopeTaskId"] == task["id"]
    missing = await client.post(POLICIES, json=policy(scopeTaskId=str(uuid.uuid4())), headers=admin)
    assert missing.status_code == 404


async def test_changing_definition_bumps_version_and_revalidates(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    created = (await client.post(POLICIES, json=policy(), headers=admin)).json()
    item = f"{POLICIES}/{created['id']}"
    new_definition = {"rules": [{"id": "other", "pattern": "forbidden"}]}
    updated = await client.patch(item, json={"definition": new_definition}, headers=admin)
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert updated.json()["definition"]["rules"][0]["id"] == "other"
    renamed = await client.patch(item, json={"name": "renamed", "enabled": False}, headers=admin)
    assert renamed.json()["version"] == 2
    assert renamed.json()["enabled"] is False
    invalid = await client.patch(item, json={"definition": {"rules": []}}, headers=admin)
    assert invalid.status_code == 400
    assert (await client.get(item, headers=admin)).json()["version"] == 2
    assert (
        await client.patch(item, json={"kind": "request_rule"}, headers=admin)
    ).status_code == 400


async def test_policy_get_delete_and_not_found(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    created = (await client.post(POLICIES, json=policy(), headers=admin)).json()
    item = f"{POLICIES}/{created['id']}"
    assert (await client.get(item, headers=admin)).json() == created
    assert (await client.delete(item, headers=admin)).status_code == 204
    assert (await client.get(item, headers=admin)).status_code == 404
    assert (await client.delete(item, headers=admin)).status_code == 404
    assert (await client.patch(item, json={"enabled": False}, headers=admin)).status_code == 404


async def test_policy_list_filters(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    task = (await client.post("/api/v1/tasks", json={"name": "summarize"}, headers=admin)).json()
    await client.post(POLICIES, json=policy(name="inj-global"), headers=admin)
    await client.post(
        POLICIES,
        json=policy("request_rule", REQUEST_RULE, name="req-scoped", scopeTaskId=task["id"]),
        headers=admin,
    )
    await client.post(POLICIES, json=policy(name="inj-off", enabled=False), headers=admin)

    def names(body: dict[str, Any]) -> list[str]:
        return sorted(i["name"] for i in body["items"])

    assert names((await client.get(f"{POLICIES}?kind=request_rule", headers=admin)).json()) == [
        "req-scoped"
    ]
    assert names(
        (await client.get(f"{POLICIES}?scopeTaskId={task['id']}", headers=admin)).json()
    ) == ["req-scoped"]
    assert names((await client.get(f"{POLICIES}?enabled=false", headers=admin)).json()) == [
        "inj-off"
    ]
    assert names((await client.get(f"{POLICIES}?q=INJ-", headers=admin)).json()) == [
        "inj-global",
        "inj-off",
    ]
    ordered = (await client.get(f"{POLICIES}?sort=name&order=desc&limit=2", headers=admin)).json()
    assert [i["name"] for i in ordered["items"]] == ["req-scoped", "inj-off"]
    assert ordered["total"] == 3


async def test_policy_endpoints_require_admin(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str]
) -> None:
    created = (await client.post(POLICIES, json=policy(), headers=admin)).json()
    item = f"{POLICIES}/{created['id']}"
    for method, path in [("GET", POLICIES), ("GET", item), ("DELETE", item)]:
        assert (await client.request(method, path)).status_code == 401
        assert (await client.request(method, path, headers=auditor)).status_code == 403
    assert (await client.post(POLICIES, json=policy(), headers=auditor)).status_code == 403


QUOTA = {
    "scopeType": "project",
    "scopeRef": "COE_1",
    "kind": "rate",
    "limitValue": 5,
    "windowSeconds": 60,
}


async def test_create_quota(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    response = await client.post(QUOTAS, json=QUOTA, headers=admin)
    body = response.json()
    assert response.status_code == 201
    assert (body["scopeType"], body["scopeRef"], body["kind"]) == ("project", "COE_1", "rate")
    assert (body["limitValue"], body["windowSeconds"], body["enabled"]) == (5, 60, True)


@pytest.mark.parametrize(
    "overrides",
    [
        {"limitValue": 0},
        {"windowSeconds": 0},
        {"limitValue": 1_000_000_001},
        {"windowSeconds": 31_536_001},
        {"scopeType": "galaxy"},
        {"kind": "burst"},
        {"scopeRef": ""},
        {"scopeRef": " padded "},
        {"scopeRef": "lowercase_key"},
        {"scopeType": "task", "scopeRef": "Not A Task"},
    ],
)
async def test_invalid_quotas_are_400(
    client: httpx.AsyncClient, admin: dict[str, str], overrides: dict[str, Any]
) -> None:
    response = await client.post(QUOTAS, json={**QUOTA, **overrides}, headers=admin)
    assert response.status_code == 400


async def test_scope_refs_for_free_form_scopes(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    team = {**QUOTA, "scopeType": "team", "scopeRef": "Data Science"}
    caller = {**QUOTA, "scopeType": "caller", "scopeRef": "app-1"}
    task = {**QUOTA, "scopeType": "task", "scopeRef": "summarize"}
    for payload in (team, caller, task):
        assert (await client.post(QUOTAS, json=payload, headers=admin)).status_code == 201


async def test_quota_unique_per_scope_and_kind(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    assert (await client.post(QUOTAS, json=QUOTA, headers=admin)).status_code == 201
    assert (await client.post(QUOTAS, json=QUOTA, headers=admin)).status_code == 409
    other_kind = {**QUOTA, "kind": "quota", "windowSeconds": 86400}
    assert (await client.post(QUOTAS, json=other_kind, headers=admin)).status_code == 201


async def test_quota_update_delete_and_not_found(
    client: httpx.AsyncClient, admin: dict[str, str]
) -> None:
    created = (await client.post(QUOTAS, json=QUOTA, headers=admin)).json()
    item = f"{QUOTAS}/{created['id']}"
    updated = await client.patch(item, json={"limitValue": 9, "enabled": False}, headers=admin)
    assert (updated.json()["limitValue"], updated.json()["enabled"]) == (9, False)
    for bad in ({"scopeRef": "OTHER"}, {"limitValue": 0}, {"limitValue": None}, {}):
        assert (await client.patch(item, json=bad, headers=admin)).status_code == 400
    assert (await client.get(item, headers=admin)).json()["limitValue"] == 9
    assert (await client.delete(item, headers=admin)).status_code == 204
    assert (await client.get(item, headers=admin)).status_code == 404
    assert (await client.delete(item, headers=admin)).status_code == 404
    assert (await client.patch(item, json={"enabled": True}, headers=admin)).status_code == 404


async def test_quota_list_filters(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    await client.post(QUOTAS, json=QUOTA, headers=admin)
    await client.post(
        QUOTAS,
        json={**QUOTA, "scopeType": "caller", "scopeRef": "app-1", "enabled": False},
        headers=admin,
    )
    await client.post(QUOTAS, json={**QUOTA, "kind": "quota", "windowSeconds": 3600}, headers=admin)

    def refs(body: dict[str, Any]) -> list[tuple[str, str]]:
        return sorted((i["scopeType"], i["kind"]) for i in body["items"])

    assert refs((await client.get(f"{QUOTAS}?scopeType=caller", headers=admin)).json()) == [
        ("caller", "rate")
    ]
    assert refs((await client.get(f"{QUOTAS}?kind=quota", headers=admin)).json()) == [
        ("project", "quota")
    ]
    assert refs((await client.get(f"{QUOTAS}?enabled=false", headers=admin)).json()) == [
        ("caller", "rate")
    ]
    assert (await client.get(f"{QUOTAS}?scopeRef=COE_1", headers=admin)).json()["total"] == 2
    ordered = (await client.get(f"{QUOTAS}?sort=windowSeconds", headers=admin)).status_code
    assert ordered == 400
    by_limit = (await client.get(f"{QUOTAS}?sort=limitValue&order=desc", headers=admin)).json()
    assert by_limit["total"] == 3


async def test_quota_endpoints_require_admin(
    client: httpx.AsyncClient, admin: dict[str, str], outsider: dict[str, str]
) -> None:
    created = (await client.post(QUOTAS, json=QUOTA, headers=admin)).json()
    item = f"{QUOTAS}/{created['id']}"
    for method, path in [("GET", QUOTAS), ("GET", item), ("DELETE", item)]:
        assert (await client.request(method, path)).status_code == 401
        assert (await client.request(method, path, headers=outsider)).status_code == 403
    assert (await client.post(QUOTAS, json=QUOTA, headers=outsider)).status_code == 403


async def test_policy_and_quota_changes_are_audited(
    client: httpx.AsyncClient, admin: dict[str, str], database: Database
) -> None:
    created = (await client.post(POLICIES, json=policy(name="audited"), headers=admin)).json()
    await client.patch(
        f"{POLICIES}/{created['id']}",
        json={"definition": {"rules": [{"id": "a", "pattern": "b"}]}},
        headers=admin,
    )
    quota = (await client.post(QUOTAS, json=QUOTA, headers=admin)).json()
    await client.delete(f"{QUOTAS}/{quota['id']}", headers=admin)
    async with database.read_sessions() as session:
        rows = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
    assert [r.action for r in rows] == [
        "policy.create",
        "policy.update",
        "quota.create",
        "quota.delete",
    ]
    assert rows[0].event_metadata == {"name": "audited", "kind": "prompt_injection", "version": 1}
    assert rows[1].event_metadata["changed"] == ["definition", "version"]
    assert rows[2].event_metadata["scopeRef"] == "COE_1"
