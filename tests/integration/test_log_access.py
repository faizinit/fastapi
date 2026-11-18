import uuid

import httpx
from sqlalchemy import select, text

from app.db.session import Database
from app.models import AuditLog

AUDIT = "/api/v1/audit-logs"
EVENTS = "/api/v1/security-events"


async def seed_audit_entries(client: httpx.AsyncClient, admin: dict[str, str]) -> None:
    await client.post("/api/v1/tasks", json={"name": "summarize"}, headers=admin)
    await client.post("/api/v1/models", json={"name": "m1", "provider": "local"}, headers=admin)
    await client.post(
        "/api/v1/projects",
        json={"projectKey": "COE_1", "name": "COE", "team": "COE"},
        headers=admin,
    )


async def test_auditor_lists_audit_entries_newest_first(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str]
) -> None:
    await seed_audit_entries(client, admin)
    response = await client.get(AUDIT, headers=auditor)
    body = response.json()
    assert response.status_code == 200
    assert body["total"] == 3
    assert [e["action"] for e in body["items"]] == [
        "project.create",
        "llm_model.create",
        "task.create",
    ]
    first = body["items"][0]
    assert first["actorSub"] == "sub-admin-1"
    assert first["actorRole"] == "governance_admin"
    assert first["metadata"] == {"projectKey": "COE_1"}
    assert len(first["rowHash"]) == 64
    assert first["seq"] == 3


async def test_audit_filters_and_pagination(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str]
) -> None:
    await seed_audit_entries(client, admin)
    by_action = (await client.get(f"{AUDIT}?action=task.create", headers=auditor)).json()
    assert [e["resourceType"] for e in by_action["items"]] == ["task"]
    by_actor = (await client.get(f"{AUDIT}?actor=sub-admin-1&limit=2", headers=auditor)).json()
    assert (by_actor["total"], len(by_actor["items"])) == (3, 2)
    by_type = (await client.get(f"{AUDIT}?resourceType=project", headers=auditor)).json()
    assert by_type["total"] == 1
    resource_id = by_type["items"][0]["resourceId"]
    by_id = (await client.get(f"{AUDIT}?resourceId={resource_id}", headers=auditor)).json()
    assert by_id["total"] == 1
    corr = by_type["items"][0]["correlationId"]
    by_corr = (await client.get(f"{AUDIT}?correlationId={corr}", headers=auditor)).json()
    assert by_corr["total"] == 1
    page2 = (
        await client.get(f"{AUDIT}?actor=sub-admin-1&limit=2&offset=2", headers=auditor)
    ).json()
    assert [e["seq"] for e in page2["items"]] == [1]
    none = (await client.get(f"{AUDIT}?actor=nobody", headers=auditor)).json()
    assert none["total"] == 0


async def test_audit_date_filters(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str]
) -> None:
    await seed_audit_entries(client, admin)
    future = (
        await client.get(f"{AUDIT}?occurredFrom=2999-01-01T00:00:00Z", headers=auditor)
    ).json()
    assert future["total"] == 0
    past = (await client.get(f"{AUDIT}?occurredTo=2000-01-01T00:00:00Z", headers=auditor)).json()
    assert past["total"] == 0
    window = await client.get(
        f"{AUDIT}?actor=sub-admin-1&occurredFrom=2000-01-01T00:00:00Z&occurredTo=2999-01-01T00:00:00Z",
        headers=auditor,
    )
    assert window.json()["total"] == 3
    naive = await client.get(f"{AUDIT}?occurredFrom=2026-01-01T00:00:00", headers=auditor)
    assert naive.status_code == 400
    garbage = await client.get(f"{AUDIT}?occurredFrom=yesterday", headers=auditor)
    assert garbage.status_code == 400


async def test_audit_log_reads_are_themselves_audited(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str], database: Database
) -> None:
    await seed_audit_entries(client, admin)
    await client.get(f"{AUDIT}?actor=sub-admin-1&resourceType=task", headers=auditor)
    async with database.read_sessions() as session:
        last = (
            await session.execute(select(AuditLog).order_by(AuditLog.seq.desc()).limit(1))
        ).scalar_one()
    assert last.action == "audit_logs.read"
    assert last.actor_sub == "sub-auditor-1"
    assert last.actor_role == "audit_reviewer"
    assert last.event_metadata == {"actor": "sub-admin-1", "resourceType": "task"}


async def test_get_audit_entry(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str]
) -> None:
    await seed_audit_entries(client, admin)
    listing = (await client.get(AUDIT, headers=auditor)).json()
    entry = listing["items"][0]
    fetched = await client.get(f"{AUDIT}/{entry['id']}", headers=auditor)
    assert fetched.status_code == 200
    assert fetched.json() == entry
    assert (await client.get(f"{AUDIT}/{uuid.uuid4()}", headers=auditor)).status_code == 404
    assert (await client.get(f"{AUDIT}/not-a-uuid", headers=auditor)).status_code == 400


async def test_verify_reports_intact_chain(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str]
) -> None:
    await seed_audit_entries(client, admin)
    response = await client.get(f"{AUDIT}/verify", headers=auditor)
    assert response.status_code == 200
    assert response.json() == {"valid": True, "checked": 3, "firstBrokenSeq": None}
    partial = (await client.get(f"{AUDIT}/verify?fromSeq=2&toSeq=3", headers=auditor)).json()
    assert partial["checked"] == 2


async def test_verify_detects_out_of_band_tampering(
    client: httpx.AsyncClient, admin: dict[str, str], auditor: dict[str, str], database: Database
) -> None:
    await seed_audit_entries(client, admin)
    async with database.write_session() as session:
        await session.execute(text("DROP TRIGGER trg_audit_logs_no_update"))
        await session.execute(text("UPDATE audit_logs SET actor_sub = 'mallory' WHERE seq = 2"))
    response = await client.get(f"{AUDIT}/verify", headers=auditor)
    assert response.json() == {"valid": False, "checked": 1, "firstBrokenSeq": 2}


async def test_verify_parameter_validation(
    client: httpx.AsyncClient, auditor: dict[str, str]
) -> None:
    for query in ("fromSeq=0", "toSeq=0", "fromSeq=abc"):
        assert (await client.get(f"{AUDIT}/verify?{query}", headers=auditor)).status_code == 400


async def test_audit_logs_are_restricted_to_auditors(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    auditor: dict[str, str],
    outsider: dict[str, str],
) -> None:
    await seed_audit_entries(client, admin)
    entry_id = (await client.get(AUDIT, headers=auditor)).json()["items"][0]["id"]
    for path in (AUDIT, f"{AUDIT}/{entry_id}", f"{AUDIT}/verify"):
        assert (await client.get(path)).status_code == 401
        assert (await client.get(path, headers=admin)).status_code == 403
        assert (await client.get(path, headers=outsider)).status_code == 403


async def generate_events(client: httpx.AsyncClient, outsider: dict[str, str]) -> None:
    await client.get("/api/v1/tasks", headers={"Authorization": "Bearer junk"}, params={})
    await client.get("/api/v1/tasks")
    await client.get("/api/v1/tasks", headers=outsider)


async def test_reviewers_and_admins_list_security_events(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    auditor: dict[str, str],
    outsider: dict[str, str],
) -> None:
    await generate_events(client, outsider)
    for headers in (auditor, admin):
        response = await client.get(EVENTS, headers=headers)
        body = response.json()
        assert response.status_code == 200
        assert body["total"] == 3
        types = sorted(e["eventType"] for e in body["items"])
        assert types == ["access_denied", "auth_failed", "auth_failed"]
        assert set(body["items"][0]) == {
            "id",
            "eventType",
            "severity",
            "requestId",
            "correlationId",
            "llmRequestId",
            "projectId",
            "serviceIdentityId",
            "callerSub",
            "sourceIp",
            "details",
            "occurredAt",
        }


async def test_security_event_filters(
    client: httpx.AsyncClient, auditor: dict[str, str], outsider: dict[str, str]
) -> None:
    await generate_events(client, outsider)

    def total(body: httpx.Response) -> int:
        assert body.status_code == 200
        result: int = body.json()["total"]
        return result

    assert total(await client.get(f"{EVENTS}?eventType=access_denied", headers=auditor)) == 1
    assert total(await client.get(f"{EVENTS}?severity=warning", headers=auditor)) == 3
    assert total(await client.get(f"{EVENTS}?severity=critical", headers=auditor)) == 0
    assert total(await client.get(f"{EVENTS}?callerSub=sub-outsider-1", headers=auditor)) == 1
    assert total(await client.get(f"{EVENTS}?projectId={uuid.uuid4()}", headers=auditor)) == 0
    assert total(await client.get(f"{EVENTS}?requestId=none", headers=auditor)) == 0
    listing = (await client.get(f"{EVENTS}?limit=1", headers=auditor)).json()
    corr = listing["items"][0]["correlationId"]
    assert total(await client.get(f"{EVENTS}?correlationId={corr}", headers=auditor)) == 1
    assert (
        total(await client.get(f"{EVENTS}?occurredFrom=2000-01-01T00:00:00Z", headers=auditor)) == 3
    )
    assert (
        total(await client.get(f"{EVENTS}?occurredTo=2000-01-01T00:00:00Z", headers=auditor)) == 0
    )
    assert (await client.get(f"{EVENTS}?eventType=bogus", headers=auditor)).status_code == 400


async def test_get_security_event(
    client: httpx.AsyncClient, auditor: dict[str, str], outsider: dict[str, str]
) -> None:
    await generate_events(client, outsider)
    event = (await client.get(EVENTS, headers=auditor)).json()["items"][0]
    fetched = await client.get(f"{EVENTS}/{event['id']}", headers=auditor)
    assert fetched.json() == event
    assert (await client.get(f"{EVENTS}/{uuid.uuid4()}", headers=auditor)).status_code == 404


async def test_security_events_are_restricted(
    client: httpx.AsyncClient, outsider: dict[str, str]
) -> None:
    assert (await client.get(EVENTS)).status_code == 401
    assert (await client.get(EVENTS, headers=outsider)).status_code == 403
    assert (await client.get(f"{EVENTS}/{uuid.uuid4()}", headers=outsider)).status_code == 403


async def test_security_event_reads_are_audited_with_the_readers_role(
    client: httpx.AsyncClient,
    admin: dict[str, str],
    auditor: dict[str, str],
    database: Database,
) -> None:
    await client.get(EVENTS, headers=auditor)
    await client.get(f"{EVENTS}?severity=info", headers=admin)
    async with database.read_sessions() as session:
        rows = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
    assert [(r.action, r.actor_role) for r in rows] == [
        ("security_events.read", "audit_reviewer"),
        ("security_events.read", "governance_admin"),
    ]
    assert rows[1].event_metadata == {"severity": "info"}
