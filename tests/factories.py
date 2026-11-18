"""Factories that persist valid entities, overridable per test."""

import itertools
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.roles import Role
from app.db.base import utcnow
from app.models import (
    LLMModel,
    Policy,
    Project,
    ProjectModel,
    ProjectTask,
    Quota,
    ServiceIdentity,
    Task,
)
from app.models.enums import (
    IdentityStatus,
    PolicyKind,
    QuotaKind,
    QuotaScope,
)

_counter = itertools.count(1)


def _n() -> int:
    return next(_counter)


async def _persist[T](session: AsyncSession, entity: T) -> T:
    session.add(entity)
    await session.flush()
    return entity


async def make_project(session: AsyncSession, **overrides: Any) -> Project:
    n = _n()
    values: dict[str, Any] = {"project_key": f"PROJ_{n}", "name": f"Project {n}", "team": "COE"}
    values.update(overrides)
    return await _persist(session, Project(**values))


async def make_task(session: AsyncSession, **overrides: Any) -> Task:
    values: dict[str, Any] = {"name": f"task_{_n()}", "description": "A task"}
    values.update(overrides)
    return await _persist(session, Task(**values))


async def make_model(session: AsyncSession, **overrides: Any) -> LLMModel:
    values: dict[str, Any] = {"name": f"model-{_n()}", "provider": "local"}
    values.update(overrides)
    return await _persist(session, LLMModel(**values))


async def make_identity(
    session: AsyncSession,
    project: Project | None = None,
    **overrides: Any,
) -> ServiceIdentity:
    project = project or await make_project(session)
    values: dict[str, Any] = {
        "project_id": project.id,
        "client_id": f"client-{uuid.uuid4().hex[:8]}",
        "display_name": "Test App",
        "roles": [Role.SERVICE.value],
        "status": IdentityStatus.APPROVED,
        "approved_by": "admin",
        "approved_at": utcnow(),
    }
    values.update(overrides)
    return await _persist(session, ServiceIdentity(**values))


async def grant_task(session: AsyncSession, project: Project, task: Task) -> ProjectTask:
    return await _persist(
        session, ProjectTask(project_id=project.id, task_id=task.id, granted_by="admin")
    )


async def grant_model(session: AsyncSession, project: Project, model: LLMModel) -> ProjectModel:
    return await _persist(
        session, ProjectModel(project_id=project.id, model_id=model.id, granted_by="admin")
    )


async def make_policy(session: AsyncSession, **overrides: Any) -> Policy:
    values: dict[str, Any] = {
        "name": f"policy-{_n()}",
        "kind": PolicyKind.PROMPT_INJECTION,
        "definition": {"rules": []},
    }
    values.update(overrides)
    return await _persist(session, Policy(**values))


async def make_quota(session: AsyncSession, **overrides: Any) -> Quota:
    values: dict[str, Any] = {
        "scope_type": QuotaScope.PROJECT,
        "scope_ref": f"PROJ_{_n()}",
        "kind": QuotaKind.RATE,
        "limit_value": 10,
        "window_seconds": 60,
    }
    values.update(overrides)
    return await _persist(session, Quota(**values))
