"""Seed a development database with a demo project, task, model and approved identity.

    python -m scripts.seed

The script is idempotent and records its changes in the audit trail. Run migrations first.
"""

import asyncio
import uuid
from dataclasses import dataclass
from typing import cast

from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.core.context import Actor, RequestMeta
from app.core.roles import Role
from app.db.base import utcnow
from app.db.session import Database
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
from app.models.enums import IdentityStatus, PolicyKind, QuotaKind, QuotaScope
from app.models.types import JSONValue
from app.repositories.llm_model import LLMModelRepository
from app.repositories.policy import PolicyRepository
from app.repositories.project import ProjectRepository
from app.repositories.project_grant import ProjectModelRepository, ProjectTaskRepository
from app.repositories.quota import QuotaRepository
from app.repositories.service_identity import ServiceIdentityRepository
from app.repositories.task import TaskRepository
from app.services.audit import AuditService

SEEDER = Actor(subject="seed-script", role=Role.GOVERNANCE_ADMIN.value)
META = RequestMeta(correlation_id="seed")

DEMO_PROJECT_KEY = "DEMO_1"
DEMO_CLIENT_ID = "demo-app"
DEMO_TASK = "summarize_document"
DEMO_MODEL = "local-echo"
DEMO_POLICY = "demo-response-content-security"


@dataclass
class SeedResult:
    created: list[str]

    def add(self, label: str) -> None:
        self.created.append(label)


async def seed(database: Database) -> SeedResult:
    """Create any missing demo records in a single transaction."""
    audit = AuditService(database)
    result = SeedResult(created=[])
    async with database.write_session() as session:
        task = await TaskRepository(session).get_by_name(DEMO_TASK)
        if task is None:
            task = await TaskRepository(session).add(
                Task(name=DEMO_TASK, description="Demo summarization task", max_payload_bytes=65536)
            )
            result.add(f"task {DEMO_TASK}")

        model = await LLMModelRepository(session).get_by_name(DEMO_MODEL)
        if model is None:
            model = await LLMModelRepository(session).add(
                LLMModel(name=DEMO_MODEL, provider="local")
            )
            result.add(f"model {DEMO_MODEL}")

        project = await ProjectRepository(session).find_one(Project.project_key == DEMO_PROJECT_KEY)
        if project is None:
            project = await ProjectRepository(session).add(
                Project(project_key=DEMO_PROJECT_KEY, name="Demo project", team="DEMO")
            )
            result.add(f"project {DEMO_PROJECT_KEY}")

        if not await ProjectTaskRepository(session).is_granted(project.id, task.id):
            await ProjectTaskRepository(session).add(
                ProjectTask(project_id=project.id, task_id=task.id, granted_by=SEEDER.subject)
            )
            result.add("task grant")
        if not await ProjectModelRepository(session).is_granted(project.id, model.id):
            await ProjectModelRepository(session).add(
                ProjectModel(project_id=project.id, model_id=model.id, granted_by=SEEDER.subject)
            )
            result.add("model grant")

        if await ServiceIdentityRepository(session).get_by_client_id(DEMO_CLIENT_ID) is None:
            await ServiceIdentityRepository(session).add(
                ServiceIdentity(
                    project_id=project.id,
                    client_id=DEMO_CLIENT_ID,
                    display_name="Demo application",
                    roles=[Role.SERVICE.value],
                    status=IdentityStatus.APPROVED,
                    approved_by=SEEDER.subject,
                    approved_at=utcnow(),
                )
            )
            result.add(f"service identity {DEMO_CLIENT_ID}")

        if not await PolicyRepository(session).exists(Policy.name == DEMO_POLICY):
            await PolicyRepository(session).add(
                Policy(
                    name=DEMO_POLICY,
                    kind=PolicyKind.CONTENT_SECURITY,
                    definition={
                        "denyPatterns": [{"id": "us-ssn", "pattern": r"\b\d{3}-\d{2}-\d{4}\b"}],
                        "maxOutputChars": 100_000,
                    },
                )
            )
            result.add(f"policy {DEMO_POLICY}")

        quota_repository = QuotaRepository(session)
        if not await quota_repository.exists(
            Quota.scope_type == QuotaScope.PROJECT,
            Quota.scope_ref == DEMO_PROJECT_KEY,
            Quota.kind == QuotaKind.RATE,
        ):
            await quota_repository.add(
                Quota(
                    scope_type=QuotaScope.PROJECT,
                    scope_ref=DEMO_PROJECT_KEY,
                    kind=QuotaKind.RATE,
                    limit_value=600,
                    window_seconds=60,
                )
            )
            result.add("project rate limit")

        if result.created:
            await audit.append(
                session,
                actor=SEEDER,
                action="seed.apply",
                resource_type="seed",
                resource_id=str(uuid.uuid4()),
                meta=META,
                details={"created": cast(list[JSONValue], result.created)},
            )
    return result


async def run() -> int:
    database = Database(Settings())
    try:
        result = await seed(database)
    except OperationalError as exc:
        print(f"Seeding failed ({exc.orig}). Have you run `make migrate`?")
        return 1
    finally:
        await database.dispose()
    print(("Created: " + ", ".join(result.created)) if result.created else "Already seeded.")
    return 0


def main() -> int:
    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
