"""Aggregates all v1 routes."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    audit_logs,
    llm,
    me,
    models,
    policies,
    projects,
    quotas,
    security_events,
    service_identities,
    tasks,
)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(me.router)
api_router.include_router(tasks.router)
api_router.include_router(models.router)
api_router.include_router(projects.router)
api_router.include_router(service_identities.router)
api_router.include_router(policies.router)
api_router.include_router(quotas.router)
api_router.include_router(security_events.router)
api_router.include_router(audit_logs.router)
api_router.include_router(llm.router)
