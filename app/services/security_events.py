"""Records security events in their own transaction so they persist even when a request fails."""

import uuid
from typing import cast

import structlog
from sqlalchemy.exc import SQLAlchemyError

from app.core.logging import mask_value
from app.core.metrics import Metrics
from app.db.session import Database
from app.models.enums import SecurityEventType, Severity
from app.models.security_event import SecurityEvent
from app.models.types import JSONObject, JSONValue
from app.repositories.security_event import SecurityEventRepository

logger = structlog.get_logger(__name__)
MAX_DETAIL_STRING = 500


def sanitize_details(details: JSONObject) -> JSONObject:
    """Mask sensitive keys and bound string sizes before details are persisted."""
    masked = cast(JSONObject, mask_value(details))
    return {key: _truncate(value) for key, value in masked.items()}


def _truncate(value: JSONValue) -> JSONValue:
    if isinstance(value, str) and len(value) > MAX_DETAIL_STRING:
        return value[:MAX_DETAIL_STRING] + "..."
    return value


class SecurityEventRecorder:
    def __init__(self, database: Database, metrics: Metrics) -> None:
        self._database = database
        self._metrics = metrics

    async def record(
        self,
        event_type: SecurityEventType,
        severity: Severity,
        *,
        request_id: str | None = None,
        correlation_id: str | None = None,
        llm_request_id: uuid.UUID | None = None,
        project_id: uuid.UUID | None = None,
        service_identity_id: uuid.UUID | None = None,
        caller_sub: str | None = None,
        source_ip: str | None = None,
        details: JSONObject | None = None,
    ) -> None:
        """Persist an event. Raises if the database is unavailable."""
        self._metrics.security_events.labels(event_type.value).inc()
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            request_id=request_id,
            correlation_id=correlation_id,
            llm_request_id=llm_request_id,
            project_id=project_id,
            service_identity_id=service_identity_id,
            caller_sub=caller_sub,
            source_ip=source_ip,
            details=sanitize_details(details or {}),
        )
        async with self._database.write_session() as session:
            await SecurityEventRepository(session).add(event)

    async def try_record(
        self,
        event_type: SecurityEventType,
        severity: Severity,
        *,
        request_id: str | None = None,
        correlation_id: str | None = None,
        llm_request_id: uuid.UUID | None = None,
        project_id: uuid.UUID | None = None,
        service_identity_id: uuid.UUID | None = None,
        caller_sub: str | None = None,
        source_ip: str | None = None,
        details: JSONObject | None = None,
    ) -> None:
        """Best-effort variant for denial paths: the request is already being refused."""
        try:
            await self.record(
                event_type,
                severity,
                request_id=request_id,
                correlation_id=correlation_id,
                llm_request_id=llm_request_id,
                project_id=project_id,
                service_identity_id=service_identity_id,
                caller_sub=caller_sub,
                source_ip=source_ip,
                details=details,
            )
        except SQLAlchemyError:
            logger.error("security_event_not_recorded", event_type=event_type.value)
