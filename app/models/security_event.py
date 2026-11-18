import uuid
from datetime import datetime
from typing import cast

from sqlalchemy import JSON, ForeignKey, Index, String, Table, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.append_only import install_append_only_triggers
from app.db.base import Base, UTCDateTime, UUIDPrimaryKeyMixin, utcnow
from app.models.enums import SecurityEventType, Severity
from app.models.types import JSONObject, enum_column


class SecurityEvent(UUIDPrimaryKeyMixin, Base):
    """An immutable record of a denied, invalid or abnormal request."""

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_occurred_at", "occurred_at"),
        Index("ix_security_events_type_occurred_at", "event_type", "occurred_at"),
        Index("ix_security_events_project_occurred_at", "project_id", "occurred_at"),
        Index("ix_security_events_request_id", "request_id"),
    )

    event_type: Mapped[SecurityEventType] = mapped_column(
        enum_column(SecurityEventType, "security_event_type")
    )
    severity: Mapped[Severity] = mapped_column(enum_column(Severity, "security_severity"))
    request_id: Mapped[str | None] = mapped_column(String(128), default=None)
    correlation_id: Mapped[str | None] = mapped_column(String(128), default=None)
    llm_request_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("llm_requests.id"), default=None
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("projects.id"), default=None
    )
    service_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("service_identities.id"), default=None
    )
    caller_sub: Mapped[str | None] = mapped_column(String(255), default=None)
    source_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    details: Mapped[JSONObject] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


install_append_only_triggers(cast(Table, SecurityEvent.__table__))
