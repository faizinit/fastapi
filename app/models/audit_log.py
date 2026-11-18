from datetime import datetime
from typing import cast

from sqlalchemy import JSON, Index, Integer, String, Table
from sqlalchemy.orm import Mapped, mapped_column

from app.db.append_only import install_append_only_triggers
from app.db.base import Base, UTCDateTime, UUIDPrimaryKeyMixin, utcnow
from app.models.types import JSONObject

GENESIS_HASH = "0" * 64


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """A tamper-evident audit record. Rows are hash-chained and cannot be updated or deleted."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("uq_audit_logs_seq", "seq", unique=True),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_actor_occurred_at", "actor_sub", "occurred_at"),
        Index("ix_audit_logs_occurred_at", "occurred_at"),
    )

    seq: Mapped[int] = mapped_column(Integer)
    actor_sub: Mapped[str] = mapped_column(String(255))
    actor_role: Mapped[str] = mapped_column(String(50))
    action: Mapped[str] = mapped_column(String(100))
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(128), default=None)
    request_id: Mapped[str | None] = mapped_column(String(128), default=None)
    correlation_id: Mapped[str | None] = mapped_column(String(128), default=None)
    outcome: Mapped[str] = mapped_column(String(50))
    event_metadata: Mapped[JSONObject] = mapped_column("metadata", JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


install_append_only_triggers(cast(Table, AuditLog.__table__))

__all__ = ["GENESIS_HASH", "AuditLog"]
