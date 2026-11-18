import uuid

from sqlalchemy import ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Entity
from app.models.enums import LLMRequestStatus
from app.models.types import enum_column


class LLMRequest(Entity):
    """Audit metadata for one processed LLM request. Prompt and response text are never stored."""

    __tablename__ = "llm_requests"
    __table_args__ = (
        Index("uq_llm_requests_project_request", "project_id", "request_id", unique=True),
        Index("ix_llm_requests_created_at", "created_at"),
        Index("ix_llm_requests_status", "status"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id"))
    service_identity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("service_identities.id")
    )
    request_id: Mapped[str] = mapped_column(String(128))
    correlation_id: Mapped[str] = mapped_column(String(128))
    task_name: Mapped[str] = mapped_column(String(100))
    task_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("tasks.id"), default=None)
    model_name: Mapped[str] = mapped_column(String(100))
    model_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("llm_models.id"), default=None
    )
    status: Mapped[LLMRequestStatus] = mapped_column(
        enum_column(LLMRequestStatus, "llm_request_status"), default=LLMRequestStatus.RECEIVED
    )
    request_bytes: Mapped[int] = mapped_column(Integer, default=0)
    response_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    request_sha256: Mapped[str] = mapped_column(String(64))
    response_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    error_code: Mapped[str | None] = mapped_column(String(100), default=None)
    latency_ms: Mapped[int | None] = mapped_column(Integer, default=None)
    provider_attempts: Mapped[int] = mapped_column(Integer, default=0)
