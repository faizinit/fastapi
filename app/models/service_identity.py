import uuid
from datetime import datetime

from sqlalchemy import JSON, ForeignKey, Index, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import SoftDeletableEntity, UTCDateTime
from app.models.enums import IdentityStatus
from app.models.project import Project
from app.models.types import enum_column


class ServiceIdentity(SoftDeletableEntity):
    """A registered business application, bound to exactly one project."""

    __tablename__ = "service_identities"
    __table_args__ = (
        Index(
            "uq_service_identities_client_id_active",
            "client_id",
            unique=True,
            sqlite_where=text("deleted_at IS NULL"),
        ),
        Index("ix_service_identities_project_id_status", "project_id", "status"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id"))
    client_id: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(200))
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[IdentityStatus] = mapped_column(
        enum_column(IdentityStatus, "identity_status"), default=IdentityStatus.PENDING
    )
    approved_by: Mapped[str | None] = mapped_column(String(255), default=None)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(255), default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), default=None)
    revocation_reason: Mapped[str | None] = mapped_column(String(500), default=None)

    project: Mapped[Project] = relationship(lazy="joined")

    @property
    def project_key(self) -> str:
        return self.project.project_key
