import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeletableEntity, TimestampMixin, UTCDateTime, utcnow
from app.models.enums import ProjectStatus
from app.models.llm_model import LLMModel
from app.models.task import Task
from app.models.types import enum_column


class Project(SoftDeletableEntity):
    __tablename__ = "projects"
    __table_args__ = (
        Index(
            "uq_projects_project_key_active",
            "project_key",
            unique=True,
            sqlite_where=text("deleted_at IS NULL"),
        ),
        Index("ix_projects_team", "team"),
    )

    project_key: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(200))
    team: Mapped[str] = mapped_column(String(100))
    status: Mapped[ProjectStatus] = mapped_column(
        enum_column(ProjectStatus, "project_status"), default=ProjectStatus.ACTIVE
    )


class ProjectTask(TimestampMixin, Base):
    """Grants a project permission to use a task."""

    __tablename__ = "project_tasks"
    __table_args__ = (Index("ix_project_tasks_task_id", "task_id"),)

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    task_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="CASCADE"), primary_key=True
    )
    granted_by: Mapped[str] = mapped_column(String(255))
    granted_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    task: Mapped[Task] = relationship(lazy="joined")


class ProjectModel(TimestampMixin, Base):
    """Grants a project permission to use an LLM model."""

    __tablename__ = "project_models"
    __table_args__ = (Index("ix_project_models_model_id", "model_id"),)

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    model_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("llm_models.id", ondelete="CASCADE"), primary_key=True
    )
    granted_by: Mapped[str] = mapped_column(String(255))
    granted_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    model: Mapped[LLMModel] = relationship(lazy="joined")
