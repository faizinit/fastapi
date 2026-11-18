import uuid

from sqlalchemy import JSON, CheckConstraint, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Entity
from app.models.enums import PolicyKind
from app.models.types import JSONObject, enum_column


class Policy(Entity):
    """A security rule set: injection rules, request rules, response schema or content rules."""

    __tablename__ = "policies"
    __table_args__ = (
        Index("ix_policies_kind_scope_enabled", "kind", "scope_task_id", "enabled"),
        Index("uq_policies_name", "name", unique=True),
        CheckConstraint("version > 0", name="version_positive"),
    )

    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[PolicyKind] = mapped_column(enum_column(PolicyKind, "policy_kind"))
    scope_task_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="CASCADE"), default=None
    )
    definition: Mapped[JSONObject] = mapped_column(JSON)
    version: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(default=True)
