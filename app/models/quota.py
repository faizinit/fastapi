from sqlalchemy import CheckConstraint, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Entity
from app.models.enums import QuotaKind, QuotaScope
from app.models.types import enum_column


class Quota(Entity):
    """A rate limit or quota attached to a caller, team, project or task."""

    __tablename__ = "quotas"
    __table_args__ = (
        Index("uq_quotas_scope_kind", "scope_type", "scope_ref", "kind", unique=True),
        CheckConstraint("limit_value > 0", name="limit_positive"),
        CheckConstraint("window_seconds > 0", name="window_positive"),
    )

    scope_type: Mapped[QuotaScope] = mapped_column(enum_column(QuotaScope, "quota_scope"))
    scope_ref: Mapped[str] = mapped_column(String(255))
    kind: Mapped[QuotaKind] = mapped_column(enum_column(QuotaKind, "quota_kind"))
    limit_value: Mapped[int] = mapped_column(Integer)
    window_seconds: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(default=True)


class RateCounter(Base):
    """A fixed-window hit counter backing rate limits and quotas."""

    __tablename__ = "rate_counters"
    __table_args__ = (Index("ix_rate_counters_expires_at", "expires_at"),)

    key: Mapped[str] = mapped_column(String(300), primary_key=True)
    window_start: Mapped[int] = mapped_column(Integer, primary_key=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[int] = mapped_column(Integer)
