from sqlalchemy import CheckConstraint, Index, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import SoftDeletableEntity


class Task(SoftDeletableEntity):
    """An allow-listed processing task that projects may be granted."""

    __tablename__ = "tasks"
    __table_args__ = (
        Index("uq_tasks_name_active", "name", unique=True, sqlite_where=text("deleted_at IS NULL")),
        CheckConstraint("max_payload_bytes > 0", name="max_payload_positive"),
    )

    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text, default="")
    max_payload_bytes: Mapped[int] = mapped_column(Integer, default=65536)
    enabled: Mapped[bool] = mapped_column(default=True)
