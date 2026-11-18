from sqlalchemy import Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import SoftDeletableEntity


class LLMModel(SoftDeletableEntity):
    """An approved LLM model that projects may be granted."""

    __tablename__ = "llm_models"
    __table_args__ = (
        Index(
            "uq_llm_models_name_active",
            "name",
            unique=True,
            sqlite_where=text("deleted_at IS NULL"),
        ),
    )

    name: Mapped[str] = mapped_column(String(100))
    provider: Mapped[str] = mapped_column(String(100))
    enabled: Mapped[bool] = mapped_column(default=True)
