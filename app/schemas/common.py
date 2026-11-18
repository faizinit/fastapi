"""Schema building blocks shared by every resource."""

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from fastapi import Query
from pydantic import BaseModel, ConfigDict, model_validator
from pydantic.alias_generators import to_camel


class ApiModel(BaseModel):
    """Base schema: camelCase on the wire, rejects unknown request fields."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        from_attributes=True,
    )


class UpdateModel(ApiModel):
    """Base for PATCH bodies: omitted fields are untouched; explicit null is rejected."""

    @model_validator(mode="after")
    def _reject_explicit_null(self) -> Self:
        nulls = [name for name in self.model_fields_set if getattr(self, name) is None]
        if nulls:
            raise ValueError(f"fields cannot be null: {', '.join(sorted(nulls))}")
        return self

    @model_validator(mode="after")
    def _require_some_change(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one field must be provided")
        return self


class Timestamped(ApiModel):
    created_at: datetime
    updated_at: datetime


class Page[T](ApiModel):
    """Paginated list envelope."""

    items: list[T]
    total: int
    limit: int
    offset: int


class PageParams(BaseModel):
    limit: int
    offset: int


class SortOrder(StrEnum):
    ASC = "asc"
    DESC = "desc"


def page_params(
    limit: Annotated[int, Query(ge=1, le=200, description="Page size.")] = 50,
    offset: Annotated[int, Query(ge=0, description="Rows to skip.")] = 0,
) -> PageParams:
    return PageParams(limit=limit, offset=offset)


def build_page[T: ApiModel](
    schema: type[T], rows: Sequence[object], total: int, page: PageParams
) -> Page[T]:
    """Validate ORM rows into `schema` and wrap them in the pagination envelope."""
    return Page(
        items=[schema.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )
