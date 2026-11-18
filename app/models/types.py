"""Column helpers shared by models."""

from enum import Enum

from sqlalchemy import Enum as SAEnum

type JSONValue = str | int | float | bool | list[JSONValue] | dict[str, JSONValue] | None
type JSONObject = dict[str, JSONValue]


def enum_column[E: Enum](enum_cls: type[E], name: str) -> SAEnum:
    """A portable enum stored as VARCHAR with a CHECK constraint on the enum values."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        length=32,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda members: [member.value for member in members],
    )
