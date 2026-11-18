"""SQLite triggers that make a table append-only (no UPDATE, no DELETE)."""

from typing import Any

from sqlalchemy import Table, event, text
from sqlalchemy.engine import Connection


def append_only_statements(table_name: str) -> tuple[str, str]:
    return (
        f"CREATE TRIGGER trg_{table_name}_no_update BEFORE UPDATE ON {table_name} "
        f"BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END",
        f"CREATE TRIGGER trg_{table_name}_no_delete BEFORE DELETE ON {table_name} "
        f"BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END",
    )


def install_append_only_triggers(table: Table) -> None:
    """Create the triggers whenever the table is created with `metadata.create_all`."""
    for statement in append_only_statements(table.name):
        event.listen(table, "after_create", _executor(statement))


def _executor(statement: str) -> Any:  # Any: SQLAlchemy event listeners are loosely typed.
    def run(_: Table, connection: Connection, **__: Any) -> None:
        connection.execute(text(statement))

    return run
