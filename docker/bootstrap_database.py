"""Prepare the application database before the container starts."""

from __future__ import annotations

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from backend.core.database import (
    create_db_tables,
    engine,
    get_missing_required_columns,
)


ALEMBIC_CONFIG = "/app/backend/alembic.ini"


def _assert_current_schema() -> None:
    missing = get_missing_required_columns()
    if missing:
        details = "; ".join(
            f"{table}: {', '.join(columns)}" for table, columns in sorted(missing.items())
        )
        raise RuntimeError(f"Database bootstrap produced an incomplete schema: {details}")


def main() -> None:
    config = Config(ALEMBIC_CONFIG)
    tables = set(inspect(engine).get_table_names())
    has_application_schema = "users" in tables
    has_alembic_version = "alembic_version" in tables

    if not has_application_schema:
        print("No application schema found; creating the current schema.")
        create_db_tables()
        _assert_current_schema()
        command.stamp(config, "head", purge=True)
        print("Fresh database created and stamped at the current migration head.")
        return

    if not has_alembic_version:
        _assert_current_schema()
        command.stamp(config, "head", purge=True)
        print("Existing current schema stamped at the migration head.")
        return

    command.upgrade(config, "head")
    print("Database migrations applied successfully.")


if __name__ == "__main__":
    main()
