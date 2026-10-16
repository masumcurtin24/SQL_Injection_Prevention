# backend/alembic/env.py
import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# --- Custom Setup to Locate Project Root and Load .env ---
# This section helps Alembic find your .env file and project modules.
# It assumes env.py is in SQL_Injection_Prevention/backend/alembic/
try:
    # Determine the project root directory (SQL_Injection_Prevention)
    # by going up two levels from the current file's directory (alembic/)
    PROJECT_ROOT_FOR_ALEMBIC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    
    # Add the project root to sys.path so that modules like 'backend.core.database' can be imported
    if PROJECT_ROOT_FOR_ALEMBIC not in sys.path:
        sys.path.insert(0, PROJECT_ROOT_FOR_ALEMBIC)
        print(f"INFO (Alembic env.py): Added project root to sys.path: {PROJECT_ROOT_FOR_ALEMBIC}")

    # Load .env file from the project root
    from dotenv import load_dotenv
    dotenv_path = os.path.join(PROJECT_ROOT_FOR_ALEMBIC, ".env")
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path)
        print(f"INFO (Alembic env.py): Loaded .env file from {dotenv_path}")
    else:
        print(f"WARNING (Alembic env.py): .env file not found at {dotenv_path}. DATABASE_URL might not be set.")

except ImportError:
    print("WARNING (Alembic env.py): python-dotenv not installed. Cannot load .env file. "
          "Ensure DATABASE_URL is set via other means or in alembic.ini.")
except Exception as e:
    print(f"ERROR (Alembic env.py): Could not configure paths or load .env: {e}")
# --- End Custom Setup ---

from backend.core.database_url import sanitize_database_url


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line needs to be located after loading the .env file if your logging config depends on it.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# --- Set sqlalchemy.url from environment variable ---
# This overrides the sqlalchemy.url from alembic.ini if DATABASE_URL is found in .env
DATABASE_URL_FROM_ENV = os.getenv("DATABASE_URL")
if DATABASE_URL_FROM_ENV:
    # If it's a relative SQLite path (e.g., "sqlite:///./sql_app.db"),
    # make it absolute relative to the determined PROJECT_ROOT.
    if DATABASE_URL_FROM_ENV.startswith("sqlite:///./") and PROJECT_ROOT_FOR_ALEMBIC:
        relative_db_path = DATABASE_URL_FROM_ENV.split("sqlite:///./", 1)[1]
        abs_db_path = os.path.join(PROJECT_ROOT_FOR_ALEMBIC, relative_db_path)
        resolved_db_url = f"sqlite:///{abs_db_path}"
        print(
            "INFO (Alembic env.py): Resolved relative SQLite DATABASE_URL to: "
            f"{sanitize_database_url(resolved_db_url)}"
        )
        config.set_main_option("sqlalchemy.url", resolved_db_url)
    elif DATABASE_URL_FROM_ENV.startswith("sqlite:///"): # Absolute SQLite path
        config.set_main_option("sqlalchemy.url", DATABASE_URL_FROM_ENV)
        print(
            "INFO (Alembic env.py): Using absolute SQLite DATABASE_URL from env: "
            f"{sanitize_database_url(DATABASE_URL_FROM_ENV)}"
        )
    else: # For other database types like PostgreSQL, use the URL as is
        config.set_main_option("sqlalchemy.url", DATABASE_URL_FROM_ENV)
        print(
            "INFO (Alembic env.py): Using DATABASE_URL from env: "
            f"{sanitize_database_url(DATABASE_URL_FROM_ENV)}"
        )
else:
    print("WARNING (Alembic env.py): DATABASE_URL not found in environment. "
          "Alembic will rely on sqlalchemy.url from alembic.ini (if set).")
# --- End sqlalchemy.url setup ---


# add your model's MetaData object here
# target_metadata = mymodel.Base.metadata
# --- Import your Base and models ---
try:
    from backend.core.database import Base as AppBase  # Import your Base from your application's database.py
    from backend.core import models  # noqa: F401 - register model metadata with AppBase
    target_metadata = AppBase.metadata
    print("INFO (Alembic env.py): Successfully imported Base and models for autogenerate support.")
except ImportError as e:
    print(f"ERROR (Alembic env.py): Could not import Base or models from backend.core. "
          f"Ensure sys.path is correct and modules exist. Error: {e}")
    target_metadata = None
# --- End Import Base and models ---


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # For SQLite, connect_args is needed for multi-threaded access if FastAPI uses threads.
    # This is generally only an issue with SQLite.
    connectable_args = {}
    db_url = config.get_main_option("sqlalchemy.url")
    if db_url and db_url.startswith("sqlite"):
        connectable_args["connect_args"] = {"check_same_thread": False}
        
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        **connectable_args # Pass connect_args if it's SQLite
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    from backend.security.request_context import reset_current_service, set_current_service

    token = set_current_service("alembic")
    try:
        run_migrations_offline()
    finally:
        reset_current_service(token)
else:
    from backend.security.request_context import reset_current_service, set_current_service

    token = set_current_service("alembic")
    try:
        run_migrations_online()
    finally:
        reset_current_service(token)
