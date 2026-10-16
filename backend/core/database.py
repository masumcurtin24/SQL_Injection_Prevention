# backend/core/database.py
# NO LEADING SPACES OR TABS ON THIS LINE OR THE NEXT
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import declarative_base, sessionmaker
import os
import sys # Ensure sys is imported for path manipulation if used by logger in other modules
from dotenv import load_dotenv
import logging # For path setup logger

# --- Basic Logger Setup specifically for this file's path logic ---
_db_path_logger = logging.getLogger("DatabasePathSetup")
if not _db_path_logger.handlers:
    _db_path_logger.setLevel(logging.INFO)
    _db_handler = logging.StreamHandler(sys.stdout)
    _db_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    _db_handler.setFormatter(_db_formatter)
    _db_path_logger.addHandler(_db_handler)
# --- End Logger Setup ---


# Determine the base directory of the project (SQL_Injection_Prevention)
# This assumes database.py is in SQL_Injection_Prevention/backend/core/
PROJECT_ROOT = None
try:
    current_file_path = os.path.abspath(__file__)
    # Go up from core -> backend -> SQL_Injection_Prevention
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(current_file_path), "..", ".."))
    _db_path_logger.info(f"Database.py: Determined PROJECT_ROOT: {PROJECT_ROOT}")
except Exception as e:
    _db_path_logger.error(f"Database.py: Error determining PROJECT_ROOT: {e}")
    # Fallback if __file__ is not available or path logic fails
    PROJECT_ROOT = os.path.abspath(os.path.join(os.getcwd(), "..", "..")) # Assuming CWD is backend/core
    _db_path_logger.warning(f"Database.py: Using fallback PROJECT_ROOT based on CWD assumption: {PROJECT_ROOT}")


if PROJECT_ROOT and os.path.exists(os.path.join(PROJECT_ROOT, ".env")):
    dotenv_path = os.path.join(PROJECT_ROOT, ".env")
    load_dotenv(dotenv_path)
    _db_path_logger.info(f"Database.py: Loaded .env from {dotenv_path}")
else:
    _db_path_logger.warning(f"Database.py: .env file not found at project root ({PROJECT_ROOT}). DATABASE_URL might not be set.")


SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

if SQLALCHEMY_DATABASE_URL is None:
    db_filename = "sql_app.db"
    if PROJECT_ROOT:
        db_path = os.path.join(PROJECT_ROOT, db_filename) # Place DB in project root
    else:
        # If project root couldn't be determined, place it in backend/core/ (less ideal)
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_filename)
        _db_path_logger.warning(f"Database.py: PROJECT_ROOT not found, defaulting DB to service script dir.")

    SQLALCHEMY_DATABASE_URL = f"sqlite:///{db_path}"
    _db_path_logger.warning(f"Database.py: DATABASE_URL not found in .env file. Defaulting to SQLite at: {SQLALCHEMY_DATABASE_URL}")
else:
    if SQLALCHEMY_DATABASE_URL.startswith("sqlite:///./") and PROJECT_ROOT:
        relative_db_path = SQLALCHEMY_DATABASE_URL.split("sqlite:///./", 1)[1]
        db_path = os.path.join(PROJECT_ROOT, relative_db_path)
        SQLALCHEMY_DATABASE_URL = f"sqlite:///{db_path}"
        _db_path_logger.info(f"Database.py: Relative SQLite DATABASE_URL resolved to: {SQLALCHEMY_DATABASE_URL}")
    else:
        _db_path_logger.info(f"Database.py: Using DATABASE_URL from .env: {SQLALCHEMY_DATABASE_URL}")


engine_args = {}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine_args["connect_args"] = {"check_same_thread": False}

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, **engine_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# --- SQL Enforcement Hook: intercept outgoing statements ---
try:
    from backend.security.sql_enforcer import enforce

    @event.listens_for(engine, "before_cursor_execute")
    def _sql_enforcement(conn, cursor, statement, parameters, context, executemany):
        try:
            enforce(
                statement,
                parameters,
                execution_context=context,
                executemany=bool(executemany),
            )
        except PermissionError:
            # Re-raise to stop execution; SQLAlchemy will propagate
            raise
        except Exception as e:
            # Configurable fail-open vs fail-closed behavior on enforcer exceptions
            # Support both legacy and current env var names
            fail_open = os.getenv("SQL_ENFORCER_FAIL_OPEN", "").strip().lower() in {"1","true","yes","y"}
            if not fail_open:
                fail_open = os.getenv("SQL_ENFORCEMENT_FAIL_OPEN", "false").strip().lower() in {"1","true","yes","y"}
            msg = f"SQL enforcement error: {e}. Statement (truncated)='{str(statement)[:200]}'"
            if fail_open:
                _db_path_logger.error(msg)
                # proceed (fail-open) only when explicitly configured
                return
            # default: fail-closed to avoid silent bypass
            _db_path_logger.critical(msg)
            raise
except Exception as e:
    _db_path_logger.error(f"SQL enforcement hook not installed: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_db_tables():
    # Import all modules here that define models so that
    # they are registered with Base before create_all is called.
    # This import should be inside the function if models.py imports Base from here,
    # to avoid circular import issues at the module level.
    try:
        from backend.core import models  # noqa: F401

        # Schema creation executes DDL. The SQL enforcer is designed to block DDL by default
        # unless explicitly allowed for a migration context. For startup table creation, we
        # temporarily disable enforcement to avoid blocking internal schema initialization.
        enforcer_prev_mode = None
        enforcer_module = None
        try:
            import backend.security.sql_enforcer as enforcer_module  # type: ignore

            enforcer_prev_mode = getattr(enforcer_module, "ENFORCEMENT_MODE", None)
            enforcer_module.ENFORCEMENT_MODE = "off"  # type: ignore[attr-defined]
        except Exception:
            enforcer_module = None
            enforcer_prev_mode = None

        try:
            Base.metadata.create_all(bind=engine)
        finally:
            if enforcer_module is not None and enforcer_prev_mode is not None:
                try:
                    enforcer_module.ENFORCEMENT_MODE = enforcer_prev_mode  # type: ignore[attr-defined]
                except Exception:
                    pass

        _db_path_logger.info("Database.py: Database tables checked/created (if they didn't exist).")
    except Exception as e:
        _db_path_logger.error(f"Database.py: Could not create database tables: {e}", exc_info=True)


def get_missing_required_columns() -> dict[str, list[str]]:
    """
    Return required runtime columns that are missing from the current DB schema.
    This guards against model/schema drift when create_all() was used without
    applying Alembic migrations on an existing database.
    """
    required: dict[str, list[str]] = {
        "tenants": ["id", "slug", "name", "is_active", "created_at"],
        "users": ["full_name", "tenant_id"],
        "alerts": ["tenant_id"],
        "sql_analysis_logs": ["risk_level", "suggested_action", "category", "is_malicious", "tenant_id"],
        "spam_analysis_logs": ["is_spam", "spam_score", "classification_label", "category", "tenant_id"],
        "file_analysis_logs": ["overall_status", "recommended_action", "risk_score_value", "category", "tenant_id"],
        "audit_logs": ["tenant_id"],
        "security_cases": ["tenant_id"],
        "security_case_notes": ["tenant_id"],
        "alert_case_links": ["tenant_id"],
        "defender_feedback": ["tenant_id"],
        "defender_model_registry": ["tenant_id"],
        "defender_training_jobs": ["tenant_id"],
    }
    missing: dict[str, list[str]] = {}
    try:
        inspector = inspect(engine)
        for table_name, required_cols in required.items():
            try:
                existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
            except Exception:
                existing_cols = set()
            table_missing = [col for col in required_cols if col not in existing_cols]
            if table_missing:
                missing[table_name] = table_missing
    except Exception as e:
        _db_path_logger.error(f"Database.py: Failed inspecting DB schema: {e}", exc_info=True)
    return missing


def ensure_runtime_schema_compatibility() -> None:
    """
    Raises RuntimeError when required columns are missing.
    """
    missing = get_missing_required_columns()
    if not missing:
        return
    details = "; ".join(f"{table} missing {cols}" for table, cols in missing.items())
    raise RuntimeError(
        "Database schema is out of date for current runtime models. "
        f"{details}. Apply Alembic migrations (e.g., `cd backend && python -m alembic -c alembic.ini upgrade head`)."
    )

# Example of calling create_db_tables (e.g., in main.py on startup, or manually)
#     create_db_tables()
