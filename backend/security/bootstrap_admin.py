import os
from datetime import datetime, timezone

from backend.core.database import SessionLocal
from backend.core.models import DEFAULT_TENANT_ID, User
from backend.security.auth import hash_password
from backend.security.request_context import sql_service_context
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


def ensure_bootstrap_admin() -> None:
    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "").strip()
    full_name = str(os.getenv("BOOTSTRAP_ADMIN_FULL_NAME", "") or "").strip() or None
    if not email or not password:
        return

    with sql_service_context("bootstrap_service", role="admin"):
        db = SessionLocal()
        try:
            existing = db.query(User).filter(User.email == email).first()
            if existing is not None:
                if not str(existing.tenant_id or "").strip():
                    existing.tenant_id = DEFAULT_TENANT_ID
                    db.add(existing)
                    db.commit()
                    logger.info(f"Bootstrap admin {email} updated with default tenant.")
                logger.info(f"Bootstrap admin exists for {email}; leaving unchanged.")
                return

            user = User(
                email=email,
                tenant_id=DEFAULT_TENANT_ID,
                full_name=full_name,
                password_hash=hash_password(password),
                role="admin",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            db.add(user)
            db.commit()
            logger.info(f"Bootstrapped admin user created for {email}.")
        except Exception:
            logger.exception("Failed to bootstrap admin user")
        finally:
            db.close()
