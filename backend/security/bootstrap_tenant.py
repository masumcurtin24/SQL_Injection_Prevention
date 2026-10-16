from __future__ import annotations

from datetime import datetime, timezone

from backend.core.database import SessionLocal
from backend.core.models import Tenant, DEFAULT_TENANT_ID
from backend.security.request_context import sql_service_context
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)

DEFAULT_TENANT_SLUG = "primary"
DEFAULT_TENANT_NAME = "Primary Tenant"


def ensure_default_tenant() -> None:
    with sql_service_context("bootstrap_service", role="admin"):
        db = SessionLocal()
        try:
            existing = db.query(Tenant).filter(Tenant.id == DEFAULT_TENANT_ID).first()
            if existing is not None:
                return
            tenant = Tenant(
                id=DEFAULT_TENANT_ID,
                slug=DEFAULT_TENANT_SLUG,
                name=DEFAULT_TENANT_NAME,
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            db.add(tenant)
            db.commit()
            logger.info("Bootstrapped default tenant '%s' (%s).", DEFAULT_TENANT_NAME, DEFAULT_TENANT_ID)
        except Exception:
            db.rollback()
            logger.exception("Failed to bootstrap default tenant")
        finally:
            db.close()
