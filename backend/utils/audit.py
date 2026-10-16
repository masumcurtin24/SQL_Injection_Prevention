import json
import uuid
from typing import Any, Dict, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from backend.core.models import DEFAULT_TENANT_ID, AuditLog, User
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


def _safe_json(value: Optional[Dict[str, Any]]) -> Optional[str]:
    if value is None:
        return None
    try:
        return json.dumps(value, default=str, ensure_ascii=True, sort_keys=True)
    except Exception:
        try:
            return json.dumps({"unserializable_details": str(value)}, ensure_ascii=True)
        except Exception:
            return None


def write_audit(
    db: Session,
    request: Optional[Request],
    actor: Optional[User],
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    tenant_id: Optional[str] = None,
) -> Optional[AuditLog]:
    ip = None
    user_agent = None
    if request is not None:
        try:
            ip = request.client.host if request.client else None
        except Exception:
            ip = None
        try:
            user_agent = request.headers.get("user-agent")
        except Exception:
            user_agent = None

    effective_tenant_id = str(tenant_id or "").strip()
    if not effective_tenant_id and actor is not None:
        effective_tenant_id = str(getattr(actor, "tenant_id", "") or "").strip()
    if not effective_tenant_id and request is not None:
        try:
            effective_tenant_id = str(request.headers.get("X-Tenant-ID") or "").strip()
        except Exception:
            effective_tenant_id = ""
    if not effective_tenant_id:
        effective_tenant_id = DEFAULT_TENANT_ID

    entry = AuditLog(
        id=str(uuid.uuid4()),
        tenant_id=effective_tenant_id,
        actor_user_id=getattr(actor, "id", None) if actor is not None else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=ip,
        user_agent=user_agent,
        success=bool(success),
        details_json=_safe_json(details),
    )

    try:
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry
    except Exception:
        db.rollback()
        logger.exception("Failed to persist audit log for action '%s'", action)
        return None
