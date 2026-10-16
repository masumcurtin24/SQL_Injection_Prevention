import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import AuditLog, User
from backend.server.deps.policy import require_policy
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.server.schemas.audit import AuditListResponse, AuditLogItem
from backend.utils.user_summary import build_user_summary_map

router = APIRouter()


@router.get("", response_model=AuditListResponse, summary="List audit events (admin only)")
def list_audit_events(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None),
    actor_user_id: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    _user: User = Depends(require_policy("dashboard.access.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> AuditListResponse:
    query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_ctx.tenant_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if actor_user_id:
        query = query.filter(AuditLog.actor_user_id == actor_user_id)
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)

    total = query.count()
    rows = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    actor_map = build_user_summary_map(
        db=db,
        user_ids=[str(row.actor_user_id or "").strip() for row in rows],
        include_unknown=False,
    )

    items = []
    for row in rows:
        details = None
        if row.details_json:
            try:
                details = json.loads(row.details_json)
            except Exception:
                details = {"raw": row.details_json}
        items.append(
            AuditLogItem(
                id=row.id,
                timestamp=row.timestamp,
                tenant_id=row.tenant_id,
                actor_user_id=row.actor_user_id,
                actor=actor_map.get(str(row.actor_user_id or "").strip()) if row.actor_user_id else None,
                action=row.action,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                ip=row.ip,
                user_agent=row.user_agent,
                success=row.success,
                details=details,
            )
        )

    return AuditListResponse(items=items, limit=limit, offset=offset, total=total)
