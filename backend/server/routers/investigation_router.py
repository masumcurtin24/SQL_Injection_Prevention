from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import User
from backend.server.deps.policy import require_policy
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.server.schemas.investigation import InvestigationTimelineResponse
from backend.services.investigation_service import InvestigationService
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


def get_investigation_service() -> InvestigationService:
    try:
        return InvestigationService.get_instance()
    except RuntimeError as e:
        logger.critical("CRITICAL: InvestigationService not available: %s", e)
        raise HTTPException(status_code=503, detail="Investigation service is not available.")


@router.get("/timeline", response_model=InvestigationTimelineResponse, summary="Get investigation timeline")
def get_investigation_timeline_endpoint(
    limit: int = Query(200, ge=1, le=500),
    day: Optional[date] = Query(None, description="Optional UTC day (YYYY-MM-DD)."),
    start: Optional[datetime] = Query(None, description="Optional start datetime (UTC)."),
    end: Optional[datetime] = Query(None, description="Optional end datetime (UTC)."),
    before: Optional[datetime] = Query(
        None,
        description="Optional cursor datetime (UTC). Returns events strictly older than this timestamp.",
    ),
    event_types: Optional[str] = Query(
        None,
        description="Optional CSV filter: query,file_scan,spam_check,alert,case,case_note,case_alert_link",
    ),
    entity_key: Optional[str] = Query(None, description="Optional entity key filter."),
    entity_value: Optional[str] = Query(None, description="Optional entity value match filter."),
    db: Session = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service),
    _current_user: User = Depends(require_policy("investigation.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> InvestigationTimelineResponse:
    try:
        resolved_start = start
        resolved_end = end
        if day is not None:
            resolved_start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
            resolved_end = resolved_start + timedelta(days=1)

        items = service.get_timeline(
            db=db,
            tenant_id=tenant_ctx.tenant_id,
            limit=limit,
            start=resolved_start,
            end=resolved_end,
            before=before,
            event_types=event_types,
            entity_key=entity_key,
            entity_value=entity_value,
        )
        return InvestigationTimelineResponse(
            items=items,
            count=len(items),
            limit=limit,
            start=resolved_start.isoformat() if resolved_start else None,
            end=resolved_end.isoformat() if resolved_end else None,
            before=before.isoformat() if before else None,
            event_types=event_types,
            entity_key=entity_key,
            entity_value=entity_value,
        )
    except Exception as e:
        logger.error("Error in /investigation/timeline endpoint: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve investigation timeline.")
