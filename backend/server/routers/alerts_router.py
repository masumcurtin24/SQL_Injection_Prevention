# backend/server/routers/alerts_router.py (Corrected)
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

# --- Project Module Imports ---
from backend.core.database import get_db
from backend.core.models import User
from backend.server.deps.auth import require_role
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.server.schemas.responses import AlertsListResponse, Alert as AlertSchema
from backend.services.alerts_service import AlertsService
from backend.utils.audit import write_audit
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

def get_alerts_service() -> AlertsService:
    """Dependency injector for AlertsService."""
    try:
        return AlertsService.get_instance()
    except RuntimeError as e:
        logger.critical(f"CRITICAL: Could not get AlertsService instance. Error: {e}")
        raise HTTPException(status_code=503, detail="Alerts Service is not available.")

@router.get(
    "",
    response_model=AlertsListResponse,
    summary="Get a List of Security Alerts"
)
async def get_alerts_list_endpoint(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number."),
    page_size: int = Query(10, ge=1, le=100, description="Alerts per page."),
    severity: Optional[str] = Query(None, description="Filter by severity.", enum=['Critical', 'High', 'Medium', 'Low', 'Info', 'All']),
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledged status."),
    search_term: Optional[str] = Query(None, description="Search term for alerts."),
    service: AlertsService = Depends(get_alerts_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> AlertsListResponse:
    logger.info(f"API /alerts called with params: page={page}, severity='{severity}', search='{search_term}'")
    try:
        # The service now handles all the filtering and pagination logic
        return service.get_alerts(
            db=db,
            page=page,
            page_size=page_size,
            severity=severity if severity != "All" else None,
            acknowledged=acknowledged,
            search_term=search_term,
            tenant_id=tenant_ctx.tenant_id,
        )
    except Exception as e:
        logger.error(f"Error in /alerts endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts.")

@router.get(
    "/{alert_id}",
    response_model=Dict[str, Any],
    summary="Get a Specific Alert by ID"
)
async def get_alert_detail_endpoint(
    request: Request,
    alert_id: str,
    db: Session = Depends(get_db),
    service: AlertsService = Depends(get_alerts_service),
    current_user: User = Depends(require_role("analyst")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    logger.info(f"API /alerts/{alert_id} called.")
    alert_payload = service.get_alert_detail_payload(db=db, alert_id=alert_id, tenant_id=tenant_ctx.tenant_id)
    if not alert_payload:
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="alerts.detail.view",
            resource_type="alert",
            resource_id=alert_id,
            details={"reason": "not_found"},
            success=False,
        )
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found.")
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="alerts.detail.view",
        resource_type="alert",
        resource_id=alert_id,
        details=None,
        success=True,
    )
    return alert_payload


@router.patch(
    "/{alert_id}/acknowledge",
    response_model=AlertSchema,
    summary="Acknowledge or Unacknowledge an Alert"
)
async def acknowledge_alert_endpoint(
    request: Request,
    alert_id: str,
    acknowledge: bool = Query(True, description="Set to true to acknowledge, false to unacknowledge."),
    db: Session = Depends(get_db),
    service: AlertsService = Depends(get_alerts_service),
    current_user: User = Depends(require_role("analyst")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> AlertSchema:
    logger.info(f"API /alerts/{alert_id}/acknowledge called with acknowledge={acknowledge}.")
    updated_alert = service.acknowledge_alert(
        db=db,
        alert_id=alert_id,
        acknowledge_status=acknowledge,
        tenant_id=tenant_ctx.tenant_id,
    )
    if not updated_alert:
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="alerts.acknowledge" if acknowledge else "alerts.unacknowledge",
            resource_type="alert",
            resource_id=alert_id,
            details={"acknowledge": acknowledge, "reason": "alert_not_found"},
            success=False,
        )
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found.")
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="alerts.acknowledge" if acknowledge else "alerts.unacknowledge",
        resource_type="alert",
        resource_id=alert_id,
        details={"acknowledge": acknowledge},
        success=True,
    )
    return AlertSchema.model_validate(updated_alert)
