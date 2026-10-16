# backend/server/routers/dashboard_router.py (Corrected)
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone, date
from sqlalchemy.orm import Session

# --- Project Module Imports ---
# This try/except block is fine and handles different running environments.
try:
    from backend.core.database import get_db
    from backend.core.models import User
    from backend.server.deps.policy import require_policy
    from backend.server.deps.tenant import TenantContext, get_tenant_context
    from backend.server.schemas.responses import (
        DashboardSummaryResponse, ThreatTrendResponse,
        ThreatsByCategoryResponse, AlertSeverityDistributionResponse,
        DashboardStats,
        DashboardStatsHistoryResponse,
    )
    from backend.services.dashboard_service import DashboardService, get_recent_events
    from backend.utils.audit import write_audit
    from backend.utils.logging_utils import setup_logger
    from backend.services.file_scan_queue_service import BaseFileScanQueueService
except ImportError:
    print("INFO: Dashboard router using fallback imports.")
    import sys, os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir_path = os.path.abspath(os.path.join(current_dir, '..', '..'))
    if backend_dir_path not in sys.path: sys.path.insert(0, backend_dir_path)
    from core.database import get_db
    from core.models import User
    from server.deps.policy import require_policy
    from server.deps.tenant import TenantContext, get_tenant_context
    from server.schemas.responses import (DashboardSummaryResponse, ThreatTrendResponse, ThreatsByCategoryResponse, AlertSeverityDistributionResponse, DashboardStats, DashboardStatsHistoryResponse)
    from services.dashboard_service import DashboardService, get_recent_events
    from utils.audit import write_audit
    from utils.logging_utils import setup_logger
    from services.file_scan_queue_service import BaseFileScanQueueService

logger = setup_logger(__name__)
router = APIRouter()
_ADMIN_LIVE_FEED_TYPES = ["query", "file_scan", "spam_check", "alert"]
_VIEWER_LIVE_FEED_TYPES = ["query", "file_scan", "spam_check"]


def _normalize_live_event_types_csv(raw: Optional[str], allowed: list[str]) -> str:
    allowed_set = set(allowed)
    requested = [token.strip().lower() for token in str(raw or "").split(",") if token and token.strip()]
    if not requested:
        return ",".join(allowed)
    filtered = [token for token in requested if token in allowed_set]
    if not filtered:
        return ",".join(allowed)
    # Keep stable canonical ordering to avoid noisy frontend diffing.
    normalized = [token for token in allowed if token in set(filtered)]
    return ",".join(normalized)

# --- CORRECTED Dependency Injector ---
# This no longer creates its own instance. It fetches the one from startup.
def get_dashboard_service() -> DashboardService:
    """
    Dependency injector that retrieves the single, globally-initialized
    instance of DashboardService created at application startup.
    """
    try:
        # Correctly get the singleton instance that was initialized in `main.py`
        return DashboardService.get_instance()
    except RuntimeError as e:
        logger.critical(f"FATAL: Could not get DashboardService instance. It was likely not initialized at startup. Error: {e}")
        raise HTTPException(status_code=503, detail="Dashboard service is not available.")

# --- Endpoints (No changes needed here) ---

@router.get("/summary-stats", response_model=DashboardSummaryResponse, tags=["Dashboard"])
async def get_dashboard_summary_stats_endpoint(
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.metrics.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> DashboardSummaryResponse:
    logger.info("API endpoint /summary-stats called.")
    try:
        return service.get_dashboard_summary(db=db, tenant_id=tenant_ctx.tenant_id)
    except Exception as e:
        logger.error(f"Error in /summary-stats endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard summary statistics.")

@router.get("/threat-trends", response_model=ThreatTrendResponse, tags=["Dashboard"])
async def get_threat_trends_endpoint(
    days: Optional[int] = Query(7, ge=1, le=90, description="Number of past days for trend data (1-90)."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.metrics.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> ThreatTrendResponse:
    logger.info(f"API endpoint /threat-trends called for {days} days.")
    try:
        return service.get_threat_trends(db=db, days=days, tenant_id=tenant_ctx.tenant_id)
    except Exception as e:
        logger.error(f"Error in /threat-trends endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve threat trend data.")

@router.get("/threats-by-category", response_model=ThreatsByCategoryResponse, tags=["Dashboard"])
async def get_threats_by_category_endpoint(
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.metrics.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> ThreatsByCategoryResponse:
    logger.info("API endpoint /threats-by-category called.")
    try:
        return service.get_threats_by_category(db=db, tenant_id=tenant_ctx.tenant_id)
    except Exception as e:
        logger.error(f"Error in /threats-by-category endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve threats by category data.")

@router.get("/alert-severity-distribution", response_model=AlertSeverityDistributionResponse, tags=["Dashboard"])
async def get_alert_severity_distribution_endpoint(
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.metrics.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> AlertSeverityDistributionResponse:
    logger.info("API endpoint /alert-severity-distribution called.")
    try:
        return service.get_alert_severity_distribution(db=db, tenant_id=tenant_ctx.tenant_id)
    except Exception as e:
        logger.error(f"Error in /alert-severity-distribution endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve alert severity distribution data.")
    
@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(
    scope: str = Query("today", description="Stats scope: today|total"),
    day: Optional[date] = Query(None, description="Override day (YYYY-MM-DD) for scope=today."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.metrics.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    """
    This function is the public-facing API endpoint for retrieving dashboard stats.
    When the frontend sends a GET request to '/api/dashboard/stats', this code runs.
    """
    try:
        s = str(scope or "").strip().lower()
        if s in {"total", "all", "lifetime"}:
            return service.get_dashboard_statistics(db=db, tenant_id=tenant_ctx.tenant_id)

        target_day = day or datetime.now(timezone.utc).date()
        start = datetime(target_day.year, target_day.month, target_day.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        return service.get_dashboard_statistics(db=db, start=start, end=end, tenant_id=tenant_ctx.tenant_id)
    except Exception as e:
        logger.error(f"Error in /stats endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard statistics.")


@router.get("/executive-overview", tags=["Dashboard"])
def get_dashboard_executive_overview(
    scope: str = Query("today", description="Overview scope: today|total"),
    day: Optional[date] = Query(None, description="Override day (YYYY-MM-DD) for scope=today."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.metrics.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        s = str(scope or "").strip().lower()
        if s in {"total", "all", "lifetime"}:
            payload = service.get_executive_overview(db=db, tenant_id=tenant_ctx.tenant_id)
            payload["scope"] = "total"
            payload["day"] = None
            return payload

        target_day = day or datetime.now(timezone.utc).date()
        start = datetime(target_day.year, target_day.month, target_day.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        payload = service.get_executive_overview(db=db, start=start, end=end, tenant_id=tenant_ctx.tenant_id)
        payload["scope"] = "today"
        payload["day"] = str(target_day)
        return payload
    except Exception as e:
        logger.error(f"Error in /executive-overview endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve executive overview.")


@router.get("/stats-history", response_model=DashboardStatsHistoryResponse, tags=["Dashboard"])
def get_dashboard_stats_history(
    days: int = Query(30, ge=1, le=365, description="Number of past days to include (1-365)."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.metrics.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> DashboardStatsHistoryResponse:
    try:
        return service.get_dashboard_statistics_history(db=db, days=days, tenant_id=tenant_ctx.tenant_id)
    except Exception as e:
        logger.error(f"Error in /stats-history endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard statistics history.")


@router.get("/platform-health", tags=["Dashboard"])
async def get_platform_health_endpoint(
    request: Request,
    top: int = Query(20, ge=1, le=200, description="Top endpoints to include from HTTP telemetry."),
    fp_days: int = Query(30, ge=1, le=365, description="False-positive trend horizon in days."),
    analyst_only: bool = Query(True, description="Use only human analyst feedback for quality metrics."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("monitoring.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    """
    Aggregated platform health view for admin/analyst dashboard cards.
    Includes telemetry, websocket status, queue health, model lifecycle, and quality trends.
    """
    queue_stats: Optional[Dict[str, Any]] = None
    try:
        queue_service = getattr(request.app.state, "file_scan_queue_service", None)
        if isinstance(queue_service, BaseFileScanQueueService):
            queue_stats = await queue_service.stats()
        elif queue_service is not None and hasattr(queue_service, "stats"):
            maybe_stats = queue_service.stats()
            if hasattr(maybe_stats, "__await__"):
                queue_stats = await maybe_stats
            elif isinstance(maybe_stats, dict):
                queue_stats = maybe_stats
    except Exception as queue_exc:
        logger.warning(f"Unable to collect file scan queue stats for platform health: {queue_exc}")

    try:
        return service.get_platform_health(
            db=db,
            queue_stats=queue_stats,
            top_endpoints=top,
            fp_days=fp_days,
            analyst_only=analyst_only,
            tenant_id=tenant_ctx.tenant_id,
        )
    except Exception as e:
        logger.error(f"Error in /platform-health endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve platform health.")


@router.get("/access-feed", tags=["Dashboard"])
def get_access_feed_endpoint(
    limit: int = Query(50, ge=1, le=500, description="Maximum session rows to return."),
    active_only: bool = Query(True, description="When true, include only active sessions."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.access.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        return service.get_access_feed(db=db, limit=limit, active_only=active_only, tenant_id=tenant_ctx.tenant_id)
    except Exception as e:
        logger.error(f"Error in /access-feed endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve access feed.")


@router.get("/live-events", tags=["Dashboard"])
def get_recent_live_events(
    limit: int = Query(50, ge=1, le=500, description="Maximum number of mixed live events to return."),
    day: Optional[date] = Query(None, description="Optional UTC day filter (YYYY-MM-DD)."),
    before: Optional[datetime] = Query(
        None,
        description="Optional cursor timestamp (ISO-8601). Returns events strictly older than this timestamp.",
    ),
    event_types: Optional[str] = Query(
        None,
        description="Optional CSV filter: query,file_scan,spam_check,alert",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("dashboard.events.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        role = str(getattr(current_user, "role", "") or "").strip().lower()
        is_admin_scope = role in {"admin", "analyst"}

        effective_day = day
        effective_before = before
        if is_admin_scope:
            effective_event_types = _normalize_live_event_types_csv(event_types, _ADMIN_LIVE_FEED_TYPES)
        else:
            # Viewer scope is intentionally bounded to the current UTC day only.
            effective_day = datetime.now(timezone.utc).date()
            effective_event_types = _normalize_live_event_types_csv(event_types, _VIEWER_LIVE_FEED_TYPES)
            # Keep cursoring available but bounded by effective_day window.
            effective_before = before

        start = None
        end = None
        if effective_day is not None:
            start = datetime(effective_day.year, effective_day.month, effective_day.day, tzinfo=timezone.utc)
            end = start + timedelta(days=1)

        events = get_recent_events(
            db=db,
            limit=limit,
            start=start,
            end=end,
            before=effective_before,
            event_types=effective_event_types,
            tenant_id=tenant_ctx.tenant_id,
        )
        next_before = events[-1]["timestamp"] if len(events) >= limit and events else None
        return {
            "events": events,
            "limit": limit,
            "day": str(effective_day) if effective_day is not None else None,
            "before": effective_before.isoformat() if effective_before is not None else None,
            "event_types": effective_event_types,
            "next_before": next_before,
            "has_more": bool(next_before),
            "scope": "admin" if is_admin_scope else "viewer",
        }
    except Exception as e:
        logger.error(f"Error in /live-events endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve live events.")


@router.get("/live-events/detail", tags=["Dashboard"])
def get_live_event_detail(
    request: Request,
    event_type: str = Query(..., description="Live event type: query|file_scan|spam_check|alert"),
    event_id: str = Query(..., description="Live event identifier"),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    current_user: User = Depends(require_policy("dashboard.detail.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        detail = service.get_live_event_detail(
            db=db,
            event_type=event_type,
            event_id=event_id,
            tenant_id=tenant_ctx.tenant_id,
        )
        if not detail:
            write_audit(
                db=db,
                request=request,
                actor=current_user,
                action="dashboard.live_event.detail.view",
                resource_type="dashboard_live_event",
                resource_id=f"{event_type}:{event_id}",
                details={"event_type": event_type, "event_id": event_id, "reason": "not_found"},
                success=False,
                tenant_id=tenant_ctx.tenant_id,
            )
            raise HTTPException(status_code=404, detail="Live event detail not found.")
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="dashboard.live_event.detail.view",
            resource_type="dashboard_live_event",
            resource_id=f"{event_type}:{event_id}",
            details={"event_type": event_type, "event_id": event_id},
            success=True,
            tenant_id=tenant_ctx.tenant_id,
        )
        return detail
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in /live-events/detail endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve live event detail.")


@router.get("/files-scanned", tags=["Dashboard"])
def get_files_scanned_for_day(
    day: Optional[date] = Query(None, description="UTC day in YYYY-MM-DD. Defaults to today."),
    limit: Optional[int] = Query(None, ge=1, le=2000, description="Deprecated alias for page_size."),
    page: int = Query(1, ge=1, description="Page number (1-based)."),
    page_size: int = Query(100, ge=1, le=2000, description="Rows per page."),
    search: Optional[str] = Query(None, min_length=1, max_length=200, description="Search by filename or analysis id."),
    category: Optional[str] = Query(None, pattern="^(safe|suspicious|blocked)$", description="Filter by category."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.detail.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        target_day = day or datetime.now(timezone.utc).date()
        start = datetime(target_day.year, target_day.month, target_day.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        effective_page_size = limit if limit is not None else page_size
        result = service.get_files_scanned_page(
            db=db,
            start=start,
            end=end,
            tenant_id=tenant_ctx.tenant_id,
            page=page,
            page_size=effective_page_size,
            search=search,
            category=category,
        )
        rows = result.get("items", [])
        return {
            "day": str(target_day),
            "count": len(rows),
            "total": int(result.get("total", 0)),
            "page": int(result.get("page", page)),
            "page_size": int(result.get("page_size", effective_page_size)),
            "total_pages": int(result.get("total_pages", 0)),
            "search": search,
            "category": category,
            "files": rows,
        }
    except Exception as e:
        logger.error(f"Error in /files-scanned endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve file scan details.")


@router.get("/sql-queries", tags=["Dashboard"])
def get_sql_queries_for_day(
    day: Optional[date] = Query(None, description="UTC day in YYYY-MM-DD. Defaults to today."),
    limit: Optional[int] = Query(None, ge=1, le=2000, description="Deprecated alias for page_size."),
    page: int = Query(1, ge=1, description="Page number (1-based)."),
    page_size: int = Query(100, ge=1, le=2000, description="Rows per page."),
    malicious_only: bool = Query(False, description="Return only High/Critical SQL assessments."),
    search: Optional[str] = Query(None, min_length=1, max_length=200, description="Search by query text or analysis id."),
    category: Optional[str] = Query(None, pattern="^(safe|suspicious|blocked)$", description="Filter by category."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.detail.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        target_day = day or datetime.now(timezone.utc).date()
        start = datetime(target_day.year, target_day.month, target_day.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        effective_page_size = limit if limit is not None else page_size
        result = service.get_sql_queries_page(
            db=db,
            start=start,
            end=end,
            tenant_id=tenant_ctx.tenant_id,
            page=page,
            page_size=effective_page_size,
            malicious_only=malicious_only,
            search=search,
            category=category,
        )
        rows = result.get("items", [])
        return {
            "day": str(target_day),
            "count": len(rows),
            "total": int(result.get("total", 0)),
            "page": int(result.get("page", page)),
            "page_size": int(result.get("page_size", effective_page_size)),
            "total_pages": int(result.get("total_pages", 0)),
            "malicious_only": malicious_only,
            "search": search,
            "category": category,
            "queries": rows,
        }
    except Exception as e:
        logger.error(f"Error in /sql-queries endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve SQL query details.")


@router.get("/spam-detections", tags=["Dashboard"])
def get_spam_detections_for_day(
    day: Optional[date] = Query(None, description="UTC day in YYYY-MM-DD. Defaults to today."),
    limit: Optional[int] = Query(None, ge=1, le=2000, description="Deprecated alias for page_size."),
    page: int = Query(1, ge=1, description="Page number (1-based)."),
    page_size: int = Query(100, ge=1, le=2000, description="Rows per page."),
    detected_only: bool = Query(True, description="Return only rows classified as spam."),
    search: Optional[str] = Query(None, min_length=1, max_length=200, description="Search by subject or analysis id."),
    category: Optional[str] = Query(None, pattern="^(safe|suspicious|blocked)$", description="Filter by category."),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
    _user: User = Depends(require_policy("dashboard.detail.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        target_day = day or datetime.now(timezone.utc).date()
        start = datetime(target_day.year, target_day.month, target_day.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        effective_page_size = limit if limit is not None else page_size
        result = service.get_spam_checks_page(
            db=db,
            start=start,
            end=end,
            tenant_id=tenant_ctx.tenant_id,
            page=page,
            page_size=effective_page_size,
            detected_only=detected_only,
            search=search,
            category=category,
        )
        rows = result.get("items", [])
        return {
            "day": str(target_day),
            "count": len(rows),
            "total": int(result.get("total", 0)),
            "page": int(result.get("page", page)),
            "page_size": int(result.get("page_size", effective_page_size)),
            "total_pages": int(result.get("total_pages", 0)),
            "detected_only": detected_only,
            "search": search,
            "category": category,
            "detections": rows,
        }
    except Exception as e:
        logger.error(f"Error in /spam-detections endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve spam detection details.")
