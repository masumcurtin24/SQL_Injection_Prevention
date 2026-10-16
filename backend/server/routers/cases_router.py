from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import User
from backend.server.deps.policy import require_policy
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.server.schemas.cases import (
    CaseActivityResponse,
    CaseAlertLinkRequest,
    CaseAlertLinksResponse,
    CaseAssignRequest,
    CaseCreateRequest,
    CaseNoteRequest,
    CaseNotesResponse,
    CaseStatusUpdateRequest,
    SecurityCaseDetail,
    SecurityCaseListResponse,
    SecurityCaseStatsResponse,
    SecurityCaseSummary,
)
from backend.services.alerts_service import AlertsService
from backend.utils.user_summary import build_user_summary_map
from backend.services.case_management_service import CaseManagementService
from backend.utils.audit import write_audit
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


def get_case_service() -> CaseManagementService:
    try:
        return CaseManagementService.get_instance()
    except RuntimeError as e:
        logger.critical("CRITICAL: CaseManagementService not available: %s", e)
        raise HTTPException(status_code=503, detail="Case management service is not available.")


def _map_alert_severity_to_case(alert_severity: str) -> str:
    sev = str(alert_severity or "").strip().lower()
    if sev == "critical":
        return "Critical"
    if sev == "high":
        return "High"
    if sev == "medium":
        return "Medium"
    return "Low"


def _get_case_or_404(service: CaseManagementService, db: Session, case_id: str, tenant_id: str):
    case = service.get_case_by_id(db=db, case_id=case_id, tenant_id=tenant_id)
    if case is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return case


def _get_case_detail_or_404(
    service: CaseManagementService,
    db: Session,
    case_id: str,
    tenant_id: str,
) -> SecurityCaseDetail:
    payload = service.get_case_detail_payload(db=db, case_id=case_id, tenant_id=tenant_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return SecurityCaseDetail.model_validate(payload)


@router.get("", response_model=SecurityCaseListResponse, summary="List investigation cases")
def list_cases_endpoint(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    owner_user_id: Optional[str] = Query(None),
    search_term: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    _current_user: User = Depends(require_policy("cases.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseListResponse:
    try:
        cases, total, total_pages, status_counts = service.list_cases(
            db=db,
            tenant_id=tenant_ctx.tenant_id,
            page=page,
            page_size=page_size,
            status=status,
            severity=severity,
            owner_user_id=owner_user_id,
            search_term=search_term,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return SecurityCaseListResponse(
        cases=[SecurityCaseSummary.model_validate(c) for c in cases],
        total_cases=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        status_counts=status_counts,
    )


@router.get("/stats", response_model=SecurityCaseStatsResponse, summary="Get case statistics")
def get_case_stats_endpoint(
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    _current_user: User = Depends(require_policy("cases.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseStatsResponse:
    return SecurityCaseStatsResponse.model_validate(service.get_stats(db=db, tenant_id=tenant_ctx.tenant_id))


@router.post("", response_model=SecurityCaseDetail, summary="Create investigation case")
def create_case_endpoint(
    payload: CaseCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    current_user: User = Depends(require_policy("cases.create")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseDetail:
    try:
        created = service.create_case(
            db=db,
            tenant_id=tenant_ctx.tenant_id,
            created_by_user_id=str(current_user.id),
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            domain=payload.domain,
            source_type=payload.source_type,
            source_id=payload.source_id,
            owner_user_id=payload.owner_user_id,
            tags=payload.tags,
            evidence=payload.evidence,
            alert_ids=payload.alert_ids,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="cases.create",
        resource_type="security_case",
        resource_id=created.id,
        details={"status": created.status, "severity": created.severity},
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return _get_case_detail_or_404(service=service, db=db, case_id=created.id, tenant_id=tenant_ctx.tenant_id)


@router.post("/from-alert/{alert_id}", response_model=SecurityCaseDetail, summary="Create case from alert")
def create_case_from_alert_endpoint(
    alert_id: str,
    request: Request,
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    current_user: User = Depends(require_policy("cases.create")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseDetail:
    alert = AlertsService.get_instance().get_alert_by_id(db=db, alert_id=alert_id, tenant_id=tenant_ctx.tenant_id)
    if alert is None:
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="cases.create.from_alert",
            resource_type="alert",
            resource_id=alert_id,
            details={"reason": "alert_not_found"},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    alert_detail = AlertsService.get_instance().get_alert_detail_payload(
        db=db,
        alert_id=alert.id,
        tenant_id=tenant_ctx.tenant_id,
    )
    explainability = (alert_detail or {}).get("explainability") if isinstance(alert_detail, dict) else None
    evidence = [
        {
            "type": "alert_explainability",
            "alert_id": alert.id,
            "severity_source": "alert",
            "risk_score": (explainability or {}).get("risk_score") if isinstance(explainability, dict) else None,
            "decision_confidence": (explainability or {}).get("decision_confidence") if isinstance(explainability, dict) else None,
            "ai_reliability": (explainability or {}).get("ai_reliability") if isinstance(explainability, dict) else None,
            "review_required": ((explainability or {}).get("decision_rationale") or {}).get("review_required")
            if isinstance(explainability, dict)
            else None,
            "recommended_handling": ((explainability or {}).get("decision_rationale") or {}).get("recommended_handling")
            if isinstance(explainability, dict)
            else None,
            "evidence_contributions": (explainability or {}).get("evidence_contributions") if isinstance(explainability, dict) else None,
            "limitations": (explainability or {}).get("limitations") if isinstance(explainability, dict) else None,
        }
    ]

    created = service.create_case(
        db=db,
        tenant_id=tenant_ctx.tenant_id,
        created_by_user_id=str(current_user.id),
        title=f"Investigate Alert: {alert.title}",
        description=alert.message,
        severity=_map_alert_severity_to_case(alert.severity),
        domain="alert",
        source_type="alert",
        source_id=alert.id,
        owner_user_id=str(current_user.id),
        tags=(alert.tags or []) + ["from-alert"],
        evidence=evidence,
        alert_ids=[alert.id],
    )
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="cases.create.from_alert",
        resource_type="security_case",
        resource_id=created.id,
        details={"alert_id": alert_id},
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return _get_case_detail_or_404(service=service, db=db, case_id=created.id, tenant_id=tenant_ctx.tenant_id)


@router.get("/{case_id}", response_model=SecurityCaseDetail, summary="Get case detail")
def get_case_detail_endpoint(
    case_id: str,
    request: Request,
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    current_user: User = Depends(require_policy("cases.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseDetail:
    payload = service.get_case_detail_payload(db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id)
    if payload is None:
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="cases.detail.view",
            resource_type="security_case",
            resource_id=case_id,
            details={"reason": "not_found"},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="cases.detail.view",
        resource_type="security_case",
        resource_id=case_id,
        details=None,
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return SecurityCaseDetail.model_validate(payload)


@router.patch("/{case_id}/status", response_model=SecurityCaseDetail, summary="Update case status")
def update_case_status_endpoint(
    case_id: str,
    payload: CaseStatusUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    current_user: User = Depends(require_policy("cases.update")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseDetail:
    case = _get_case_or_404(service=service, db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id)
    try:
        updated = service.update_status(
            db=db,
            case=case,
            new_status=payload.status,
            actor_user_id=str(current_user.id),
            note=payload.note,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="cases.status.update",
        resource_type="security_case",
        resource_id=case_id,
        details={"status": payload.status},
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return _get_case_detail_or_404(service=service, db=db, case_id=updated.id, tenant_id=tenant_ctx.tenant_id)


@router.patch("/{case_id}/assign", response_model=SecurityCaseDetail, summary="Assign case owner")
def assign_case_endpoint(
    case_id: str,
    payload: CaseAssignRequest,
    request: Request,
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    current_user: User = Depends(require_policy("cases.assign")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseDetail:
    case = _get_case_or_404(service=service, db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id)

    updated = service.assign_owner(
        db=db,
        case=case,
        owner_user_id=payload.owner_user_id,
        actor_user_id=str(current_user.id),
        note=payload.note,
    )
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="cases.assign",
        resource_type="security_case",
        resource_id=case_id,
        details={"owner_user_id": payload.owner_user_id},
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return _get_case_detail_or_404(service=service, db=db, case_id=updated.id, tenant_id=tenant_ctx.tenant_id)


@router.post("/{case_id}/notes", response_model=SecurityCaseDetail, summary="Add case note")
def add_case_note_endpoint(
    case_id: str,
    payload: CaseNoteRequest,
    request: Request,
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    current_user: User = Depends(require_policy("cases.update")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseDetail:
    case = _get_case_or_404(service=service, db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id)
    try:
        updated = service.add_note(
            db=db,
            case=case,
            actor_user_id=str(current_user.id),
            note=payload.note,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="cases.note",
        resource_type="security_case",
        resource_id=case_id,
        details=None,
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return _get_case_detail_or_404(service=service, db=db, case_id=updated.id, tenant_id=tenant_ctx.tenant_id)


@router.post("/{case_id}/alerts", response_model=SecurityCaseDetail, summary="Link alert to case")
def link_alert_to_case_endpoint(
    case_id: str,
    payload: CaseAlertLinkRequest,
    request: Request,
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    current_user: User = Depends(require_policy("cases.update")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> SecurityCaseDetail:
    case = _get_case_or_404(service=service, db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id)
    try:
        updated = service.link_alert(
            db=db,
            case=case,
            tenant_id=tenant_ctx.tenant_id,
            alert_id=payload.alert_id,
            actor_user_id=str(current_user.id),
            note=payload.note,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="cases.alert.link",
        resource_type="security_case",
        resource_id=case_id,
        details={"alert_id": payload.alert_id},
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return _get_case_detail_or_404(service=service, db=db, case_id=updated.id, tenant_id=tenant_ctx.tenant_id)


@router.get("/{case_id}/notes", response_model=CaseNotesResponse, summary="List case notes")
def list_case_notes_endpoint(
    case_id: str,
    limit: int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    _current_user: User = Depends(require_policy("cases.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> CaseNotesResponse:
    _get_case_or_404(service=service, db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id)
    notes = service.list_case_notes(db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id, limit=limit)
    user_map = build_user_summary_map(
        db=db,
        user_ids=[str(row.author_user_id or "").strip() for row in notes],
        include_unknown=False,
    )
    return CaseNotesResponse(
        case_id=case_id,
        count=len(notes),
        notes=[
            {
                "id": row.id,
                "case_id": row.case_id,
                "tenant_id": row.tenant_id,
                "created_at": row.created_at,
                "author_user_id": row.author_user_id,
                "author": user_map.get(str(row.author_user_id or "").strip()) if row.author_user_id else None,
                "note": row.note,
            }
            for row in notes
        ],
    )


@router.get("/{case_id}/alerts", response_model=CaseAlertLinksResponse, summary="List alert links for case")
def list_case_alert_links_endpoint(
    case_id: str,
    limit: int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    _current_user: User = Depends(require_policy("cases.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> CaseAlertLinksResponse:
    _get_case_or_404(service=service, db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id)
    links = service.list_case_alert_links(db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id, limit=limit)
    user_map = build_user_summary_map(
        db=db,
        user_ids=[str(row.linked_by_user_id or "").strip() for row in links],
        include_unknown=False,
    )
    return CaseAlertLinksResponse(
        case_id=case_id,
        count=len(links),
        links=[
            {
                "id": row.id,
                "case_id": row.case_id,
                "tenant_id": row.tenant_id,
                "alert_id": row.alert_id,
                "linked_at": row.linked_at,
                "linked_by_user_id": row.linked_by_user_id,
                "linked_by": user_map.get(str(row.linked_by_user_id or "").strip()) if row.linked_by_user_id else None,
                "note": row.note,
            }
            for row in links
        ],
    )


@router.get("/{case_id}/activity", response_model=CaseActivityResponse, summary="List case activity timeline")
def list_case_activity_endpoint(
    case_id: str,
    limit: int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
    service: CaseManagementService = Depends(get_case_service),
    _current_user: User = Depends(require_policy("cases.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> CaseActivityResponse:
    case = _get_case_or_404(service=service, db=db, case_id=case_id, tenant_id=tenant_ctx.tenant_id)
    activity = service.list_case_activity(db=db, case=case, tenant_id=tenant_ctx.tenant_id, limit=limit)
    return CaseActivityResponse(case_id=case_id, count=len(activity), activity=activity)
