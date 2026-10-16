from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import User
from backend.server.deps.auth import require_role
from backend.server.deps.policy import require_policy
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.server.schemas.defender import (
    DefenderModelInfo,
    DefenderPromoteRequest,
    DefenderRollbackRequest,
    DefenderRollbackResponse,
    DefenderRetrainRequest,
    DefenderRetrainResponse,
    DefenderRetrainResult,
    DefenderStatusResponse,
    DefenderTrainingJobInfo,
    FileFeedbackRequest,
    SQLFeedbackRequest,
    SpamFeedbackV1Request,
)
from backend.services.defender_ai_service import DefenderAIService
from backend.services.spam_autopipeline_service import SpamAutopipelineService
from backend.utils.audit import write_audit
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


def get_defender_service() -> DefenderAIService:
    try:
        return DefenderAIService.get_instance()
    except Exception:
        return DefenderAIService()


def get_spam_autopipeline_service(request: Request) -> SpamAutopipelineService:
    service = getattr(request.app.state, "spam_autopipeline_service", None)
    if service is not None:
        return service
    try:
        return SpamAutopipelineService.get_instance()
    except Exception:
        return SpamAutopipelineService()


@router.post("/feedback/sql", summary="Submit labeled SQL feedback")
async def submit_sql_feedback(
    payload: SQLFeedbackRequest,
    db: Session = Depends(get_db),
    _user=Depends(require_role("reviewer")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        return service.submit_sql_feedback(
            db=db,
            tenant_id=tenant_ctx.tenant_id,
            query=payload.query,
            true_label=payload.true_label,
            predicted_label=payload.predicted_label,
            confidence=payload.confidence,
            analysis_id=payload.analysis_id,
            source=payload.source,
            notes=payload.notes,
        )
    except Exception as exc:
        logger.error(f"Failed to submit SQL feedback: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to submit SQL feedback")


@router.post("/feedback/file", summary="Submit labeled file feedback")
async def submit_file_feedback(
    payload: FileFeedbackRequest,
    db: Session = Depends(get_db),
    _user=Depends(require_role("reviewer")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        return service.submit_file_feedback(
            db=db,
            tenant_id=tenant_ctx.tenant_id,
            filename=payload.filename,
            observed_text=payload.observed_text,
            true_label=payload.true_label,
            predicted_label=payload.predicted_label,
            recommended_action=payload.recommended_action,
            confidence=payload.confidence,
            analysis_id=payload.analysis_id,
            source=payload.source,
            notes=payload.notes,
        )
    except Exception as exc:
        logger.error(f"Failed to submit file feedback: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to submit file feedback")


@router.post("/feedback/spam", summary="Submit labeled spam feedback")
async def submit_spam_feedback(
    payload: SpamFeedbackV1Request,
    db: Session = Depends(get_db),
    _user=Depends(require_role("reviewer")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    try:
        return service.submit_spam_feedback(
            db=db,
            tenant_id=tenant_ctx.tenant_id,
            body_text=payload.body_text,
            subject=payload.subject,
            sender_email=payload.sender_email,
            true_label=payload.true_label,
            predicted_label=payload.predicted_label,
            confidence=payload.confidence,
            analysis_id=payload.analysis_id,
            source=payload.source,
            notes=payload.notes,
        )
    except Exception as exc:
        logger.error(f"Failed to submit spam feedback: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to submit spam feedback")


@router.get("/status", response_model=DefenderStatusResponse, summary="Get Defender AI status")
async def get_defender_status(
    db: Session = Depends(get_db),
    _user=Depends(require_role("reviewer")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> DefenderStatusResponse:
    data = service.get_status(db, tenant_id=tenant_ctx.tenant_id)
    models_payload = {
        domain: [DefenderModelInfo.model_validate(row) for row in rows]
        for domain, rows in (data.get("models") or {}).items()
    }
    return DefenderStatusResponse(
        feedback_counts=data.get("feedback_counts") or {},
        pending_feedback=int(data.get("pending_feedback") or 0),
        models=models_payload,
        recent_jobs=[DefenderTrainingJobInfo.model_validate(row) for row in (data.get("recent_jobs") or [])],
        job_status_counts=data.get("job_status_counts") or {},
    )


@router.get("/models", response_model=List[DefenderModelInfo], summary="List Defender model registry entries")
async def list_models(
    domain: Optional[str] = Query(None),
    stage: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user=Depends(require_role("reviewer")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> List[DefenderModelInfo]:
    rows = service.list_models(db=db, tenant_id=tenant_ctx.tenant_id, domain=domain, stage=stage, limit=limit)
    return [DefenderModelInfo.model_validate(row) for row in rows]


@router.post("/train", response_model=DefenderRetrainResponse, summary="Run Defender retraining and register candidates")
async def retrain_defender_models(
    request: Request,
    payload: DefenderRetrainRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("defender.train.run")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> DefenderRetrainResponse:
    job = service.create_training_job(
        db=db,
        tenant_id=tenant_ctx.tenant_id,
        domain=payload.domain,
        min_feedback_samples=payload.min_feedback_samples,
        promote_if_better=payload.promote_if_better,
        requested_by=current_user.id,
        notes=payload.notes,
    )
    job = service.run_training_job(db=db, job_id=job.id, tenant_id=tenant_ctx.tenant_id)
    result_rows = (job.result or {}).get("results") or []
    results = [DefenderRetrainResult(**row) for row in result_rows]
    success = all(r.status not in {"error"} for r in results)

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="defender.train.run",
        resource_type="defender_training_job",
        resource_id=job.id,
        details={
            "domain": payload.domain,
            "min_feedback_samples": payload.min_feedback_samples,
            "promote_if_better": payload.promote_if_better,
            "result_count": len(results),
            "status": job.status,
        },
        success=success,
        tenant_id=tenant_ctx.tenant_id,
    )

    return DefenderRetrainResponse(
        status="ok",
        job_id=job.id,
        results=results,
    )


@router.get("/train/jobs", response_model=List[DefenderTrainingJobInfo], summary="List Defender retraining jobs")
async def list_training_jobs(
    domain: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user=Depends(require_role("reviewer")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> List[DefenderTrainingJobInfo]:
    rows = service.list_training_jobs(db=db, tenant_id=tenant_ctx.tenant_id, domain=domain, status=status, limit=limit)
    return [DefenderTrainingJobInfo.model_validate(row) for row in rows]


@router.get("/train/jobs/{job_id}", response_model=DefenderTrainingJobInfo, summary="Get Defender retraining job by id")
async def get_training_job(
    job_id: str,
    db: Session = Depends(get_db),
    _user=Depends(require_role("reviewer")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> DefenderTrainingJobInfo:
    row = service.get_training_job(db=db, job_id=job_id, tenant_id=tenant_ctx.tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Training job not found: {job_id}")
    return DefenderTrainingJobInfo.model_validate(row)


@router.post("/models/promote", response_model=DefenderModelInfo, summary="Promote a candidate model to active")
async def promote_defender_model(
    request: Request,
    payload: DefenderPromoteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("defender.model.promote")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> DefenderModelInfo:
    try:
        row = service.promote_model(
            db=db,
            registry_id=payload.registry_id,
            notes=payload.notes,
            force=payload.force,
            tenant_id=tenant_ctx.tenant_id,
        )
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="defender.model.promote",
            resource_type="defender_model_registry",
            resource_id=row.id,
            details={"domain": row.domain, "version": row.version, "force": payload.force},
            success=True,
            tenant_id=tenant_ctx.tenant_id,
        )
        return DefenderModelInfo.model_validate(row)
    except ValueError as exc:
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="defender.model.promote",
            resource_type="defender_model_registry",
            resource_id=payload.registry_id,
            details={"force": payload.force, "error": str(exc)},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error(f"Failed to promote model: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to promote model")


@router.post("/models/rollback", response_model=DefenderRollbackResponse, summary="Rollback active model for a domain")
async def rollback_defender_model(
    request: Request,
    payload: DefenderRollbackRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("defender.model.rollback")),
    service: DefenderAIService = Depends(get_defender_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> DefenderRollbackResponse:
    try:
        result = service.rollback_model(
            db=db,
            domain=payload.domain,
            target_registry_id=payload.target_registry_id,
            notes=payload.notes,
            tenant_id=tenant_ctx.tenant_id,
        )
        active_registry = DefenderModelInfo.model_validate(result["active_registry"])
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="defender.model.rollback",
            resource_type="defender_model_registry",
            resource_id=active_registry.id,
            details={
                "domain": payload.domain,
                "rolled_back_from_registry_id": result.get("rolled_back_from_registry_id"),
                "target_registry_id": payload.target_registry_id,
            },
            success=True,
            tenant_id=tenant_ctx.tenant_id,
        )
        return DefenderRollbackResponse(
            domain=payload.domain,
            rolled_back_from_registry_id=result.get("rolled_back_from_registry_id"),
            active_registry=active_registry,
        )
    except ValueError as exc:
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="defender.model.rollback",
            resource_type="defender_model_registry",
            resource_id=payload.target_registry_id or payload.domain,
            details={"domain": payload.domain, "error": str(exc)},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error(f"Failed to rollback model: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to rollback model")


@router.get("/spam-autopipeline/status", summary="Get spam autopipeline scheduler status")
async def get_spam_autopipeline_status(
    _user=Depends(require_role("reviewer")),
    service: SpamAutopipelineService = Depends(get_spam_autopipeline_service),
):
    return service.status()


@router.post("/spam-autopipeline/run-now", summary="Run spam autopipeline immediately")
async def run_spam_autopipeline_now(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("defender.spam.autopipeline.run")),
    service: SpamAutopipelineService = Depends(get_spam_autopipeline_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    result = await service.run_now(trigger="manual")
    status = str(result.get("status") or "").lower()
    success = status == "ok"
    if status in {"busy", "disabled"}:
        success = False

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="defender.spam.autopipeline.run",
        resource_type="spam_autopipeline",
        resource_id="global",
        details={
            "status": status,
            "trigger": result.get("trigger"),
            "error": result.get("error"),
        },
        success=success,
        tenant_id=tenant_ctx.tenant_id,
    )

    if status == "busy":
        raise HTTPException(status_code=409, detail="Spam autopipeline run already in progress.")
    if status == "disabled":
        raise HTTPException(status_code=400, detail="Spam autopipeline is disabled.")
    if not success:
        raise HTTPException(status_code=500, detail={"message": "Spam autopipeline failed", "result": result})

    return result
