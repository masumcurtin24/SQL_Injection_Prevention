# backend/server/routers/spam_analyzer_router.py
import asyncio
import os
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.core.models import User
from backend.server.schemas.requests import EmailAnalysisRequest
from backend.server.schemas.feedback import SpamFeedbackRequest
from backend.server.schemas.responses import EmailAnalysisResponse
from backend.services.defender_ai_service import DefenderAIService
from backend.services.spam_detection_service import SpamDetectionService
from backend.server.deps.auth import require_role
from backend.server.deps.policy import require_policy
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.utils.audit import write_audit
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)
router = APIRouter()

def get_spam_detection_service() -> SpamDetectionService:
    """Dependency injector that retrieves the singleton instance created at startup."""
    try:
        instance = SpamDetectionService.get_instance()
        if not instance.is_model_loaded():
             raise HTTPException(status_code=503, detail="Spam Detection model is not available.")
        return instance
    except RuntimeError as e:
        logger.critical(f"CRITICAL: {e}")
        raise HTTPException(status_code=503, detail="Spam Detection Service is not initialized.")

@router.post("/email", response_model=EmailAnalysisResponse, summary="Analyze Email Content for Spam")
async def analyze_email_content_endpoint(
    request_body: EmailAnalysisRequest,
    db: Session = Depends(get_db),
    service: SpamDetectionService = Depends(get_spam_detection_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> EmailAnalysisResponse:
    if not request_body.body_text or not request_body.body_text.strip():
        raise HTTPException(status_code=400, detail="Email body_text cannot be empty.")
    
    analysis_result_dict = service.analyze_email(
        db=db,
        email_data=request_body,
        tenant_id=tenant_ctx.tenant_id,
    )
    return EmailAnalysisResponse(**analysis_result_dict)

@router.post("/feedback", summary="Submit labeled feedback for online spam learner")
async def submit_spam_feedback(
    request_body: SpamFeedbackRequest,
    db: Session = Depends(get_db),
    service: SpamDetectionService = Depends(get_spam_detection_service),
    _user=Depends(require_role("analyst")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    text = f"{request_body.subject or ''} {request_body.body_text}".strip()
    if not text:
        raise HTTPException(status_code=400, detail="Empty feedback text")
    try:
        updated = service.submit_feedback(text=text, label=request_body.label)

        try:
            defender_service = DefenderAIService.get_instance()
        except Exception:
            defender_service = DefenderAIService()

        # This endpoint is used for analyst correction; when predicted_label is not provided,
        # infer the opposite class so Defender can track FN/FP signals.
        inferred_predicted = request_body.predicted_label
        if not inferred_predicted:
            inferred_predicted = "Ham" if request_body.label == "Spam" else "Spam"

        defender_feedback = defender_service.submit_spam_feedback(
            db=db,
            tenant_id=tenant_ctx.tenant_id,
            body_text=request_body.body_text,
            subject=request_body.subject,
            sender_email=request_body.sender_email,
            true_label=request_body.label,
            predicted_label=inferred_predicted,
            confidence=request_body.confidence,
            analysis_id=request_body.analysis_id,
            source=request_body.source,
            notes=request_body.notes,
        )

        response = {"status": "ok", **updated, "defender_feedback": defender_feedback}
        auto = defender_feedback.get("auto_retrain") if isinstance(defender_feedback, dict) else None
        if auto is not None:
            response["auto_retrain"] = auto
        return response
    except Exception as e:
        logger.error(f"Feedback processing failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to process feedback")

@router.get("/settings", summary="Get spam analyzer settings")
async def get_spam_settings(
    service: SpamDetectionService = Depends(get_spam_detection_service)
):
    return service.get_settings()

@router.put(
    "/settings",
    summary="Update spam analyzer settings (in-memory overrides)",
)
async def update_spam_settings(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("spam.settings.update")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
    service: SpamDetectionService = Depends(get_spam_detection_service),
):
    before = service.get_settings()
    try:
        updated = service.set_settings(
            final_threshold=payload.get("final_threshold"),
            suspicious_tlds=payload.get("suspicious_tlds"),
            thresholds=payload.get("thresholds"),
            feature_weights=payload.get("feature_weights"),
            calibration=payload.get("calibration"),
            allow_threshold=payload.get("allow_threshold"),
            suspicious_threshold=payload.get("suspicious_threshold"),
            block_threshold=payload.get("block_threshold"),
            ood_threshold=payload.get("ood_threshold"),
        )
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.settings.update",
            resource_type="config",
            resource_id="spam-settings",
            details={
                "changed_keys": sorted(list(payload.keys())),
                "before_thresholds": before.get("thresholds"),
                "after_thresholds": updated.get("thresholds"),
                "before_feature_weights": before.get("feature_weights"),
                "after_feature_weights": updated.get("feature_weights"),
            },
            success=True,
            tenant_id=tenant_ctx.tenant_id,
        )
        return updated
    except ValueError as e:
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.settings.update",
            resource_type="config",
            resource_id="spam-settings",
            details={"changed_keys": sorted(list(payload.keys())), "error": str(e)},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=400, detail=str(e))

@router.post(
    "/blocklist",
    summary="Upload and reload domain blocklist",
)
async def upload_blocklist(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("spam.blocklist.upload")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
    service: SpamDetectionService = Depends(get_spam_detection_service),
):
    try:
        content = await file.read()
        bl_path = os.getenv("REPUTATION_BLOCKLIST_PATH", "backend/data/reputation/blocklist.txt")
        os.makedirs(os.path.dirname(bl_path), exist_ok=True)
        with open(bl_path, "wb") as f:
            f.write(content)
        result = service.reload_blocklist(bl_path)
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.blocklist.upload",
            resource_type="config",
            resource_id="spam-blocklist",
            details={
                "filename": str(file.filename or ""),
                "size_bytes": len(content),
                "path": bl_path,
                "blocklist_count": result.get("blocklist_count"),
            },
            success=True,
            tenant_id=tenant_ctx.tenant_id,
        )
        return result
    except Exception as e:
        logger.error(f"Blocklist upload failed: {e}", exc_info=True)
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.blocklist.upload",
            resource_type="config",
            resource_id="spam-blocklist",
            details={"filename": str(file.filename or ""), "error": str(e)},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=500, detail="Failed to upload blocklist")


@router.post(
    "/reputation/reload",
    summary="Reload spam reputation maps from configured files",
)
async def reload_reputation_assets(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("spam.settings.update")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
    service: SpamDetectionService = Depends(get_spam_detection_service),
):
    try:
        rep = service.reload_reputation_scores()
        allow = service.reload_allowlist()
        block = service.reload_blocklist()
        fraud = service.reload_fraud_pattern_pack()
        payload = {
            "status": "ok",
            "reputation": rep,
            "allowlist": allow,
            "blocklist": block,
            "fraud_patterns": fraud,
        }
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.reputation.reload",
            resource_type="config",
            resource_id="spam-reputation",
            details={
                "reputation_entries": rep.get("reputation_entries"),
                "allowlist_count": allow.get("allowlist_count"),
                "blocklist_count": block.get("blocklist_count"),
                "fraud_pattern_count": fraud.get("pattern_count"),
            },
            success=True,
            tenant_id=tenant_ctx.tenant_id,
        )
        return payload
    except Exception as e:
        logger.error(f"Reputation reload failed: {e}", exc_info=True)
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.reputation.reload",
            resource_type="config",
            resource_id="spam-reputation",
            details={"error": str(e)},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=500, detail="Failed to reload reputation assets")


@router.post(
    "/reputation/update",
    summary="Ingest upstream reputation feeds, then reload scores",
)
async def update_reputation_assets(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("spam.settings.update")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
    service: SpamDetectionService = Depends(get_spam_detection_service),
):
    try:
        from backend.scripts.update_spam_reputation_feed import main as update_reputation_feed_main

        exit_code = await asyncio.to_thread(update_reputation_feed_main)
        if int(exit_code) != 0:
            raise RuntimeError(f"updater_exit_code={exit_code}")

        rep = service.reload_reputation_scores()
        allow = service.reload_allowlist()
        block = service.reload_blocklist()
        fraud = service.reload_fraud_pattern_pack()
        payload = {
            "status": "ok",
            "upstream_ingest": {"exit_code": int(exit_code)},
            "reputation": rep,
            "allowlist": allow,
            "blocklist": block,
            "fraud_patterns": fraud,
        }
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.reputation.update",
            resource_type="config",
            resource_id="spam-reputation",
            details={
                "upstream_exit_code": int(exit_code),
                "reputation_entries": rep.get("reputation_entries"),
                "allowlist_count": allow.get("allowlist_count"),
                "blocklist_count": block.get("blocklist_count"),
                "fraud_pattern_count": fraud.get("pattern_count"),
            },
            success=True,
            tenant_id=tenant_ctx.tenant_id,
        )
        return payload
    except Exception as e:
        logger.error(f"Reputation update failed: {e}", exc_info=True)
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.reputation.update",
            resource_type="config",
            resource_id="spam-reputation",
            details={"error": str(e)},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=500, detail="Failed to update reputation assets")


@router.post(
    "/reputation/fraud-patterns/reload",
    summary="Reload curated fraud pattern pack used for phishing detection",
)
async def reload_fraud_patterns(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("spam.settings.update")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
    service: SpamDetectionService = Depends(get_spam_detection_service),
):
    try:
        payload = {
            "status": "ok",
            "fraud_patterns": service.reload_fraud_pattern_pack(),
        }
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.fraud_patterns.reload",
            resource_type="config",
            resource_id="spam-fraud-patterns",
            details={
                "pattern_count": (payload.get("fraud_patterns") or {}).get("pattern_count"),
                "path": (payload.get("fraud_patterns") or {}).get("path"),
            },
            success=True,
            tenant_id=tenant_ctx.tenant_id,
        )
        return payload
    except Exception as e:
        logger.error(f"Fraud pattern reload failed: {e}", exc_info=True)
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="spam.fraud_patterns.reload",
            resource_type="config",
            resource_id="spam-fraud-patterns",
            details={"error": str(e)},
            success=False,
            tenant_id=tenant_ctx.tenant_id,
        )
        raise HTTPException(status_code=500, detail="Failed to reload fraud pattern pack")
