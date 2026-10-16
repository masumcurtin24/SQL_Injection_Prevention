# backend/server/routers/file_analyzer_router.py
import asyncio
import inspect
import time
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Query, status

from backend.services.file_analysis_service import FileAnalysisService
from backend.services.file_scan_queue_service import BaseFileScanQueueService
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.utils.logging_utils import setup_logger
from backend.server.schemas.responses import (
    FileAnalysisResponse,
    FileScanJobAcceptedResponse,
    FileScanJobStatusResponse,
    FileScanQueueStatsResponse,
)
from pathlib import Path
import os
try:
    import yara  # type: ignore
except Exception:
    yara = None  # YARA may not be present in some envs

logger = setup_logger(__name__)
router = APIRouter()
DEFAULT_SYNC_WAIT_TIMEOUT_SECONDS = max(5.0, float(os.getenv("FILE_SCAN_SYNC_WAIT_TIMEOUT_SECONDS", "120")))
DEFAULT_SYNC_POLL_INTERVAL_MS = max(50, int(os.getenv("FILE_SCAN_SYNC_POLL_INTERVAL_MS", "200")))


def _coerce_job_result_payload(result: Any) -> Dict[str, Any]:
    if isinstance(result, dict):
        return result
    if hasattr(result, "model_dump"):
        try:
            return result.model_dump(mode="json")  # type: ignore[call-arg]
        except Exception:
            try:
                return result.model_dump()  # type: ignore[call-arg]
            except Exception:
                return {}
    return {}


def _enqueue_supports_tenant(queue_service: BaseFileScanQueueService) -> bool:
    try:
        sig = inspect.signature(queue_service.enqueue)
    except (TypeError, ValueError):
        return True
    if "tenant_id" in sig.parameters:
        return True
    return any(param.kind == inspect.Parameter.VAR_KEYWORD for param in sig.parameters.values())


async def _enqueue_job(
    queue_service: BaseFileScanQueueService,
    *,
    filename: str,
    file_bytes: bytes,
    tenant_id: str,
) -> Dict[str, Any]:
    if _enqueue_supports_tenant(queue_service):
        return await queue_service.enqueue(filename=filename, file_bytes=file_bytes, tenant_id=tenant_id)
    return await queue_service.enqueue(filename=filename, file_bytes=file_bytes)

def get_file_analysis_service() -> FileAnalysisService:
    """Dependency injector that retrieves the singleton instance created at startup."""
    try:
        instance = FileAnalysisService.get_instance()
        if not instance.are_resources_loaded():
            # Attempt a one-time recovery: recompile YARA from the rules directory if available
            if yara is not None:
                try:
                    backend_dir = Path(__file__).resolve().parents[2]
                    rules_dir = backend_dir / 'yara_rules'
                    if rules_dir.is_dir():
                        file_map = {f.name: str(f) for f in rules_dir.glob('*.yar')}
                        if file_map:
                            compiled = yara.compile(filepaths=file_map)
                            # Set on instance (best-effort recovery)
                            setattr(instance, '_yara_rules', compiled)
                            # Recheck
                            if instance.are_resources_loaded():
                                logger.info("FileAnalysisService: YARA rules recovered via router fallback.")
                                return instance
                except Exception as e:
                    logger.error(f"FileAnalysisService: YARA recovery failed: {e}")
            # If still not ready, decide based on strict mode
            strict = os.getenv('FILE_ANALYSIS_STRICT_INIT', 'false').strip().lower() in {"1","true","yes","y"}
            if strict:
                raise HTTPException(status_code=503, detail="File Analysis resources are not available.")
            logger.warning("FileAnalysisService: proceeding without full resources (strict mode disabled).")
            return instance
        return instance
    except RuntimeError as e:
        logger.critical(f"CRITICAL: {e}")
        raise HTTPException(status_code=503, detail="File Analysis Service is not initialized.")


def get_file_scan_queue_service(request: Request) -> BaseFileScanQueueService:
    instance = getattr(request.app.state, "file_scan_queue_service", None)
    if instance is None:
        raise HTTPException(status_code=503, detail="File scan queue service is not initialized.")
    return instance


@router.post("/file", response_model=FileAnalysisResponse, summary="Upload and analyze a file")
async def analyze_uploaded_file(
    file: UploadFile = File(...),
    queue_service: BaseFileScanQueueService = Depends(get_file_scan_queue_service),
    _service: FileAnalysisService = Depends(get_file_analysis_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
    wait_timeout_seconds: float = Query(
        DEFAULT_SYNC_WAIT_TIMEOUT_SECONDS,
        ge=1.0,
        le=600.0,
        description="Max seconds to wait for queued file scan completion.",
    ),
    poll_interval_ms: int = Query(
        DEFAULT_SYNC_POLL_INTERVAL_MS,
        ge=50,
        le=5000,
        description="Polling interval in milliseconds while waiting for queued scan completion.",
    ),
):
    """
    Queue-first synchronous file scan:
    1) enqueue upload into file-scan queue
    2) wait for terminal state and return completed analysis payload
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="File has no filename.")

    logger.info(f"API endpoint /file received request for analysis of file: '{file.filename}'")
    
    try:
        stats_payload = await queue_service.stats()
        if stats_payload.get("processor_enabled") is False:
            raise HTTPException(
                status_code=503,
                detail="File scan processor is disabled. Use /file/queue and run a dedicated processor worker.",
            )

        payload = await file.read()
        if not payload:
            raise HTTPException(status_code=400, detail="Empty file payload.")

        accepted_job = await _enqueue_job(
            queue_service,
            filename=file.filename,
            file_bytes=payload,
            tenant_id=tenant_ctx.tenant_id,
        )
        job_id = str(accepted_job.get("job_id") or "")
        if not job_id:
            raise HTTPException(status_code=500, detail="Queue did not return a valid job id.")

        poll_seconds = max(0.05, poll_interval_ms / 1000.0)
        deadline = time.monotonic() + wait_timeout_seconds

        while True:
            job = await queue_service.get_job(job_id)
            if not job:
                raise HTTPException(
                    status_code=500,
                    detail=f"Queued job '{job_id}' could not be found while waiting for completion.",
                )
            job_tenant_id = str(job.get("tenant_id") or "").strip()
            if job_tenant_id and job_tenant_id != tenant_ctx.tenant_id:
                raise HTTPException(status_code=404, detail=f"Queued job '{job_id}' not found.")

            job_status = str(job.get("status") or "").lower()
            if job_status == "completed":
                result_payload = _coerce_job_result_payload(job.get("result"))
                if not result_payload:
                    raise HTTPException(
                        status_code=500,
                        detail=f"Queued job '{job_id}' completed without a valid result payload.",
                    )
                return FileAnalysisResponse.model_validate(result_payload)

            if job_status in {"failed", "dead_letter"}:
                raise HTTPException(
                    status_code=500,
                    detail=f"Queued job '{job_id}' failed with status '{job_status}': {job.get('error') or 'unknown error'}",
                )

            if job_status not in {"queued", "processing"}:
                logger.warning(
                    "File scan queued job has unexpected status while waiting (job_id=%s status=%s)",
                    job_id,
                    job_status,
                )

            if time.monotonic() >= deadline:
                raise HTTPException(
                    status_code=504,
                    detail={
                        "message": "Timed out waiting for queued file analysis result.",
                        "job_id": job_id,
                        "status": job_status or "unknown",
                    },
                )

            await asyncio.sleep(poll_seconds)
    except RuntimeError as ex:
        if str(ex) == "queue_full":
            raise HTTPException(status_code=503, detail="File scan queue is full. Retry later.")
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during file analysis for '{file.filename}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An unexpected internal error occurred during file analysis.")


@router.post(
    "/file/queue",
    response_model=FileScanJobAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue file analysis job",
)
async def queue_file_analysis(
    file: UploadFile = File(...),
    queue_service: BaseFileScanQueueService = Depends(get_file_scan_queue_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="File has no filename.")

    logger.info(f"API endpoint /file/queue received request for file: '{file.filename}'")
    try:
        payload = await file.read()
        if not payload:
            raise HTTPException(status_code=400, detail="Empty file payload.")
        job = await _enqueue_job(
            queue_service,
            filename=file.filename,
            file_bytes=payload,
            tenant_id=tenant_ctx.tenant_id,
        )
        return FileScanJobAcceptedResponse(**job)
    except RuntimeError as ex:
        if str(ex) == "queue_full":
            raise HTTPException(status_code=503, detail="File scan queue is full. Retry later.")
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to queue file analysis for '{file.filename}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to queue file analysis.")


@router.get(
    "/file/jobs/{job_id}",
    response_model=FileScanJobStatusResponse,
    summary="Get file scan job status/result",
)
async def get_file_scan_job(
    job_id: str,
    queue_service: BaseFileScanQueueService = Depends(get_file_scan_queue_service),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    job = await queue_service.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job_tenant_id = str(job.get("tenant_id") or "").strip()
    if job_tenant_id and job_tenant_id != tenant_ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")
    return FileScanJobStatusResponse(**job)


@router.get(
    "/file/queue/stats",
    response_model=FileScanQueueStatsResponse,
    summary="Get file scan queue runtime stats",
)
async def get_file_scan_queue_stats(
    queue_service: BaseFileScanQueueService = Depends(get_file_scan_queue_service),
):
    stats_payload = await queue_service.stats()
    return FileScanQueueStatsResponse(**stats_payload)


@router.get(
    "/file/dynamic/provider-status",
    summary="Get file dynamic-analysis provider runtime status",
)
async def get_file_dynamic_provider_status(
    service: FileAnalysisService = Depends(get_file_analysis_service),
):
    return service.get_dynamic_provider_status()

