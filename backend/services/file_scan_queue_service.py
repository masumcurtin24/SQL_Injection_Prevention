import asyncio
import io
import inspect
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from starlette.datastructures import UploadFile

from backend.core.database import SessionLocal
from backend.core.models import DEFAULT_TENANT_ID
from backend.services.file_analysis_service import FileAnalysisService
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


JobAnalyzer = Callable[..., Awaitable[Dict[str, Any]]]
JOB_STATUSES = {"queued", "processing", "completed", "failed", "dead_letter"}


@dataclass
class _QueueJob:
    job_id: str
    filename: str
    tenant_id: str
    file_bytes: Optional[bytes]
    max_attempts: int
    status: str = "queued"
    attempts: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class BaseFileScanQueueService:
    async def start(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def stop(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def enqueue(self, *, filename: str, file_bytes: bytes, tenant_id: Optional[str] = None) -> Dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError

    async def stats(self) -> Dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError


class FileScanQueueService(BaseFileScanQueueService):
    """
    In-memory async queue for file scans.

    Jobs move through:
    queued -> processing -> completed
                           -> failed -> queued (retry)
                           -> dead_letter (after max attempts)
    """

    def __init__(
        self,
        *,
        worker_count: Optional[int] = None,
        max_queue_size: Optional[int] = None,
        max_attempts: Optional[int] = None,
        retry_backoff_seconds: Optional[float] = None,
        job_retention_seconds: Optional[int] = None,
        analyzer: Optional[JobAnalyzer] = None,
    ):
        self._worker_count = max(1, int(worker_count or os.getenv("FILE_SCAN_QUEUE_WORKERS", "1")))
        self._max_queue_size = max(1, int(max_queue_size or os.getenv("FILE_SCAN_QUEUE_MAX_SIZE", "128")))
        self._max_attempts = max(1, int(max_attempts or os.getenv("FILE_SCAN_QUEUE_MAX_ATTEMPTS", "2")))
        self._retry_backoff_seconds = max(
            0.0, float(retry_backoff_seconds if retry_backoff_seconds is not None else os.getenv("FILE_SCAN_QUEUE_RETRY_BACKOFF_SECONDS", "0.25"))
        )
        self._job_retention_seconds = max(
            60, int(job_retention_seconds or os.getenv("FILE_SCAN_QUEUE_JOB_RETENTION_SECONDS", "3600"))
        )

        self._queue: asyncio.Queue[Optional[str]] = asyncio.Queue(maxsize=self._max_queue_size)
        self._jobs: Dict[str, _QueueJob] = {}
        self._workers: List[asyncio.Task] = []
        self._lock = asyncio.Lock()
        self._running = False
        self._analyzer = analyzer or self._analyze_with_file_service
        self._analyzer_supports_tenant = self._supports_tenant_arg(self._analyzer)

    @staticmethod
    def _supports_tenant_arg(analyzer: JobAnalyzer) -> bool:
        try:
            sig = inspect.signature(analyzer)
        except (TypeError, ValueError):
            return True
        params = list(sig.parameters.values())
        if any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params):
            return True
        positional = [
            p
            for p in params
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        return len(positional) >= 3

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        for idx in range(self._worker_count):
            self._workers.append(asyncio.create_task(self._worker_loop(idx)))
        logger.info(
            "FileScanQueueService started (workers=%s, queue_size=%s, max_attempts=%s)",
            self._worker_count,
            self._max_queue_size,
            self._max_attempts,
        )

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        for _ in self._workers:
            await self._queue.put(None)
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info("FileScanQueueService stopped")

    async def enqueue(self, *, filename: str, file_bytes: bytes, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        if not filename:
            raise ValueError("filename is required")
        if file_bytes is None:
            raise ValueError("file_bytes is required")
        if self._queue.full():
            raise RuntimeError("queue_full")
        effective_tenant_id = str(tenant_id or "").strip() or DEFAULT_TENANT_ID

        job = _QueueJob(
            job_id=f"fsq-{uuid.uuid4()}",
            filename=filename,
            tenant_id=effective_tenant_id,
            file_bytes=file_bytes,
            max_attempts=self._max_attempts,
        )
        async with self._lock:
            self._purge_expired_locked()
            self._jobs[job.job_id] = job
        await self._queue.put(job.job_id)
        return await self.get_job(job.job_id) or {}

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return self._serialize_job(job)

    async def stats(self) -> Dict[str, Any]:
        async with self._lock:
            counts = {k: 0 for k in JOB_STATUSES}
            for j in self._jobs.values():
                counts[j.status] = counts.get(j.status, 0) + 1
            payload = {
                "running": self._running,
                "worker_count": self._worker_count,
                "queue_max_size": self._max_queue_size,
                "queue_size": self._queue.qsize(),
                "jobs_total": len(self._jobs),
                "status_counts": counts,
                "backend": "memory",
                "processor_enabled": True,
            }
            return payload

    async def _worker_loop(self, worker_idx: int) -> None:
        while True:
            job_id = await self._queue.get()
            if job_id is None:
                self._queue.task_done()
                break
            try:
                await self._process_job(job_id, worker_idx)
            except Exception as exc:
                logger.error("File queue worker %s failed for job %s: %s", worker_idx, job_id, exc, exc_info=True)
            finally:
                self._queue.task_done()

    async def _process_job(self, job_id: str, worker_idx: int) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            if job.file_bytes is None:
                job.status = "dead_letter"
                job.error = "missing_payload"
                job.completed_at = datetime.now(timezone.utc)
                job.updated_at = job.completed_at
                return
            job.status = "processing"
            job.attempts += 1
            job.started_at = datetime.now(timezone.utc)
            job.updated_at = job.started_at

            filename = job.filename
            payload = bytes(job.file_bytes)
            tenant_id = job.tenant_id

        try:
            if self._analyzer_supports_tenant:
                result = await self._analyzer(filename, payload, tenant_id)
            else:
                result = await self._analyzer(filename, payload)
        except Exception as exc:
            err = str(exc)[:500]
            should_retry = False
            async with self._lock:
                job = self._jobs.get(job_id)
                if not job:
                    return
                job.error = err
                job.updated_at = datetime.now(timezone.utc)
                if job.attempts < job.max_attempts:
                    job.status = "queued"
                    should_retry = True
                else:
                    job.status = "dead_letter"
                    job.completed_at = datetime.now(timezone.utc)
                    job.file_bytes = None

            if should_retry:
                logger.warning(
                    "File queue job retry scheduled (job_id=%s worker=%s attempt=%s/%s error=%s)",
                    job_id,
                    worker_idx,
                    job.attempts,
                    job.max_attempts,
                    err,
                )
                if self._retry_backoff_seconds > 0:
                    await asyncio.sleep(self._retry_backoff_seconds)
                await self._queue.put(job_id)
            else:
                logger.error(
                    "File queue job moved to dead_letter (job_id=%s worker=%s attempts=%s error=%s)",
                    job_id,
                    worker_idx,
                    job.attempts if job else "?",
                    err,
                )
            return

        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = "completed"
            job.result = result
            job.error = None
            job.completed_at = datetime.now(timezone.utc)
            job.updated_at = job.completed_at
            job.file_bytes = None
            self._purge_expired_locked()

    async def _analyze_with_file_service(self, filename: str, file_bytes: bytes, tenant_id: str) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            analyzer = FileAnalysisService.get_instance()
            upload = UploadFile(filename=filename, file=io.BytesIO(file_bytes))
            return await analyzer.analyze_file(db, upload, tenant_id=tenant_id)
        finally:
            db.close()

    def _purge_expired_locked(self) -> None:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self._job_retention_seconds)
        stale_ids: List[str] = []
        for job_id, job in self._jobs.items():
            terminal = job.status in {"completed", "failed", "dead_letter"}
            ref = job.completed_at or job.updated_at or job.created_at
            if terminal and ref < cutoff:
                stale_ids.append(job_id)
        for job_id in stale_ids:
            self._jobs.pop(job_id, None)

    def _serialize_job(self, job: _QueueJob) -> Dict[str, Any]:
        return {
            "job_id": job.job_id,
            "filename": job.filename,
            "tenant_id": job.tenant_id,
            "status": job.status,
            "attempts": job.attempts,
            "max_attempts": job.max_attempts,
            "created_at": job.created_at,
            "updated_at": job.updated_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "error": job.error,
            "result": job.result if job.status == "completed" else None,
        }
