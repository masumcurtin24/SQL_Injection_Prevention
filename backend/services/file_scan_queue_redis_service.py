import asyncio
import io
import inspect
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from starlette.datastructures import UploadFile

from backend.core.database import SessionLocal
from backend.core.models import DEFAULT_TENANT_ID
from backend.services.file_analysis_service import FileAnalysisService
from backend.services.file_scan_queue_service import BaseFileScanQueueService, JOB_STATUSES, JobAnalyzer
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    if hasattr(value, "model_dump"):
        try:
            return _json_safe(value.model_dump(mode="json"))  # type: ignore[call-arg]
        except Exception:
            return _json_safe(value.model_dump())  # type: ignore[call-arg]
    return value


class RedisFileScanQueueService(BaseFileScanQueueService):
    """
    Redis-backed queue with durable job metadata and payload storage.
    Supports running API and workers on separate instances.
    """

    def __init__(
        self,
        *,
        worker_count: Optional[int] = None,
        max_queue_size: Optional[int] = None,
        max_attempts: Optional[int] = None,
        retry_backoff_seconds: Optional[float] = None,
        job_retention_seconds: Optional[int] = None,
        redis_url: Optional[str] = None,
        namespace: Optional[str] = None,
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

        self._redis_url = redis_url or os.getenv("FILE_SCAN_QUEUE_REDIS_URL", "redis://localhost:6379/0")
        self._namespace = (namespace or os.getenv("FILE_SCAN_QUEUE_REDIS_NAMESPACE", "file_scan_queue")).strip()
        self._block_timeout_seconds = max(1, int(os.getenv("FILE_SCAN_QUEUE_REDIS_BLOCK_TIMEOUT_SECONDS", "1")))
        self._processor_enabled = os.getenv("FILE_SCAN_QUEUE_PROCESSOR_ENABLED", "true").strip().lower() in {"1", "true", "yes", "y"}
        self._workers: List[asyncio.Task] = []
        self._running = False
        self._redis = None
        self._analyzer = analyzer or self._analyze_with_file_service
        self._analyzer_supports_tenant = self._supports_tenant_arg(self._analyzer)

        self._queue_key = f"{self._namespace}:queue"
        self._job_key_prefix = f"{self._namespace}:job:"
        self._payload_key_prefix = f"{self._namespace}:payload:"

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
        redis_client = _load_redis_client(self._redis_url)
        await redis_client.ping()
        self._redis = redis_client
        self._running = True
        if self._processor_enabled:
            for idx in range(self._worker_count):
                self._workers.append(asyncio.create_task(self._worker_loop(idx)))
        logger.info(
            "RedisFileScanQueueService started (redis=%s namespace=%s workers=%s processor_enabled=%s)",
            self._redis_url,
            self._namespace,
            self._worker_count,
            self._processor_enabled,
        )

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        for task in self._workers:
            task.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None
        logger.info("RedisFileScanQueueService stopped")

    async def enqueue(self, *, filename: str, file_bytes: bytes, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        if not filename:
            raise ValueError("filename is required")
        if file_bytes is None:
            raise ValueError("file_bytes is required")
        effective_tenant_id = str(tenant_id or "").strip() or DEFAULT_TENANT_ID
        redis = self._require_redis()
        qsize = int(await redis.llen(self._queue_key))
        if qsize >= self._max_queue_size:
            raise RuntimeError("queue_full")

        now = datetime.now(timezone.utc).isoformat()
        job_id = f"fsq-{uuid.uuid4()}"
        job = {
            "job_id": job_id,
            "filename": filename,
            "tenant_id": effective_tenant_id,
            "status": "queued",
            "attempts": 0,
            "max_attempts": self._max_attempts,
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "completed_at": None,
            "error": None,
            "result": None,
        }
        await redis.set(self._job_key(job_id), json.dumps(job, separators=(",", ":")))
        await redis.set(self._payload_key(job_id), file_bytes)
        await redis.rpush(self._queue_key, job_id)
        return dict(job)

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        redis = self._require_redis()
        raw = await redis.get(self._job_key(job_id))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    async def stats(self) -> Dict[str, Any]:
        redis = self._require_redis()
        counts = {k: 0 for k in JOB_STATUSES}
        cursor = 0
        pattern = f"{self._job_key_prefix}*"
        total = 0
        while True:
            cursor, keys = await redis.scan(cursor=cursor, match=pattern, count=200)
            if keys:
                values = await redis.mget(keys)
                for raw in values:
                    if not raw:
                        continue
                    try:
                        payload = json.loads(raw)
                    except Exception:
                        continue
                    status = str(payload.get("status") or "")
                    if status in counts:
                        counts[status] += 1
                        total += 1
            if int(cursor) == 0:
                break

        return {
            "running": self._running,
            "worker_count": self._worker_count,
            "queue_max_size": self._max_queue_size,
            "queue_size": int(await redis.llen(self._queue_key)),
            "jobs_total": total,
            "status_counts": counts,
            "backend": "redis",
            "processor_enabled": self._processor_enabled,
            "redis_url": self._redis_url,
            "namespace": self._namespace,
        }

    async def _worker_loop(self, worker_idx: int) -> None:
        redis = self._require_redis()
        while self._running:
            try:
                item = await redis.blpop(self._queue_key, timeout=self._block_timeout_seconds)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Redis queue worker %s BLPOP failure: %s", worker_idx, exc, exc_info=True)
                await asyncio.sleep(0.2)
                continue
            if not item:
                continue
            _, job_id_raw = item
            job_id = job_id_raw.decode("utf-8", errors="ignore") if isinstance(job_id_raw, (bytes, bytearray)) else str(job_id_raw)
            try:
                await self._process_job(job_id, worker_idx)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Redis queue worker %s failed for job %s: %s", worker_idx, job_id, exc, exc_info=True)

    async def _process_job(self, job_id: str, worker_idx: int) -> None:
        redis = self._require_redis()
        job = await self.get_job(job_id)
        if not job:
            return

        job["status"] = "processing"
        job["attempts"] = int(job.get("attempts") or 0) + 1
        job["started_at"] = datetime.now(timezone.utc).isoformat()
        job["updated_at"] = job["started_at"]
        await self._persist_job(job)

        payload = await redis.get(self._payload_key(job_id))
        if payload is None:
            job["status"] = "dead_letter"
            job["error"] = "missing_payload"
            job["completed_at"] = datetime.now(timezone.utc).isoformat()
            job["updated_at"] = job["completed_at"]
            await self._persist_job(job, ttl=self._job_retention_seconds)
            return

        filename = str(job.get("filename") or "unknown.bin")
        tenant_id = str(job.get("tenant_id") or "").strip() or DEFAULT_TENANT_ID
        try:
            if self._analyzer_supports_tenant:
                result = await self._analyzer(filename, bytes(payload), tenant_id)
            else:
                result = await self._analyzer(filename, bytes(payload))
        except Exception as exc:
            err = str(exc)[:500]
            attempts = int(job.get("attempts") or 0)
            max_attempts = int(job.get("max_attempts") or self._max_attempts)
            job["error"] = err
            job["updated_at"] = datetime.now(timezone.utc).isoformat()

            if attempts < max_attempts:
                job["status"] = "queued"
                await self._persist_job(job)
                if self._retry_backoff_seconds > 0:
                    await asyncio.sleep(self._retry_backoff_seconds)
                await redis.rpush(self._queue_key, job_id)
                logger.warning(
                    "Redis queue job retry scheduled (job_id=%s worker=%s attempt=%s/%s error=%s)",
                    job_id,
                    worker_idx,
                    attempts,
                    max_attempts,
                    err,
                )
            else:
                job["status"] = "dead_letter"
                job["completed_at"] = datetime.now(timezone.utc).isoformat()
                job["updated_at"] = job["completed_at"]
                await self._persist_job(job, ttl=self._job_retention_seconds)
                await redis.delete(self._payload_key(job_id))
                logger.error(
                    "Redis queue job moved to dead_letter (job_id=%s worker=%s attempts=%s error=%s)",
                    job_id,
                    worker_idx,
                    attempts,
                    err,
                )
            return

        job["status"] = "completed"
        job["result"] = _json_safe(result)
        job["error"] = None
        job["completed_at"] = datetime.now(timezone.utc).isoformat()
        job["updated_at"] = job["completed_at"]
        await self._persist_job(job, ttl=self._job_retention_seconds)
        await redis.delete(self._payload_key(job_id))

    async def _persist_job(self, job: Dict[str, Any], ttl: Optional[int] = None) -> None:
        redis = self._require_redis()
        raw = json.dumps(_json_safe(job), separators=(",", ":"))
        key = self._job_key(str(job["job_id"]))
        if ttl:
            await redis.set(key, raw, ex=ttl)
        else:
            await redis.set(key, raw)

    async def _analyze_with_file_service(self, filename: str, file_bytes: bytes, tenant_id: str) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            analyzer = FileAnalysisService.get_instance()
            upload = UploadFile(filename=filename, file=io.BytesIO(file_bytes))
            return await analyzer.analyze_file(db, upload, tenant_id=tenant_id)
        finally:
            db.close()

    def _job_key(self, job_id: str) -> str:
        return f"{self._job_key_prefix}{job_id}"

    def _payload_key(self, job_id: str) -> str:
        return f"{self._payload_key_prefix}{job_id}"

    def _require_redis(self):
        if self._redis is None:
            raise RuntimeError("Redis queue service is not started.")
        return self._redis


def _load_redis_client(redis_url: str):
    try:
        from redis import asyncio as redis_async  # type: ignore
    except Exception as exc:
        raise RuntimeError("redis package is required for FILE_SCAN_QUEUE_BACKEND=redis") from exc
    return redis_async.from_url(redis_url, decode_responses=False)
