import os
from typing import Optional

from backend.services.file_scan_queue_redis_service import RedisFileScanQueueService
from backend.services.file_scan_queue_service import BaseFileScanQueueService, FileScanQueueService, JobAnalyzer


def create_file_scan_queue_service(*, analyzer: Optional[JobAnalyzer] = None) -> BaseFileScanQueueService:
    backend = os.getenv("FILE_SCAN_QUEUE_BACKEND", "memory").strip().lower()
    if backend in {"memory", "inmemory"}:
        return FileScanQueueService(analyzer=analyzer)
    if backend == "redis":
        return RedisFileScanQueueService(analyzer=analyzer)
    raise ValueError(f"Unsupported FILE_SCAN_QUEUE_BACKEND: {backend}")
