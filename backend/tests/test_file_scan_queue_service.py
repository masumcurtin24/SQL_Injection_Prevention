import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.file_scan_queue_service import FileScanQueueService


async def _wait_for_terminal_status(
    service: FileScanQueueService,
    job_id: str,
    *,
    timeout: float = 3.0,
) -> dict:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        job = await service.get_job(job_id)
        if job and job.get("status") in {"completed", "dead_letter"}:
            return job
        await asyncio.sleep(0.02)
    raise TimeoutError(f"Job did not finish in {timeout}s: {job_id}")


@pytest.mark.asyncio
async def test_queue_job_completes_successfully():
    async def _ok_analyzer(filename: str, payload: bytes) -> dict:
        return {"filename": filename, "size": len(payload), "overall_assessment": {"overall_status": "Safe"}}

    svc = FileScanQueueService(
        worker_count=1,
        max_queue_size=4,
        max_attempts=2,
        retry_backoff_seconds=0.01,
        analyzer=_ok_analyzer,
    )
    await svc.start()
    try:
        accepted = await svc.enqueue(filename="report.txt", file_bytes=b"hello")
        job = await _wait_for_terminal_status(svc, accepted["job_id"])
        assert job["status"] == "completed"
        assert job["result"]["overall_assessment"]["overall_status"] == "Safe"
        assert job["attempts"] == 1
        stats = await svc.stats()
        assert stats["backend"] == "memory"
        assert stats["processor_enabled"] is True
    finally:
        await svc.stop()


@pytest.mark.asyncio
async def test_queue_job_retries_then_dead_letters():
    async def _bad_analyzer(_filename: str, _payload: bytes) -> dict:
        raise RuntimeError("boom")

    svc = FileScanQueueService(
        worker_count=1,
        max_queue_size=4,
        max_attempts=2,
        retry_backoff_seconds=0.01,
        analyzer=_bad_analyzer,
    )
    await svc.start()
    try:
        accepted = await svc.enqueue(filename="fail.txt", file_bytes=b"x")
        job = await _wait_for_terminal_status(svc, accepted["job_id"])
        assert job["status"] == "dead_letter"
        assert job["attempts"] == 2
        assert "boom" in (job.get("error") or "")
        assert job["result"] is None
    finally:
        await svc.stop()
