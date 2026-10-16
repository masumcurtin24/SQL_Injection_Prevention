from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.services.file_scan_queue_service import BaseFileScanQueueService


def _admin_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _analysis_payload(filename: str, analysis_id: str = "file-test-queued") -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "analysis_id": analysis_id,
        "analysis_timestamp": now,
        "file_details": {
            "filename": filename,
            "filesize_kb": 0.01,
            "type_validation": {
                "detected_mime_type": "text/plain",
                "is_allowed_type": True,
                "extension_provided": ".txt",
            },
            "malware_scan": {
                "is_malicious": False,
                "threat_name": None,
                "scan_engine_version": "test",
                "scan_details": {},
            },
            "ml_scan": {
                "is_suspicious_ml": False,
                "prediction_label_ml": "Benign_Text",
                "prediction_score_ml": 0.01,
            },
        },
        "overall_assessment": {
            "overall_status": "Safe",
            "risk_score": 0.01,
            "recommended_action": "ALLOW_UPLOAD",
            "reasoning": ["Test payload"],
        },
        "errors": [],
    }


class _FakeQueueService(BaseFileScanQueueService):
    def __init__(
        self,
        *,
        job_status: str = "completed",
        result_payload: Optional[Dict[str, Any]] = None,
        processor_enabled: bool = True,
    ):
        self.job_status = job_status
        self.result_payload = result_payload
        self.processor_enabled = processor_enabled
        self.job_id = "fsq-test-job"
        self.enqueued_payloads: list[Dict[str, Any]] = []

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def enqueue(self, *, filename: str, file_bytes: bytes) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        self.enqueued_payloads.append({"filename": filename, "size": len(file_bytes)})
        return {
            "job_id": self.job_id,
            "filename": filename,
            "status": "queued",
            "attempts": 0,
            "max_attempts": 2,
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        if job_id != self.job_id:
            return None
        now = datetime.now(timezone.utc)
        return {
            "job_id": job_id,
            "filename": "queued-file.txt",
            "status": self.job_status,
            "attempts": 1,
            "max_attempts": 2,
            "created_at": now,
            "updated_at": now,
            "started_at": now,
            "completed_at": now if self.job_status == "completed" else None,
            "error": None,
            "result": self.result_payload if self.job_status == "completed" else None,
        }

    async def stats(self) -> Dict[str, Any]:
        return {
            "running": True,
            "worker_count": 1,
            "queue_max_size": 128,
            "queue_size": 0,
            "jobs_total": 1,
            "status_counts": {"queued": 0, "processing": 1, "completed": 0, "failed": 0, "dead_letter": 0},
            "backend": "memory",
            "processor_enabled": self.processor_enabled,
        }


def test_analyze_file_endpoint_uses_queue_first_and_returns_completed_payload(client):
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    payload = _analysis_payload("queued-file.txt")
    fake_queue = _FakeQueueService(job_status="completed", result_payload=payload, processor_enabled=True)

    original_queue = client.app.state.file_scan_queue_service
    client.app.state.file_scan_queue_service = fake_queue
    try:
        res = client.post(
            "/api/v1/analyze-file/file",
            headers=headers,
            files={"file": ("queued-file.txt", b"hello", "text/plain")},
        )
    finally:
        client.app.state.file_scan_queue_service = original_queue

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["analysis_id"] == "file-test-queued"
    assert body["overall_assessment"]["overall_status"] == "Safe"
    assert len(fake_queue.enqueued_payloads) == 1
    assert fake_queue.enqueued_payloads[0]["filename"] == "queued-file.txt"


def test_analyze_file_endpoint_rejects_when_queue_processor_disabled(client):
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    fake_queue = _FakeQueueService(job_status="processing", result_payload=None, processor_enabled=False)

    original_queue = client.app.state.file_scan_queue_service
    client.app.state.file_scan_queue_service = fake_queue
    try:
        res = client.post(
            "/api/v1/analyze-file/file",
            headers=headers,
            files={"file": ("queued-file.txt", b"hello", "text/plain")},
        )
    finally:
        client.app.state.file_scan_queue_service = original_queue

    assert res.status_code == 503, res.text
    assert "processor is disabled" in str(res.json().get("detail") or "").lower()


def test_analyze_file_endpoint_times_out_when_job_does_not_complete(client):
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    fake_queue = _FakeQueueService(job_status="processing", result_payload=None, processor_enabled=True)

    original_queue = client.app.state.file_scan_queue_service
    client.app.state.file_scan_queue_service = fake_queue
    try:
        res = client.post(
            "/api/v1/analyze-file/file?wait_timeout_seconds=1&poll_interval_ms=50",
            headers=headers,
            files={"file": ("queued-file.txt", b"hello", "text/plain")},
        )
    finally:
        client.app.state.file_scan_queue_service = original_queue

    assert res.status_code == 504, res.text
    detail = res.json().get("detail") or {}
    assert detail.get("job_id") == fake_queue.job_id
    assert str(detail.get("status") or "").lower() == "processing"


def test_dynamic_provider_status_endpoint_returns_runtime_state(client):
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/v1/analyze-file/file/dynamic/provider-status", headers=headers)
    assert res.status_code == 200, res.text
    payload = res.json()
    assert "enabled" in payload
    assert "requested_provider" in payload
    assert "active_provider" in payload
    assert "available" in payload
    assert payload.get("readiness_state") in {
        "disabled",
        "fake",
        "misconfigured",
        "live_not_validated",
        "live_validated",
    }
    assert isinstance(payload.get("validation"), dict)
