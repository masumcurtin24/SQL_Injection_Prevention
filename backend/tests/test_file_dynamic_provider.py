from __future__ import annotations

import pytest
from fastapi import FastAPI
import httpx

from backend.services.file_dynamic.providers import (
    DynamicResultPayload,
    DynamicSubmissionHandle,
    FakeDynamicAnalysisProvider,
    HttpDynamicAnalysisProvider,
    NoOpDynamicAnalysisProvider,
    create_dynamic_analysis_provider,
)


@pytest.mark.asyncio
async def test_noop_provider_reports_unavailable():
    provider = NoOpDynamicAnalysisProvider()
    handle = await provider.submit(sample_ref="sample-1", sample_bytes=b"x", metadata={"filename": "a.txt"})
    assert isinstance(handle, DynamicSubmissionHandle)
    assert handle.status == "unavailable"
    assert handle.submission_id is None


@pytest.mark.asyncio
async def test_fake_provider_submit_status_and_result_flow():
    provider = FakeDynamicAnalysisProvider(completion_polls=1, fail=False)
    handle = await provider.submit(sample_ref="sample-2", sample_bytes=b"content", metadata={"filename": "b.txt"})
    assert handle.status == "submitted"
    assert handle.submission_id

    snap1 = await provider.get_status(handle.submission_id)
    assert snap1.status in {"submitted", "running", "completed"}
    snap2 = await provider.get_status(handle.submission_id)
    assert snap2.status in {"running", "completed"}
    snap3 = await provider.get_status(handle.submission_id)
    assert snap3.status == "completed"

    result = await provider.fetch_result(handle.submission_id)
    assert isinstance(result, DynamicResultPayload)
    assert result.status == "completed"
    assert result.iocs


def test_dynamic_provider_factory_known_values():
    assert create_dynamic_analysis_provider("none").name == "none"
    assert create_dynamic_analysis_provider("fake").name == "fake"
    assert create_dynamic_analysis_provider("http", {"base_url": "https://sandbox.example"}).name == "http"
    # Unknown provider must fail-safe to no-op.
    assert create_dynamic_analysis_provider("unknown-provider").name == "none"


@pytest.mark.asyncio
async def test_http_provider_unavailable_when_misconfigured():
    provider = create_dynamic_analysis_provider("http", {"base_url": ""})
    assert provider.name == "http"
    diag = provider.diagnostics()
    assert diag["available"] is False
    assert diag["configured"] is False

    handle = await provider.submit(sample_ref="sample-3", sample_bytes=b"abc", metadata={"filename": "bad.txt"})
    assert handle.status == "unavailable"
    assert handle.submission_id is None


@pytest.mark.asyncio
async def test_http_provider_contract_submit_status_result():
    app = FastAPI()
    state = {"polls": 0}

    @app.post("/v1/dynamic/submit")
    async def submit(payload: dict):
        sample = payload.get("sample") or {}
        assert sample.get("content_base64")
        return {"submission_id": "job-123", "status": "submitted"}

    @app.get("/v1/dynamic/status/{submission_id}")
    async def status(submission_id: str):
        state["polls"] += 1
        if state["polls"] <= 1:
            return {"status": "running"}
        return {"status": "completed"}

    @app.get("/v1/dynamic/result/{submission_id}")
    async def result(submission_id: str):
        return {
            "status": "completed",
            "summary": "Dynamic sandbox completed.",
            "evidence_items": [
                {"code": "dyn_net", "label": "Network contact", "severity": "high", "details": {"dst": "c2.test"}}
            ],
            "iocs": [
                {"type": "domain", "value": "c2.test", "confidence": 0.9, "severity_hint": "high"},
                {"type": "ip", "value": "198.51.100.9"},
            ],
        }

    provider = HttpDynamicAnalysisProvider(
        base_url="http://dynamic.local",
        transport=httpx.ASGITransport(app=app),
        verify_tls=False,
    )
    submit_handle = await provider.submit(sample_ref="sample-4", sample_bytes=b"payload", metadata={"filename": "sample.bin"})
    assert submit_handle.status == "submitted"
    assert submit_handle.submission_id == "job-123"

    status_snap_1 = await provider.get_status("job-123")
    assert status_snap_1.status == "running"
    status_snap_2 = await provider.get_status("job-123")
    assert status_snap_2.status == "completed"

    result_payload = await provider.fetch_result("job-123")
    assert isinstance(result_payload, DynamicResultPayload)
    assert result_payload.status == "completed"
    assert len(result_payload.iocs) == 2
    assert any(ioc.ioc_type == "domain" and ioc.value == "c2.test" for ioc in result_payload.iocs)
    assert result_payload.evidence_items and result_payload.evidence_items[0].code == "dyn_net"
