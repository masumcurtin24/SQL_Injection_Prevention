import io
import sys
import zipfile
from pathlib import Path

import pytest
from starlette.datastructures import UploadFile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.alerts_service import AlertsService
from backend.services.file_analysis_service import FileAnalysisService


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


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_text_script_disguised_as_pdf_is_blocked_for_review():
    svc = _service()
    payload = b"powershell -c \"New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);\""

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="statement.pdf"),
    )

    overall = result["overall_assessment"]
    details = result["file_details"]["malware_scan"].get("scan_details") or {}
    verdict = result.get("structured_verdict") or {}

    assert overall["recommended_action"] in {"FLAG_FOR_REVIEW_BLOCK", "BLOCK_AND_QUARANTINE"}
    assert "safe" not in str(overall["overall_status"]).lower()
    mismatch = (details.get("file_signature") or {}).get("extension_mismatch") or {}
    assert mismatch.get("dangerous_signature") is True
    assert mismatch.get("signature", {}).get("kind") == "script_text"
    assert any(item.get("code") == "extension_content_mismatch" for item in verdict.get("evidence_items") or [])


@pytest.mark.asyncio
async def test_powershell_socket_listener_text_is_not_allowed():
    svc = _service()
    payload = b"powershell -c \"New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);\""

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="meeting_notes.txt"),
    )

    overall = result["overall_assessment"]
    details = result["file_details"]["malware_scan"].get("scan_details") or {}

    assert overall["recommended_action"] == "FLAG_FOR_REVIEW_BLOCK"
    assert "powershell_socket_listener" in set(details.get("exec_markers") or [])


@pytest.mark.asyncio
async def test_benign_macro_container_without_risky_behavior_is_reviewed_not_blocked():
    svc = _service()
    payload = _zip_bytes(
        {
            "[Content_Types].xml": b"<Types></Types>",
            "word/document.xml": b"Signed macro for monthly report generation.",
            "word/vbaProject.bin": b"Sub AutoOpen()\n' approved formatting macro\nEnd Sub",
        }
    )

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="finance_template.xlsm"),
    )

    overall = result["overall_assessment"]
    details = result["file_details"]["malware_scan"].get("scan_details") or {}
    macro = details.get("macro") or {}

    assert overall["recommended_action"] == "FLAG_FOR_REVIEW"
    assert overall["risk_score"] < 0.80
    assert "critical" not in str(overall["overall_status"]).lower()
    assert macro.get("present") is True
    assert macro.get("risky") is False
    assert (details.get("macro_defense") or {}).get("recommended_handling") == "review"


@pytest.mark.asyncio
async def test_macro_with_shell_or_powershell_behavior_is_flagged():
    svc = _service()
    payload = _zip_bytes(
        {
            "[Content_Types].xml": b"<Types></Types>",
            "word/document.xml": b"urgent invoice",
            "word/vbaProject.bin": b'CreateObject("Wscript.Shell").Run "powershell -enc AAA="',
        }
    )

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="invoice.docm"),
    )

    overall = result["overall_assessment"]
    details = result["file_details"]["malware_scan"].get("scan_details") or {}
    macro = details.get("macro") or {}

    assert overall["recommended_action"] == "BLOCK_REQUEST"
    assert str(overall["overall_status"]) in {"Risky Macro Detected", "Critical Macro Behaviour Detected"}
    assert macro.get("risky") is True
    assert {"powershell", "wscript.shell"}.intersection(set(macro.get("indicators") or []))


@pytest.mark.asyncio
async def test_archive_with_high_risk_script_entry_is_not_allowed():
    svc = _service()
    payload = _zip_bytes(
        {
            "docs/readme.txt": b"Deployment notes",
            "scripts/install.ps1": b"Write-Host 'maintenance task'",
        }
    )

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="support_bundle.zip"),
    )

    overall = result["overall_assessment"]
    archive = ((result["file_details"]["malware_scan"].get("scan_details") or {}).get("archive") or {})

    assert overall["recommended_action"] == "FLAG_FOR_REVIEW_BLOCK"
    assert archive.get("suspicious") is True
    assert any("high_risk_entry_extension:.ps1" == reason for reason in archive.get("suspicious_reasons") or [])


@pytest.mark.asyncio
async def test_plain_benign_zip_remains_allowed():
    svc = _service()
    payload = _zip_bytes(
        {
            "docs/readme.txt": b"Quarterly archive manifest",
            "reports/summary.txt": b"Business summary and approval notes",
        }
    )

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="records_bundle.zip"),
    )

    overall = result["overall_assessment"]
    archive = ((result["file_details"]["malware_scan"].get("scan_details") or {}).get("archive") or {})

    assert overall["recommended_action"] == "ALLOW_UPLOAD"
    assert archive.get("suspicious") is False
