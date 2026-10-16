import io
import sys
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
async def test_passive_pdf_with_poc_terms_does_not_auto_escalate():
    svc = _service()
    payload = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"Proof of Concept PoC function sample\n"
        + (b"A" * 96)
        + b" eval(\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF"
    )
    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="passive-report.pdf"),
    )

    overall = result["overall_assessment"]
    malware = result["file_details"]["malware_scan"]
    details = malware.get("scan_details") or {}

    assert overall["overall_status"] == "Safe"
    assert overall["recommended_action"] == "ALLOW_UPLOAD"
    assert "exploit_poc_generic_poc_terms" in (details.get("outer_yara_matches") or [])
