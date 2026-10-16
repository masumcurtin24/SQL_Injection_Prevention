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
async def test_html_file_is_analyzed_not_auto_blocked_as_type():
    svc = _service()
    payload = b"<!DOCTYPE html><html><head><title>Report</title></head><body><h1>Monthly report</h1></body></html>"

    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="Report.html"),
    )

    file_details = result["file_details"]
    overall = result["overall_assessment"]

    assert file_details["type_validation"]["is_allowed_type"] is True
    assert overall["overall_status"] != "Unauthorized Type"
