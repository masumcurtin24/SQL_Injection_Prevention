"""Baseline smoke test for FileAnalysisService.

This script exits non-zero on regression.
"""
import asyncio
import sys
import io
import json
import zipfile
from pathlib import Path

from starlette.datastructures import UploadFile

# Import service and dependencies
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.file_analysis_service import FileAnalysisService
from backend.services.alerts_service import AlertsService


class FakeSession:
    """Minimal stub Session with add/commit/refresh to avoid DB dependency during smoke tests."""
    def __init__(self):
        self._store = []

    def add(self, obj):
        self._store.append(obj)

    def commit(self):
        pass

    def refresh(self, obj):
        pass


def init_service():
    root = Path(__file__).resolve().parents[2]
    models_store = root / "backend" / "data" / "models_store"
    yara_rules = root / "backend" / "yara_rules" / "basic_rules.yar"
    # Ensure AlertsService exists; DB interactions are stubbed by FakeSession
    alerts = AlertsService()
    FileAnalysisService(
        ml_model_path=str(models_store / "file_analyzer_v1.joblib"),
        yara_rules_path=str(yara_rules),
        alerts_service=alerts,
    )
    return FileAnalysisService.get_instance()


async def scan_bytes(svc: FileAnalysisService, name: str, data: bytes):
    uf = UploadFile(file=io.BytesIO(data), filename=name)
    res = await svc.analyze_file(FakeSession(), uf)
    return res


async def main():
    svc = init_service()

    # 1) Benign text
    benign = await scan_bytes(svc, "hello.txt", b"hello world")
    benign_summary = {
        "filename": benign.get("file_details", {}).get("filename"),
        "overall": benign.get("overall_assessment", {}).get("overall_status"),
        "recommended": benign.get("overall_assessment", {}).get("recommended_action"),
    }
    print("-- Benign text result --")
    print(json.dumps(benign_summary, indent=2, default=str))

    # 2) Archive with reverse shell indicator
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr("payloads/sh.txt", "bash -i")
    archive_bytes = mem.getvalue()
    mal = await scan_bytes(svc, "rev.zip", archive_bytes)
    archive_summary = {
        "filename": mal.get("file_details", {}).get("filename"),
        "overall": mal.get("overall_assessment", {}).get("overall_status"),
        "recommended": mal.get("overall_assessment", {}).get("recommended_action"),
        "reasoning": mal.get("overall_assessment", {}).get("reasoning"),
        "scan_details_keys": list((mal.get("file_details", {}) or {}).keys()),
    }
    print("-- Archive result --")
    print(json.dumps(archive_summary, indent=2, default=str))

    benign_ok = (
        str(benign_summary.get("overall") or "").lower() == "safe"
        and str(benign_summary.get("recommended") or "").upper() == "ALLOW_UPLOAD"
    )
    archive_ok = (
        "malicious" in str(archive_summary.get("overall") or "").lower()
        and str(archive_summary.get("recommended") or "").upper() == "BLOCK_AND_QUARANTINE"
    )
    if not benign_ok:
        raise SystemExit("File smoke failed: benign text file was not allowed.")
    if not archive_ok:
        raise SystemExit("File smoke failed: malicious archive was not blocked/quarantined.")


if __name__ == "__main__":
    asyncio.run(main())
