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


class FlakySession:
    """Simulates SQLAlchemy failed transaction semantics."""

    def __init__(self) -> None:
        self.commit_calls = 0
        self.rollback_calls = 0
        self._requires_rollback = False

    def add(self, obj):
        return None

    def commit(self):
        self.commit_calls += 1
        if self.commit_calls == 1:
            self._requires_rollback = True
            raise RuntimeError("simulated insert failure")
        if self._requires_rollback:
            raise RuntimeError("rollback required before next transaction")
        return None

    def rollback(self):
        self.rollback_calls += 1
        self._requires_rollback = False
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


def _bind_shell_sample() -> bytes:
    return (
        b'powershell -c "$listener = New-Object System.Net.Sockets.TcpListener'
        b'(\'0.0.0.0\', 443); $listener.start(); $client = $listener.AcceptTcpClient();'
        b' $stream = $client.GetStream(); $sendback = (iex 2>&1 | Out-String);'
        b' $stream.Write($sendbyte, 0, $sendbyte.Length);"'
    )


@pytest.mark.asyncio
async def test_file_scan_recovers_session_after_persist_failure_and_still_creates_alert():
    svc = _service()
    session = FlakySession()

    result = await svc.analyze_file(
        session,
        UploadFile(file=io.BytesIO(_bind_shell_sample()), filename="bind-shell-recovery.txt"),
    )

    assert session.rollback_calls >= 1
    assert session.commit_calls >= 2
    assert result["overall_assessment"]["recommended_action"].startswith("BLOCK")
