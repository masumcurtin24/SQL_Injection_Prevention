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
        models_store = ROOT / 'backend' / 'data' / 'models_store'
        yara_rules = ROOT / 'backend' / 'yara_rules' / 'basic_rules.yar'
        return FileAnalysisService(
            ml_model_path=str(models_store / 'file_analyzer_v1.joblib'),
            yara_rules_path=str(yara_rules),
            alerts_service=AlertsService(),
        )


def _bind_shell_sample(full: bool) -> bytes:
    parts = [
        b'power' + b'shell -c "',
        b' = New-Object System.Net.Sockets.' + b'TcpListener(\'0.0.0.0\', 443); ',
        b'.start();  = .Accept' + b'TcpClient(); ',
        b' = .Get' + b'Stream(); ',
        b' = (i' + b'ex  2>&1 | Out-String); ',
    ]
    if full:
        parts.extend([
            b'[byte[]] = 0..65535|%{8}; while(( = .Read(, 0, .Length)) -ne 0) ',
            b'{  = (New-Object -TypeName System.Text.' + b'ASCIIEncoding).GetString(, 0, ); ',
            b' =  + \'PS \' + (pwd).Path + \'> \'; ',
            b' = ([text.encoding]::' + b'ASCII).GetBytes(); ',
            b'.Write(, 0, .Length); .Flush(); ',
            b'} .Close(); .Stop();',
        ])
    else:
        parts.append(b'.Write(, 0, .Length);"')
        return b''.join(parts)
    parts.append(b'"')
    return b''.join(parts)


@pytest.mark.asyncio
async def test_powershell_bind_shell_is_blocked_and_quarantined():
    svc = _service()
    result = await svc.analyze_file(
        FakeSession(),
        UploadFile(file=io.BytesIO(_bind_shell_sample(full=True)), filename='bind-shell.txt'),
    )

    overall = result['overall_assessment']
    malware = result['file_details']['malware_scan']

    assert overall['recommended_action'] == 'BLOCK_AND_QUARANTINE'
    assert overall['overall_status'].startswith('Malicious')
    assert malware['threat_name'] == 'powershell_tcp_socket_shell'
    assert 'powershell_socket_shell' in malware['scan_details']['exec_markers']


@pytest.mark.asyncio
async def test_powershell_bind_shell_heuristic_still_blocks_without_yara():
    svc = _service()
    original_rules = getattr(svc, '_yara_rules', None)

    try:
        svc._yara_rules = None
        result = await svc.analyze_file(
            FakeSession(),
            UploadFile(file=io.BytesIO(_bind_shell_sample(full=False)), filename='bind-shell-no-yara.txt'),
        )
    finally:
        svc._yara_rules = original_rules

    overall = result['overall_assessment']
    malware = result['file_details']['malware_scan']

    assert overall['overall_status'] == 'Malicious (Remote Shell Indicators)'
    assert overall['recommended_action'] == 'BLOCK_AND_QUARANTINE'
    assert malware['is_malicious'] is False
    assert 'powershell_socket_shell' in malware['scan_details']['exec_markers']