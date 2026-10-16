import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.file_scan_queue_factory import create_file_scan_queue_service
from backend.services.file_scan_queue_redis_service import RedisFileScanQueueService
from backend.services.file_scan_queue_service import FileScanQueueService


def test_factory_defaults_to_memory(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("FILE_SCAN_QUEUE_BACKEND", raising=False)
    svc = create_file_scan_queue_service()
    assert isinstance(svc, FileScanQueueService)


def test_factory_selects_memory_alias(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FILE_SCAN_QUEUE_BACKEND", "inmemory")
    svc = create_file_scan_queue_service()
    assert isinstance(svc, FileScanQueueService)


def test_factory_selects_redis(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FILE_SCAN_QUEUE_BACKEND", "redis")
    svc = create_file_scan_queue_service()
    assert isinstance(svc, RedisFileScanQueueService)


def test_factory_rejects_unknown_backend(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FILE_SCAN_QUEUE_BACKEND", "unsupported_backend")
    with pytest.raises(ValueError):
        create_file_scan_queue_service()
