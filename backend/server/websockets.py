# backend/server/websockets.py
import asyncio
import json
from typing import Dict, List, Optional, Set
from fastapi import WebSocket

from backend.utils.telemetry import telemetry
from backend.utils.logging_utils import setup_logger


logger = setup_logger(__name__)


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._allowed_event_types: Dict[WebSocket, Set[str]] = {}
        self._tenant_ids: Dict[WebSocket, str] = {}

    async def connect(
        self,
        websocket: WebSocket,
        allowed_event_types: Optional[Set[str]] = None,
        tenant_id: Optional[str] = None,
    ):
        await websocket.accept()
        self.active_connections.append(websocket)
        if allowed_event_types is None:
            self._allowed_event_types[websocket] = {"query", "file_scan", "spam_check", "alert"}
        else:
            self._allowed_event_types[websocket] = set(allowed_event_types)
        tenant_value = str(tenant_id or "").strip()
        if tenant_value:
            self._tenant_ids[websocket] = tenant_value
        telemetry.record_ws_connect()

    def disconnect(self, websocket: WebSocket):
        try:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
                self._allowed_event_types.pop(websocket, None)
                self._tenant_ids.pop(websocket, None)
                telemetry.record_ws_disconnect()
        except Exception:
            # Safely ignore double-removals or race conditions
            pass

    @staticmethod
    def _normalize_message_type(payload_type: Optional[str]) -> Optional[str]:
        v = str(payload_type or "").strip()
        if not v:
            return None
        if v == "NEW_ALERT_DETAILS":
            return "alert"
        return v

    def _message_event_type(self, message: str) -> Optional[str]:
        try:
            payload = json.loads(message)
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        return self._normalize_message_type(payload.get("type"))

    def _message_tenant_id(self, message: str) -> Optional[str]:
        try:
            payload = json.loads(message)
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        tenant_value = str(payload.get("tenant_id") or "").strip()
        return tenant_value or None

    async def broadcast(self, message: str):
        stale: List[WebSocket] = []
        total = len(list(self.active_connections))
        message_type = self._message_event_type(message)
        message_tenant_id = self._message_tenant_id(message)
        for connection in list(self.active_connections):
            try:
                allowed = self._allowed_event_types.get(connection) or {"query", "file_scan", "spam_check", "alert"}
                if message_type and message_type not in allowed:
                    continue
                if message_tenant_id is not None:
                    connection_tenant_id = str(self._tenant_ids.get(connection) or "").strip()
                    if not connection_tenant_id or connection_tenant_id != message_tenant_id:
                        continue
                await connection.send_text(message)
            except Exception:
                stale.append(connection)
        for s in stale:
            self.disconnect(s)
        telemetry.record_ws_broadcast(recipients=total, failed=len(stale))

    def broadcast_nowait(self, message: str) -> bool:
        """Schedule a broadcast only when a loop is currently running.

        Service methods are sometimes executed from smoke tests or sync helper
        contexts where no event loop exists. In those paths, dropping the live
        UI broadcast is correct; the analysis result and persistence still
        matter, while a missing loop should not produce unawaited coroutine
        warnings.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug("Skipping websocket broadcast because no event loop is running.")
            return False
        loop.create_task(self.broadcast(message))
        return True

manager = ConnectionManager()
