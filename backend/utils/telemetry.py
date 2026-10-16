from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional


class TelemetryCollector:
    def __init__(self) -> None:
        self._lock = Lock()
        self._http: Dict[str, Dict[str, Any]] = {}
        self._ws: Dict[str, Any] = {
            "active_connections": 0,
            "connections_total": 0,
            "disconnects_total": 0,
            "auth_failures_total": 0,
            "messages_broadcast_total": 0,
            "broadcast_send_failures_total": 0,
            "last_event_at": None,
        }

    def record_http(self, *, method: str, path: str, status_code: int, latency_ms: float) -> None:
        key = f"{str(method).upper()} {path}"
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._http.setdefault(
                key,
                {
                    "method": str(method).upper(),
                    "path": path,
                    "requests_total": 0,
                    "errors_total": 0,
                    "latency_ms_sum": 0.0,
                    "latency_ms_max": 0.0,
                    "latency_ms_last": 0.0,
                    "last_status_code": 0,
                    "last_seen_at": None,
                },
            )
            row["requests_total"] += 1
            if int(status_code) >= 400:
                row["errors_total"] += 1
            row["latency_ms_sum"] += float(latency_ms)
            row["latency_ms_last"] = float(latency_ms)
            if float(latency_ms) > float(row["latency_ms_max"]):
                row["latency_ms_max"] = float(latency_ms)
            row["last_status_code"] = int(status_code)
            row["last_seen_at"] = now

    def record_ws_connect(self) -> None:
        with self._lock:
            self._ws["active_connections"] += 1
            self._ws["connections_total"] += 1
            self._ws["last_event_at"] = datetime.now(timezone.utc).isoformat()

    def record_ws_disconnect(self) -> None:
        with self._lock:
            self._ws["active_connections"] = max(0, int(self._ws["active_connections"]) - 1)
            self._ws["disconnects_total"] += 1
            self._ws["last_event_at"] = datetime.now(timezone.utc).isoformat()

    def record_ws_auth_failure(self) -> None:
        with self._lock:
            self._ws["auth_failures_total"] += 1
            self._ws["last_event_at"] = datetime.now(timezone.utc).isoformat()

    def record_ws_broadcast(self, *, recipients: int, failed: int) -> None:
        with self._lock:
            self._ws["messages_broadcast_total"] += int(max(0, recipients))
            self._ws["broadcast_send_failures_total"] += int(max(0, failed))
            self._ws["last_event_at"] = datetime.now(timezone.utc).isoformat()

    def snapshot_http(self, *, top: int = 100) -> Dict[str, Any]:
        with self._lock:
            rows = list(self._http.values())
        for row in rows:
            req = int(row.get("requests_total") or 0)
            err = int(row.get("errors_total") or 0)
            row["error_rate"] = (float(err) / float(req)) if req else 0.0
            row["latency_ms_avg"] = (float(row.get("latency_ms_sum") or 0.0) / float(req)) if req else 0.0
        rows.sort(key=lambda r: (int(r.get("requests_total") or 0), float(r.get("latency_ms_avg") or 0.0)), reverse=True)
        limited = rows[: max(1, min(int(top), 500))]
        return {"endpoints": limited, "total_endpoints": len(rows)}

    def snapshot_ws(self) -> Dict[str, Any]:
        with self._lock:
            ws = dict(self._ws)
        total = int(ws.get("messages_broadcast_total") or 0)
        failed = int(ws.get("broadcast_send_failures_total") or 0)
        ws["broadcast_failure_rate"] = (float(failed) / float(total)) if total else 0.0
        return ws

    def snapshot_overview(self, *, top: int = 20) -> Dict[str, Any]:
        http = self.snapshot_http(top=top)
        endpoints = http.get("endpoints") or []
        totals = {
            "requests_total": 0,
            "errors_total": 0,
            "avg_latency_ms": 0.0,
            "error_rate": 0.0,
        }
        for row in endpoints:
            totals["requests_total"] += int(row.get("requests_total") or 0)
            totals["errors_total"] += int(row.get("errors_total") or 0)
            totals["avg_latency_ms"] += float(row.get("latency_ms_sum") or 0.0)
        req = int(totals["requests_total"])
        err = int(totals["errors_total"])
        totals["avg_latency_ms"] = (float(totals["avg_latency_ms"]) / float(req)) if req else 0.0
        totals["error_rate"] = (float(err) / float(req)) if req else 0.0
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "http_totals": totals,
            "http_top_endpoints": endpoints,
            "websocket": self.snapshot_ws(),
        }


telemetry = TelemetryCollector()
