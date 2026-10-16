from __future__ import annotations

import os
from typing import Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

ASGIApp = Callable[[dict, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]], Awaitable[None]]


class _BodyTooLarge(Exception):
    pass


def _get_header(headers: Iterable[Tuple[bytes, bytes]], name: str) -> Optional[str]:
    name_b = name.lower().encode("ascii")
    for k, v in headers:
        if k.lower() == name_b:
            try:
                return v.decode("latin-1")
            except Exception:
                return None
    return None


def _set_header(headers: List[Tuple[bytes, bytes]], name: str, value: str) -> None:
    name_b = name.lower().encode("ascii")
    filtered = [(k, v) for (k, v) in headers if k.lower() != name_b]
    filtered.append((name.encode("ascii"), value.encode("latin-1")))
    headers[:] = filtered


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: Optional[int] = None):
        self.app = app
        if max_body_bytes is not None:
            self.max_body_bytes = int(max_body_bytes)
        else:
            try:
                self.max_body_bytes = int(os.getenv("MAX_BODY_BYTES", "1048576"))
            except Exception:
                self.max_body_bytes = 1048576

    def _is_exempt(self, scope: dict) -> bool:
        path = (scope.get("path") or "").lower()
        if path.startswith("/api/v1/analyze-file") or path.startswith("/api/analyze-file"):
            return True
        content_type = _get_header(scope.get("headers") or [], "content-type") or ""
        if content_type.lower().startswith("multipart/form-data"):
            return True
        return False

    async def __call__(self, scope: dict, receive: Callable[[], Awaitable[dict]], send: Callable[[dict], Awaitable[None]]):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        if self._is_exempt(scope):
            await self.app(scope, receive, send)
            return

        headers = list(scope.get("headers") or [])
        cl = _get_header(headers, "content-length")
        if cl:
            try:
                if int(cl) > self.max_body_bytes:
                    await self._send_413(scope, send)
                    return
            except Exception:
                # If Content-Length is invalid, fall back to streaming enforcement.
                pass

        seen = 0

        async def receive_limited() -> dict:
            nonlocal seen
            msg = await receive()
            if msg.get("type") == "http.request":
                body = msg.get("body") or b""
                seen += len(body)
                if seen > self.max_body_bytes:
                    raise _BodyTooLarge()
            return msg

        try:
            await self.app(scope, receive_limited, send)
        except _BodyTooLarge:
            await self._send_413(scope, send)

    async def _send_413(self, scope: dict, send: Callable[[dict], Awaitable[None]]) -> None:
        path = scope.get("path") or ""
        payload = b'{"detail":"Request body too large"}'
        headers: List[Tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode("ascii")),
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
        ]
        if path.startswith("/api/v1/auth") or path.startswith("/api/auth"):
            headers.append((b"cache-control", b"no-store"))

        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": payload, "more_body": False})

