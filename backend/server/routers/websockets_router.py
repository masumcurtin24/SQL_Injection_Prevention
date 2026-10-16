# backend/server/routers/websockets_router.py (Corrected)
import asyncio
import json
import logging
import os
import time

import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.core.database import SessionLocal
from backend.core.models import Tenant
from backend.security.auth import decode_access_token, decode_step_up_token
from backend.security.authorization_policy import get_policy, role_meets_minimum
from backend.security.request_context import sql_service_context
from backend.server.deps.auth import resolve_user_from_token_payload
from backend.server.websockets import manager
from backend.utils.telemetry import telemetry

router = APIRouter()
logger = logging.getLogger(__name__)
_WS_EVENT_TYPES = ("query", "file_scan", "spam_check", "alert")
_WS_DEFAULT_USER_TYPES = {"query", "file_scan", "spam_check"}
_WS_DEFAULT_PRIVILEGED_TYPES = {"query", "file_scan", "spam_check", "alert"}
_PRIVILEGED_ROLES = {"analyst", "admin"}
_WS_APPLICATION_SUBPROTOCOL = "sqliprev.v1"
_WS_ACCESS_TOKEN_SUBPROTOCOL_PREFIX = "sqliprev.access."
_WS_STEP_UP_TOKEN_SUBPROTOCOL_PREFIX = "sqliprev.stepup."


def _legacy_ws_query_auth_enabled() -> bool:
    return str(os.getenv("WS_ALLOW_LEGACY_QUERY_AUTH", "false")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _extract_ws_auth(
    websocket: WebSocket,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Read browser-compatible auth from WebSocket subprotocol values.

    The server negotiates only the static application protocol, so credentials
    are never echoed back in the handshake. Query-string auth remains available
    only behind an explicit, deprecated compatibility flag because URLs are
    routinely captured by access logs and monitoring systems.
    """

    offered_protocols = tuple(
        str(value or "").strip()
        for value in websocket.scope.get("subprotocols", [])
        if str(value or "").strip()
    )
    access_tokens = [
        value[len(_WS_ACCESS_TOKEN_SUBPROTOCOL_PREFIX) :]
        for value in offered_protocols
        if value.startswith(_WS_ACCESS_TOKEN_SUBPROTOCOL_PREFIX)
    ]
    step_up_tokens = [
        value[len(_WS_STEP_UP_TOKEN_SUBPROTOCOL_PREFIX) :]
        for value in offered_protocols
        if value.startswith(_WS_STEP_UP_TOKEN_SUBPROTOCOL_PREFIX)
    ]
    if len(access_tokens) > 1 or len(step_up_tokens) > 1:
        return None, None, None, "ambiguous_subprotocol_auth"
    if (access_tokens or step_up_tokens) and _WS_APPLICATION_SUBPROTOCOL not in offered_protocols:
        return None, None, None, "missing_application_subprotocol"

    query_auth_present = (
        "token" in websocket.query_params or "step_up_token" in websocket.query_params
    )
    if query_auth_present:
        if access_tokens or step_up_tokens:
            return None, None, None, "mixed_auth_transports"
        if not _legacy_ws_query_auth_enabled():
            return None, None, None, "query_auth_disabled"
        logger.warning(
            "Deprecated WebSocket query-string authentication was used; "
            "migrate the client to Sec-WebSocket-Protocol authentication."
        )
        return (
            str(websocket.query_params.get("token") or "").strip() or None,
            str(websocket.query_params.get("step_up_token") or "").strip() or None,
            None,
            None,
        )

    access_token = access_tokens[0].strip() if access_tokens else ""
    step_up_token = step_up_tokens[0].strip() if step_up_tokens else ""
    negotiated_subprotocol = (
        _WS_APPLICATION_SUBPROTOCOL
        if _WS_APPLICATION_SUBPROTOCOL in offered_protocols
        else None
    )
    return (
        access_token or None,
        step_up_token or None,
        negotiated_subprotocol,
        None,
    )


def _normalize_ws_event_types(raw: str | None, role: str) -> set[str]:
    role_norm = str(role or "").strip().lower()
    default_types = _WS_DEFAULT_PRIVILEGED_TYPES if role_norm in _PRIVILEGED_ROLES else _WS_DEFAULT_USER_TYPES
    requested = [token.strip().lower() for token in str(raw or "").split(",") if token and token.strip()]
    if not requested:
        return set(default_types)
    filtered = {token for token in requested if token in set(_WS_EVENT_TYPES)}
    if not filtered:
        return set(default_types)
    if role_norm not in _PRIVILEGED_ROLES:
        filtered.discard("alert")
    return filtered or set(_WS_DEFAULT_USER_TYPES)


def _validate_alert_subscription_step_up(
    *,
    user_id: str,
    user_role: str,
    step_up_token: str | None,
) -> tuple[bool, str | None]:
    policy = get_policy("ws.alert.subscribe")
    role_norm = str(user_role or "").strip().lower()
    if not role_meets_minimum(role_norm, policy.min_role):
        return False, "insufficient_role"
    if not step_up_token:
        return False, "step_up_required"

    try:
        payload = decode_step_up_token(step_up_token)
    except jwt.ExpiredSignatureError:
        return False, "step_up_expired"
    except jwt.PyJWTError:
        return False, "step_up_invalid"

    token_user = str(payload.get("sub") or "").strip()
    token_role = str(payload.get("role") or "").strip().lower()
    if token_user != user_id:
        return False, "step_up_user_mismatch"
    if token_role != role_norm:
        return False, "step_up_role_mismatch"

    token_actions = payload.get("actions")
    if isinstance(token_actions, str):
        allowed_actions = [token_actions]
    elif isinstance(token_actions, list):
        allowed_actions = [str(item).strip() for item in token_actions if str(item).strip()]
    else:
        allowed_actions = []
    if "*" not in allowed_actions and policy.action not in allowed_actions:
        return False, "step_up_scope_mismatch"

    issued_at = int(payload.get("iat") or 0)
    if issued_at <= 0:
        return False, "step_up_invalid"
    age_seconds = int(time.time()) - issued_at
    if age_seconds > int(policy.step_up_max_age_seconds):
        return False, "step_up_stale"

    return True, None


def _resolve_ws_tenant_id(
    *,
    role: str,
    user_tenant_id: str,
    requested_tenant_id: str | None,
) -> tuple[str | None, str | None]:
    normalized_requested = str(requested_tenant_id or "").strip() or None
    normalized_user = str(user_tenant_id or "").strip() or None
    role_norm = str(role or "").strip().lower()
    if role_norm == "admin":
        return normalized_requested or normalized_user, None
    if normalized_requested and normalized_user and normalized_requested != normalized_user:
        return None, "forbidden_tenant_scope"
    return normalized_user or normalized_requested, None

@router.websocket("/ws/updates")
async def websocket_endpoint(websocket: WebSocket):
    """
    Handles the WebSocket connection. This endpoint is for broadcasting
    server-side updates to all connected clients.
    """
    token, step_up_token, negotiated_subprotocol, auth_transport_error = _extract_ws_auth(websocket)
    if auth_transport_error or not token:
        telemetry.record_ws_auth_failure()
        await websocket.close(code=1008)
        return

    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        telemetry.record_ws_auth_failure()
        await websocket.close(code=1008)
        return

    if not str(payload.get("sub") or "").strip():
        telemetry.record_ws_auth_failure()
        await websocket.close(code=1008)
        return

    requested_tenant_id = websocket.query_params.get("tenant_id")
    user = None
    role = ""
    tenant_id = ""
    db = SessionLocal()
    try:
        # WebSocket handshakes do not use the HTTP middleware that normally
        # captures X-Service-Name/path context. Assign a narrow auth context so
        # fixed ORM lookups are policy-scoped, not anonymous unknown_service SQL.
        with sql_service_context(
            "websocket_auth_service",
            tenant_id=str(payload.get("tenant_id") or requested_tenant_id or ""),
            role=str(payload.get("role") or ""),
        ):
            user = resolve_user_from_token_payload(db=db, payload=payload)
            if user is None or not bool(user.is_active):
                telemetry.record_ws_auth_failure()
                await websocket.close(code=1008)
                return

            role = str(getattr(user, "role", "") or "").strip().lower()
            user_tenant_id = str(getattr(user, "tenant_id", "") or payload.get("tenant_id") or "").strip()
            tenant_id, tenant_error = _resolve_ws_tenant_id(
                role=role,
                user_tenant_id=user_tenant_id,
                requested_tenant_id=requested_tenant_id,
            )
            if tenant_error:
                telemetry.record_ws_auth_failure()
                await websocket.close(code=1008)
                return
            if not tenant_id:
                telemetry.record_ws_auth_failure()
                await websocket.close(code=1008)
                return

            tenant_row = db.query(Tenant).filter(Tenant.id == tenant_id, Tenant.is_active.is_(True)).first()
            if tenant_row is None:
                telemetry.record_ws_auth_failure()
                await websocket.close(code=1008)
                return
    except Exception:
        telemetry.record_ws_auth_failure()
        await websocket.close(code=1008)
        return
    finally:
        db.close()

    if user is None:
        telemetry.record_ws_auth_failure()
        await websocket.close(code=1008)
        return

    user_id = str(user.id)
    requested_event_types = _normalize_ws_event_types(
        websocket.query_params.get("event_types"),
        role,
    )
    effective_event_types = set(requested_event_types)
    notice_payload: dict | None = None

    if "alert" in effective_event_types:
        is_authorized, reason = _validate_alert_subscription_step_up(
            user_id=user_id,
            user_role=role,
            step_up_token=step_up_token,
        )
        if not is_authorized:
            effective_event_types.discard("alert")
            notice_payload = {
                "type": "ws.auth.notice",
                "code": reason or "step_up_required",
                "message": "Alert stream requires fresh step-up authentication.",
            }

    websocket.state.user = {"id": user.id, "email": user.email, "role": user.role, "tenant_id": tenant_id}
    websocket.state.allowed_event_types = sorted(effective_event_types)
    await manager.connect(
        websocket,
        allowed_event_types=effective_event_types,
        tenant_id=tenant_id,
        subprotocol=negotiated_subprotocol,
    )
    if notice_payload is not None:
        await websocket.send_text(json.dumps(notice_payload))
    await websocket.send_text(
        json.dumps(
            {
                "type": "ws.session",
                "role": role,
                "tenant_id": tenant_id or None,
                "event_types": sorted(effective_event_types),
            }
        )
    )
    print(f"WS connected role={role} event_types={sorted(effective_event_types)}")
    try:
        # Heartbeat + read loop: send periodic ping and drain incoming messages
        while True:
            try:
                # Drain any client messages every 30s to avoid idle disconnects
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                # Ignore client messages; server is broadcast-only
                _ = msg
            except asyncio.TimeoutError:
                try:
                    await websocket.send_text(json.dumps({"type": "ping", "ts": asyncio.get_running_loop().time()}))
                except Exception:
                    # If we cannot send, break to cleanup
                    break
    except WebSocketDisconnect:
        print("WS disconnected by client")
    except asyncio.CancelledError:
        # Happens on server shutdown/reload; treat as normal
        print("WS task cancelled (server shutdown)")
    except Exception as e:
        print(f"Error in websocket endpoint: {e}")
    finally:
        manager.disconnect(websocket)
        print("WS cleanup complete")
