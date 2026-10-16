import pytest
import json
from starlette.websockets import WebSocketDisconnect


def _admin_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _create_user_and_login(client, role: str) -> tuple[str, str]:
    import uuid

    admin_token = _admin_token(client)
    email = f"{role}-{uuid.uuid4()}@example.com"
    password = f"{role}-password-123"
    created = client.post(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email": email, "password": password, "role": role},
    )
    assert created.status_code == 200, created.text

    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    return login.json()["access_token"], password


def test_websocket_rejects_without_token(client):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/api/v1/ws/updates"):
            pass
    assert excinfo.value.code == 1008


def test_websocket_rejects_invalid_token(client):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/api/v1/ws/updates?token=this-is-not-valid"):
            pass
    assert excinfo.value.code == 1008


def test_websocket_accepts_valid_token(client):
    token = _admin_token(client)

    with client.websocket_connect(f"/api/v1/ws/updates?token={token}") as websocket:
        first = json.loads(websocket.receive_text())
        if first.get("type") == "ws.auth.notice":
            session = json.loads(websocket.receive_text())
        else:
            session = first
        assert session.get("type") == "ws.session"
        websocket.send_text("hello")


def test_websocket_viewer_cannot_subscribe_to_alert_stream(client):
    token, _ = _create_user_and_login(client, role="viewer")
    with client.websocket_connect(
        f"/api/v1/ws/updates?token={token}&event_types=query,file_scan,spam_check,alert"
    ) as websocket:
        session = json.loads(websocket.receive_text())
        assert session.get("type") == "ws.session"
        assert "alert" not in set(session.get("event_types") or [])


def test_websocket_alert_subscription_requires_step_up(client):
    token = _admin_token(client)
    with client.websocket_connect(
        f"/api/v1/ws/updates?token={token}&event_types=query,file_scan,spam_check,alert"
    ) as websocket:
        notice = json.loads(websocket.receive_text())
        session = json.loads(websocket.receive_text())
        assert notice.get("type") == "ws.auth.notice"
        assert "step_up" in str(notice.get("code") or "")
        assert session.get("type") == "ws.session"
        assert "alert" not in set(session.get("event_types") or [])


def test_websocket_alert_subscription_accepts_valid_step_up(client):
    token = _admin_token(client)
    step_up = client.post(
        "/api/v1/auth/step-up",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": "admin-password-123", "actions": ["ws.alert.subscribe"]},
    )
    assert step_up.status_code == 200, step_up.text
    step_up_token = step_up.json()["step_up_token"]

    with client.websocket_connect(
        f"/api/v1/ws/updates?token={token}&event_types=query,file_scan,spam_check,alert&step_up_token={step_up_token}"
    ) as websocket:
        session = json.loads(websocket.receive_text())
        assert session.get("type") == "ws.session"
        assert "alert" in set(session.get("event_types") or [])
