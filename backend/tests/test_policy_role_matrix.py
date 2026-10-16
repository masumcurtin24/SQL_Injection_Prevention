from __future__ import annotations

import uuid


def _admin_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _create_user_and_login(client, role: str) -> str:
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
    return login.json()["access_token"]


def test_viewer_dashboard_scope_is_metrics_only(client):
    viewer_token = _create_user_and_login(client, "viewer")
    headers = {"Authorization": f"Bearer {viewer_token}"}

    stats = client.get("/api/v1/dashboard/stats?scope=today", headers=headers)
    assert stats.status_code == 200, stats.text

    files = client.get("/api/v1/dashboard/files-scanned", headers=headers)
    assert files.status_code == 403, files.text

    detail = client.get(
        "/api/v1/dashboard/live-events/detail?event_type=query&event_id=non-existent-id",
        headers=headers,
    )
    assert detail.status_code == 403, detail.text


def test_analyst_can_access_dashboard_detail_endpoints(client):
    analyst_token = _create_user_and_login(client, "analyst")
    headers = {"Authorization": f"Bearer {analyst_token}"}

    files = client.get("/api/v1/dashboard/files-scanned", headers=headers)
    assert files.status_code == 200, files.text
    sql = client.get("/api/v1/dashboard/sql-queries", headers=headers)
    assert sql.status_code == 200, sql.text
    spam = client.get("/api/v1/dashboard/spam-detections", headers=headers)
    assert spam.status_code == 200, spam.text

    detail = client.get(
        "/api/v1/dashboard/live-events/detail?event_type=query&event_id=non-existent-id",
        headers=headers,
    )
    assert detail.status_code == 404, detail.text


def test_monitoring_endpoints_require_analyst_or_admin(client):
    viewer_token = _create_user_and_login(client, "viewer")
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    viewer_res = client.get("/api/v1/monitoring/overview", headers=viewer_headers)
    assert viewer_res.status_code == 403, viewer_res.text

    analyst_token = _create_user_and_login(client, "analyst")
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    analyst_res = client.get("/api/v1/monitoring/overview", headers=analyst_headers)
    assert analyst_res.status_code == 200, analyst_res.text

    admin_headers = {"Authorization": f"Bearer {_admin_token(client)}"}
    admin_res = client.get("/api/v1/monitoring/overview", headers=admin_headers)
    assert admin_res.status_code == 200, admin_res.text
