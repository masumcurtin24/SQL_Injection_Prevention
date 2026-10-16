import uuid


def _login(client, email: str, password: str):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _auth(token: str):
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_switch_user_role_and_toggle_active(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")

    email = f"viewer-{uuid.uuid4()}@example.com"
    password = "viewer-password-123"
    created = client.post(
        "/api/v1/auth/users",
        headers=_auth(admin_token),
        json={"email": email, "password": password, "role": "viewer"},
    )
    assert created.status_code == 200, created.text
    user = created.json()

    viewer_token = _login(client, email, password)
    denied_alerts = client.get("/api/v1/alerts", headers=_auth(viewer_token))
    assert denied_alerts.status_code == 403, denied_alerts.text

    updated = client.patch(
        f"/api/v1/auth/users/{user['id']}",
        headers=_auth(admin_token),
        json={"role": "analyst"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["role"] == "analyst"

    promoted_token = _login(client, email, password)
    allowed_alerts = client.get("/api/v1/alerts", headers=_auth(promoted_token))
    assert allowed_alerts.status_code == 200, allowed_alerts.text

    deactivated = client.patch(
        f"/api/v1/auth/users/{user['id']}",
        headers=_auth(admin_token),
        json={"is_active": False},
    )
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["is_active"] is False

    login_after_deactivate = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_after_deactivate.status_code == 401, login_after_deactivate.text


def test_non_admin_cannot_update_users(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    email = f"viewer-{uuid.uuid4()}@example.com"
    password = "viewer-password-123"
    created = client.post(
        "/api/v1/auth/users",
        headers=_auth(admin_token),
        json={"email": email, "password": password, "role": "viewer"},
    )
    assert created.status_code == 200, created.text
    user = created.json()

    viewer_token = _login(client, email, password)
    denied = client.patch(
        f"/api/v1/auth/users/{user['id']}",
        headers=_auth(viewer_token),
        json={"role": "analyst"},
    )
    assert denied.status_code == 403, denied.text


def test_user_full_name_create_update_and_me_endpoint(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    email = f"named-{uuid.uuid4()}@example.com"
    password = "named-password-123"

    created = client.post(
        "/api/v1/auth/users",
        headers=_auth(admin_token),
        json={
            "email": email,
            "password": password,
            "role": "viewer",
            "full_name": "Named Viewer",
        },
    )
    assert created.status_code == 200, created.text
    user = created.json()
    assert user["full_name"] == "Named Viewer"

    user_token = _login(client, email, password)
    me = client.get("/api/v1/auth/me", headers=_auth(user_token))
    assert me.status_code == 200, me.text
    assert me.json()["full_name"] == "Named Viewer"

    updated = client.patch(
        f"/api/v1/auth/users/{user['id']}",
        headers=_auth(admin_token),
        json={"full_name": "Updated Viewer Name"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["full_name"] == "Updated Viewer Name"
