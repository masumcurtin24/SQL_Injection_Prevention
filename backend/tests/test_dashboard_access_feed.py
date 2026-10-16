import uuid


def _login(client, email: str, password: str) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _auth(token: str):
    return {"Authorization": f"Bearer {token}"}


def _create_user(
    client,
    admin_token: str,
    *,
    role: str,
    full_name: str,
) -> tuple[str, str]:
    email = f"{role}-{uuid.uuid4()}@example.com"
    password = f"{role}-password-123"
    created = client.post(
        "/api/v1/auth/users",
        headers=_auth(admin_token),
        json={
            "email": email,
            "password": password,
            "role": role,
            "full_name": full_name,
            "is_active": True,
        },
    )
    assert created.status_code == 200, created.text
    return email, password


def test_admin_access_feed_contains_full_name_and_session_duration(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")

    viewer_email, viewer_password = _create_user(
        client,
        admin_token,
        role="viewer",
        full_name="Viewer Feed User",
    )
    _ = _login(client, viewer_email, viewer_password)

    response = client.get(
        "/api/v1/dashboard/access-feed?limit=100&active_only=false",
        headers=_auth(admin_token),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "items" in payload
    assert isinstance(payload["items"], list)
    assert payload["count"] >= 1

    matched = [row for row in payload["items"] if row.get("email") == viewer_email]
    assert matched, f"expected access-feed row for {viewer_email}"
    row = matched[0]
    assert row.get("full_name") == "Viewer Feed User"
    assert isinstance(row.get("duration_seconds"), int)
    assert row.get("duration_seconds") >= 0


def test_only_admin_can_read_access_feed(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    analyst_email, analyst_password = _create_user(
        client,
        admin_token,
        role="analyst",
        full_name="Analyst User",
    )
    analyst_token = _login(client, analyst_email, analyst_password)

    denied = client.get("/api/v1/dashboard/access-feed", headers=_auth(analyst_token))
    assert denied.status_code == 403, denied.text

