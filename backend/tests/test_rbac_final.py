import uuid


def _login(client, email: str, password: str):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _auth_header(token: str):
    return {"Authorization": f"Bearer {token}"}


def test_rbac_final_matrix(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")

    viewer_email = f"viewer-{uuid.uuid4()}@example.com"
    analyst_email = f"analyst-{uuid.uuid4()}@example.com"
    viewer_password = "viewer-password-123"
    analyst_password = "analyst-password-123"

    viewer_create = client.post(
        "/api/v1/auth/users",
        headers=_auth_header(admin_token),
        json={"email": viewer_email, "password": viewer_password, "role": "viewer"},
    )
    assert viewer_create.status_code == 200, viewer_create.text

    analyst_create = client.post(
        "/api/v1/auth/users",
        headers=_auth_header(admin_token),
        json={"email": analyst_email, "password": analyst_password, "role": "analyst"},
    )
    assert analyst_create.status_code == 200, analyst_create.text

    viewer_token = _login(client, viewer_email, viewer_password)
    analyst_token = _login(client, analyst_email, analyst_password)

    for token in [viewer_token, analyst_token]:
        assert client.get("/api/v1/config/sql-enforcement", headers=_auth_header(token)).status_code == 403
        assert client.get("/api/v1/audit", headers=_auth_header(token)).status_code == 403
        assert client.get("/api/v1/auth/users", headers=_auth_header(token)).status_code == 403

    # Viewer cannot access analyst alerts endpoints.
    assert client.get("/api/v1/alerts", headers=_auth_header(viewer_token)).status_code == 403
    assert client.get("/api/v1/alerts", headers=_auth_header(analyst_token)).status_code == 200

    # Admin can access all governance/admin endpoints.
    assert client.get("/api/v1/config/sql-enforcement", headers=_auth_header(admin_token)).status_code == 200
    assert client.get("/api/v1/audit", headers=_auth_header(admin_token)).status_code == 200
    assert client.get("/api/v1/auth/users", headers=_auth_header(admin_token)).status_code == 200

