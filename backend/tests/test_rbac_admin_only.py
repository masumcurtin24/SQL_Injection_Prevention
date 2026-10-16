import uuid


def test_rbac_admin_only_users_list(client):
    admin_login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert admin_login.status_code == 200, admin_login.text
    admin_token = admin_login.json()["access_token"]

    viewer_email = f"viewer-{uuid.uuid4()}@example.com"
    viewer_password = "viewer-password-123"

    created = client.post(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email": viewer_email, "password": viewer_password, "role": "viewer"},
    )
    assert created.status_code == 200, created.text

    viewer_login = client.post(
        "/api/v1/auth/login",
        json={"email": viewer_email, "password": viewer_password},
    )
    assert viewer_login.status_code == 200, viewer_login.text
    viewer_token = viewer_login.json()["access_token"]

    denied = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {viewer_token}"})
    assert denied.status_code == 403, denied.text

