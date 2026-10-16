from __future__ import annotations


def _login_admin(client) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload.get("access_token")
    assert payload.get("refresh_token")
    return payload


def test_login_refresh_and_reuse_detection(client):
    login_payload = _login_admin(client)
    old_refresh = login_payload["refresh_token"]

    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert rotated.status_code == 200, rotated.text
    rotated_payload = rotated.json()
    new_refresh = rotated_payload["refresh_token"]

    assert new_refresh
    assert new_refresh != old_refresh
    assert rotated_payload.get("access_token")
    assert int(rotated_payload.get("refresh_expires_in", 0)) > 0

    reuse = client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert reuse.status_code == 401, reuse.text
    assert "reuse" in reuse.json().get("detail", "").lower()

    family_revoked = client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert family_revoked.status_code == 401, family_revoked.text


def test_logout_revokes_specific_refresh_session(client):
    login_payload = _login_admin(client)
    access_token = login_payload["access_token"]
    refresh_token = login_payload["refresh_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    logout = client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token}, headers=headers)
    assert logout.status_code == 200, logout.text
    assert logout.json().get("success") is True

    refresh_after_logout = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_after_logout.status_code == 401, refresh_after_logout.text


def test_logout_all_revokes_all_active_sessions(client):
    first = _login_admin(client)
    second = _login_admin(client)
    headers = {"Authorization": f"Bearer {first['access_token']}"}

    logout_all = client.post("/api/v1/auth/logout-all", headers=headers)
    assert logout_all.status_code == 200, logout_all.text
    assert logout_all.json().get("success") is True
    assert int(logout_all.json().get("revoked_sessions", 0)) >= 2

    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": second["refresh_token"]})
    assert r1.status_code == 401, r1.text
    assert r2.status_code == 401, r2.text
