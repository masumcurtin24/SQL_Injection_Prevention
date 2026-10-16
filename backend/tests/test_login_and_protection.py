def test_login_and_protection(client):
    # Existing endpoint should be protected
    r = client.get("/api/v1/alerts")
    assert r.status_code == 401, r.text

    # Bootstrap admin should be able to login and receive a token
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    token = login.json().get("access_token")
    assert token

    # Same endpoint should now be accessible
    r2 = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200, r2.text

