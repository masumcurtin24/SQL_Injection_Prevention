def test_request_context_no_leak(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    r1 = client.get(
        "/api/v1/_test/current-service",
        headers={"Authorization": f"Bearer {token}", "X-Service-Name": "svc-one"},
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["service"] == "svc-one"

    r2 = client.get(
        "/api/v1/_test/current-service",
        headers={"Authorization": f"Bearer {token}", "X-Service-Name": "svc-two"},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["service"] == "svc-two"

