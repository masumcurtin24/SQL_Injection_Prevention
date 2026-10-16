def _login_admin(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert response.status_code == 200
    token = response.json().get("access_token")
    assert token
    return token


def test_sql_response_includes_defender_actions(client):
    token = _login_admin(client)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/api/v1/analyze-sql/query",
        json={"query": "SELECT * FROM users WHERE name = 'admin' OR 1=1 --"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert "defender_actions" in body
    assert isinstance(body["defender_actions"], list)
    assert len(body["defender_actions"]) >= 1

    assert "defender_action_summary" in body
    summary = body["defender_action_summary"]
    assert isinstance(summary, dict)
    assert summary.get("domain") == "sql"
    assert isinstance(summary.get("decision"), str)
