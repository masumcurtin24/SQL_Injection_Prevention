def _admin_access_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    token = login.json().get("access_token")
    assert token
    return token


def _issue_step_up_token(client, access_token: str, actions=None) -> str:
    response = client.post(
        "/api/v1/auth/step-up",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"password": "admin-password-123", "actions": actions or []},
    )
    assert response.status_code == 200, response.text
    token = response.json().get("step_up_token")
    assert token
    return token


def test_config_patch_requires_step_up_token(client):
    token = _admin_access_token(client)
    response = client.patch(
        "/api/v1/config/sql-enforcement",
        headers={"Authorization": f"Bearer {token}"},
        json={"monitor": {"backoff_n": 6}},
    )
    assert response.status_code == 401, response.text
    assert "step-up" in str(response.json().get("detail", "")).lower()


def test_spam_settings_update_requires_step_up_token(client):
    token = _admin_access_token(client)
    response = client.put(
        "/api/v1/analyze-spam/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"thresholds": {"allow": 0.4, "suspicious": 0.6, "block": 0.85, "ood": 0.72}},
    )
    assert response.status_code == 401, response.text
    assert "step-up" in str(response.json().get("detail", "")).lower()


def test_step_up_action_scope_is_enforced(client):
    token = _admin_access_token(client)
    step_up = _issue_step_up_token(client, token, actions=["spam.settings.update"])
    response = client.patch(
        "/api/v1/config/sql-enforcement",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Step-Up-Token": step_up,
        },
        json={"monitor": {"backoff_n": 6}},
    )
    assert response.status_code == 403, response.text
    assert "not valid for this action" in str(response.json().get("detail", "")).lower()


def test_spam_autopipeline_run_step_up_scope_is_enforced(client):
    token = _admin_access_token(client)
    step_up = _issue_step_up_token(client, token, actions=["spam.settings.update"])
    response = client.post(
        "/api/v1/defender/spam-autopipeline/run-now",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Step-Up-Token": step_up,
        },
    )
    assert response.status_code == 403, response.text
    assert "not valid for this action" in str(response.json().get("detail", "")).lower()
