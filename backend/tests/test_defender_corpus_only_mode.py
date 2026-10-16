from __future__ import annotations


def _login_admin(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert response.status_code == 200, response.text
    token = response.json().get("access_token")
    assert token
    return token


def _admin_headers_with_step_up(client, actions=None):
    token = _login_admin(client)
    step_up = client.post(
        "/api/v1/auth/step-up",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": "admin-password-123", "actions": actions or []},
    )
    assert step_up.status_code == 200, step_up.text
    step_up_token = step_up.json().get("step_up_token")
    assert step_up_token
    return {
        "Authorization": f"Bearer {token}",
        "X-Step-Up-Token": step_up_token,
    }


def test_defender_train_allows_corpus_only_when_env_enabled(client, monkeypatch):
    monkeypatch.setenv("DEFENDER_ALLOW_CORPUS_ONLY", "true")
    headers = _admin_headers_with_step_up(client, actions=["defender.train.run"])

    response = client.post(
        "/api/v1/defender/train",
        json={
            "domain": "sql",
            "min_feedback_samples": 100,
            "promote_if_better": False,
            "notes": "corpus-only-test",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload.get("status") == "ok"
    assert payload.get("results")
    sql_result = payload["results"][0]
    assert sql_result.get("domain") == "sql"
    assert sql_result.get("status") == "trained"
    details = sql_result.get("details") or {}
    assert details.get("allow_corpus_only") is True
    assert details.get("corpus_only_bootstrap") is True
