def _login_admin(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert response.status_code == 200
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


def test_defender_sql_feedback_and_status(client):
    headers = _admin_headers_with_step_up(client, actions=["defender.train.run"])

    submit = client.post(
        "/api/v1/defender/feedback/sql",
        json={
            "query": "SELECT * FROM users WHERE id = 1 OR 1=1 --",
            "true_label": "Malicious",
            "predicted_label": "Benign",
            "confidence": 0.2,
            "source": "human",
            "notes": "False negative from analyst validation",
        },
        headers=headers,
    )
    assert submit.status_code == 200, submit.text
    body = submit.json()
    assert body.get("status") == "accepted"
    assert body.get("feedback_id")

    status = client.get("/api/v1/defender/status", headers=headers)
    assert status.status_code == 200, status.text
    status_body = status.json()
    assert status_body["feedback_counts"]["sql"] >= 1
    assert status_body["pending_feedback"] >= 1

    train = client.post(
        "/api/v1/defender/train",
        json={
            "domain": "all",
            "min_feedback_samples": 9999,
            "promote_if_better": False,
        },
        headers=headers,
    )
    assert train.status_code == 200, train.text
    train_body = train.json()
    assert train_body.get("status") == "ok"
    assert isinstance(train_body.get("results"), list)
