from backend.services.defender_ai_service import DefenderAIService


def _login_admin(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert response.status_code == 200, response.text
    token = response.json().get("access_token")
    assert token
    return token


def test_spam_false_negative_feedback_triggers_auto_retrain(client, monkeypatch):
    token = _login_admin(client)
    headers = {"Authorization": f"Bearer {token}"}

    monkeypatch.setenv("DEFENDER_SPAM_AUTO_RETRAIN_ENABLED", "true")
    monkeypatch.setenv("DEFENDER_SPAM_AUTO_RETRAIN_MIN_FALSE_NEGATIVE_SAMPLES", "1")
    monkeypatch.setenv("DEFENDER_SPAM_AUTO_RETRAIN_COOLDOWN_MINUTES", "0")
    monkeypatch.setenv("DEFENDER_SPAM_AUTO_RETRAIN_PROMOTE_IF_BETTER", "false")

    service = DefenderAIService.get_instance()
    calls = {"create": 0, "run": 0}

    class _Job:
        def __init__(self, job_id: str, status: str):
            self.id = job_id
            self.status = status

    def _fake_create_training_job(*, db, domain, min_feedback_samples, promote_if_better, requested_by, notes):
        calls["create"] += 1
        assert domain == "spam"
        assert min_feedback_samples == 1
        assert promote_if_better is False
        assert "auto_false_negative" in str(notes or "")
        return _Job("job-auto-spam-1", "queued")

    def _fake_run_training_job(*, db, job_id):
        calls["run"] += 1
        assert job_id == "job-auto-spam-1"
        return _Job(job_id, "succeeded")

    monkeypatch.setattr(service, "create_training_job", _fake_create_training_job)
    monkeypatch.setattr(service, "run_training_job", _fake_run_training_job)

    submit = client.post(
        "/api/v1/defender/feedback/spam",
        json={
            "subject": "Urgent payroll action required",
            "body_text": "Verify your account now at https://payroll-verify-secure.com/session/update",
            "sender_email": "Payroll Team <security@corp-payroll.com>",
            "true_label": "Spam",
            "predicted_label": "Ham",
            "source": "human",
            "notes": "Analyst-confirmed false negative",
        },
        headers=headers,
    )
    assert submit.status_code == 200, submit.text
    body = submit.json()
    assert body.get("status") == "accepted"
    auto = body.get("auto_retrain") or {}
    assert auto.get("triggered") is True
    assert auto.get("job_id") == "job-auto-spam-1"
    assert auto.get("job_status") == "succeeded"
    assert calls["create"] == 1
    assert calls["run"] == 1
