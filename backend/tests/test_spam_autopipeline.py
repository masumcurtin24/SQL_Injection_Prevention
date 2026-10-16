from __future__ import annotations

from backend.services.spam_autopipeline_service import SpamAutopipelineService


def _admin_access_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    token = login.json().get("access_token")
    assert token
    return token


def _admin_headers_with_step_up(client, actions=None) -> dict:
    token = _admin_access_token(client)
    step_up = client.post(
        "/api/v1/auth/step-up",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": "admin-password-123", "actions": actions or []},
    )
    assert step_up.status_code == 200, step_up.text
    step_up_token = step_up.json().get("step_up_token")
    assert step_up_token
    return {"Authorization": f"Bearer {token}", "X-Step-Up-Token": step_up_token}


def test_spam_autopipeline_status_endpoint(client):
    token = _admin_access_token(client)
    res = client.get(
        "/api/v1/defender/spam-autopipeline/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert "enabled" in body
    assert "interval_minutes" in body
    assert "last_run" in body


def test_spam_autopipeline_run_now_requires_step_up(client):
    token = _admin_access_token(client)
    res = client.post(
        "/api/v1/defender/spam-autopipeline/run-now",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 401, res.text
    assert "step-up" in str(res.json().get("detail", "")).lower()


def test_spam_autopipeline_run_now_executes_when_authorized(client, monkeypatch):
    headers = _admin_headers_with_step_up(client, actions=["defender.spam.autopipeline.run"])

    async def _fake_run_now(self: SpamAutopipelineService, *, trigger: str = "manual"):
        assert trigger == "manual"
        return {
            "status": "ok",
            "trigger": trigger,
            "started_at": "2026-04-02T00:00:00+00:00",
            "finished_at": "2026-04-02T00:00:01+00:00",
            "duration_seconds": 1.0,
            "error": None,
            "details": {"defender_retrain": [{"domain": "spam", "status": "trained"}]},
        }

    monkeypatch.setattr(SpamAutopipelineService, "run_now", _fake_run_now)

    res = client.post(
        "/api/v1/defender/spam-autopipeline/run-now",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("status") == "ok"
    assert body.get("trigger") == "manual"
