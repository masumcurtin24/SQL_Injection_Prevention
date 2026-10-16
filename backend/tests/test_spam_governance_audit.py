import json

from backend.core.database import SessionLocal
from backend.core.models import AuditLog


def _admin_headers_with_step_up(client, actions=None):
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    step_up = client.post(
        "/api/v1/auth/step-up",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": "admin-password-123", "actions": actions or []},
    )
    assert step_up.status_code == 200, step_up.text
    step_up_token = step_up.json()["step_up_token"]
    return {
        "Authorization": f"Bearer {token}",
        "X-Step-Up-Token": step_up_token,
    }


def test_spam_settings_update_is_audited(client):
    headers = _admin_headers_with_step_up(client, actions=["spam.settings.update"])
    response = client.put(
        "/api/v1/analyze-spam/settings",
        headers=headers,
        json={"final_threshold": 0.52},
    )
    assert response.status_code == 200, response.text

    db = SessionLocal()
    try:
        row = (
            db.query(AuditLog)
            .filter(AuditLog.action == "spam.settings.update")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        assert row is not None
        assert row.success is True
        details = json.loads(row.details_json or "{}")
        assert "final_threshold" in (details.get("changed_keys") or [])
    finally:
        db.close()
