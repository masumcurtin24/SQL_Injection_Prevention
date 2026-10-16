import json
import uuid

from backend.core.database import SessionLocal
from backend.core.models import AuditLog


def _details(row: AuditLog):
    if not row.details_json:
        return {}
    try:
        return json.loads(row.details_json)
    except Exception:
        return {}


def test_login_success_and_failure_are_audited(client):
    success = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert success.status_code == 200, success.text
    user_id = success.json()["user"]["id"]

    missing_email = f"missing-{uuid.uuid4()}@example.com"
    failed = client.post(
        "/api/v1/auth/login",
        json={"email": missing_email, "password": "nope-nope-nope"},
    )
    assert failed.status_code == 401, failed.text

    db = SessionLocal()
    try:
        rows = (
            db.query(AuditLog)
            .filter(AuditLog.action == "auth.login")
            .order_by(AuditLog.timestamp.desc())
            .limit(30)
            .all()
        )
        assert any(r.success and r.actor_user_id == user_id for r in rows)

        matched_failure = False
        for row in rows:
            details = _details(row)
            if (not row.success) and details.get("attempted_email") == missing_email:
                assert row.actor_user_id is None
                matched_failure = True
                break
        assert matched_failure, "expected a failed auth.login audit row for attempted email"
    finally:
        db.close()

