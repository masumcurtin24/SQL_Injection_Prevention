import uuid

from backend.core.database import SessionLocal
from backend.core.models import Alert, AuditLog


def test_alert_acknowledge_is_audited(client):
    db = SessionLocal()
    alert_id = f"alert-{uuid.uuid4()}"
    try:
        db.add(
            Alert(
                id=alert_id,
                severity="High",
                title="Test Alert",
                message="Created by test for audit verification",
                acknowledged=False,
            )
        )
        db.commit()
    finally:
        db.close()

    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    user_id = login.json()["user"]["id"]

    ack = client.patch(
        f"/api/v1/alerts/{alert_id}/acknowledge?acknowledge=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ack.status_code == 200, ack.text
    assert ack.json()["acknowledged"] is True

    db = SessionLocal()
    try:
        row = (
            db.query(AuditLog)
            .filter(AuditLog.action == "alerts.acknowledge", AuditLog.resource_id == alert_id)
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        assert row is not None
        assert row.success is True
        assert row.actor_user_id == user_id
    finally:
        db.close()

