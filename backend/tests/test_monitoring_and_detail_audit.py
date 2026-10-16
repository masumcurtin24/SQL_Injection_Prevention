from datetime import datetime, timezone
import uuid

from backend.core.database import SessionLocal
from backend.core.models import Alert, AuditLog, SQLAnalysisLog


def _login_admin(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert response.status_code == 200, response.text
    token = response.json().get("access_token")
    assert token
    return token


def test_monitoring_metrics_and_false_positive_trends(client):
    token = _login_admin(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Generate traffic for endpoint latency/error counters.
    assert client.get("/api/v1/dashboard/stats", headers=headers).status_code == 200
    assert client.get("/api/v1/dashboard/stats-history?days=2", headers=headers).status_code == 200
    assert client.get("/api/v1/monitoring/http/endpoints?top=10", headers=headers).status_code == 200

    # Add a known false positive correction for trend tracking.
    submit = client.post(
        "/api/v1/defender/feedback/sql",
        json={
            "query": "SELECT id FROM users WHERE id = 42",
            "true_label": "Benign",
            "predicted_label": "Malicious",
            "source": "human",
            "notes": "Known false positive for trend metric",
        },
        headers=headers,
    )
    assert submit.status_code == 200, submit.text

    overview = client.get("/api/v1/monitoring/overview", headers=headers)
    assert overview.status_code == 200, overview.text
    overview_payload = overview.json()
    assert "http_totals" in overview_payload
    assert overview_payload["http_totals"]["requests_total"] >= 1
    assert "websocket" in overview_payload
    assert "active_connections" in overview_payload["websocket"]

    trends = client.get("/api/v1/monitoring/false-positive-trends?days=7", headers=headers)
    assert trends.status_code == 200, trends.text
    trends_payload = trends.json()
    assert trends_payload["summary"]["sql"]["false_positives"] >= 1
    assert len(trends_payload["series"]) == 7


def test_detail_view_access_is_audited(client):
    token = _login_admin(client)
    headers = {"Authorization": f"Bearer {token}"}

    now = datetime.now(timezone.utc)
    sql_id = f"sql-audit-{uuid.uuid4()}"
    alert_id = f"alert-audit-{uuid.uuid4()}"

    with SessionLocal() as db:
        sql_row = SQLAnalysisLog(id=sql_id, timestamp=now, query_received="SELECT * FROM users WHERE id=1")
        sql_row.anomaly_detection_result = {"is_anomalous": False, "score": 0.2, "prediction_label": "Normal"}
        sql_row.query_validation_result = {"classification_label": "Benign", "classification_score": 0.15}
        sql_row.combined_assessment = {"overall_risk_level": "Low", "suggested_action": "ALLOW", "reasoning": ["safe pattern"]}

        alert = Alert(
            id=alert_id,
            timestamp=now,
            severity="Low",
            title="Audit test alert",
            message="Alert detail audit test",
            acknowledged=False,
        )
        db.add_all([sql_row, alert])
        db.commit()

    live_detail = client.get(
        f"/api/v1/dashboard/live-events/detail?event_type=query&event_id={sql_id}",
        headers=headers,
    )
    assert live_detail.status_code == 200, live_detail.text

    alert_detail = client.get(f"/api/v1/alerts/{alert_id}", headers=headers)
    assert alert_detail.status_code == 200, alert_detail.text

    with SessionLocal() as db:
        live_audit = (
            db.query(AuditLog)
            .filter(AuditLog.action == "dashboard.live_event.detail.view", AuditLog.resource_id == f"query:{sql_id}")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        alert_audit = (
            db.query(AuditLog)
            .filter(AuditLog.action == "alerts.detail.view", AuditLog.resource_id == alert_id)
            .order_by(AuditLog.timestamp.desc())
            .first()
        )

    assert live_audit is not None
    assert bool(live_audit.success) is True
    assert alert_audit is not None
    assert bool(alert_audit.success) is True
