from pathlib import Path

from backend.core.database import SessionLocal
from backend.core.models import AuditLog


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


def _submit_sql_feedback(client, headers, query: str, true_label: str, predicted_label: str):
    response = client.post(
        "/api/v1/defender/feedback/sql",
        json={
            "query": query,
            "true_label": true_label,
            "predicted_label": predicted_label,
            "source": "human",
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text


def test_defender_v2_retraining_jobs_promotion_and_rollback(client):
    headers = _admin_headers_with_step_up(
        client,
        actions=["defender.train.run", "defender.model.promote", "defender.model.rollback"],
    )

    _submit_sql_feedback(
        client,
        headers,
        "SELECT * FROM users WHERE id=1 OR 1=1 --",
        "Malicious",
        "Benign",
    )
    _submit_sql_feedback(
        client,
        headers,
        "SELECT id FROM products WHERE id = 7",
        "Benign",
        "Malicious",
    )

    train_1 = client.post(
        "/api/v1/defender/train",
        json={"domain": "sql", "min_feedback_samples": 2, "promote_if_better": False, "notes": "v2-train-1"},
        headers=headers,
    )
    assert train_1.status_code == 200, train_1.text
    payload_1 = train_1.json()
    assert payload_1.get("status") == "ok"
    assert payload_1.get("job_id")
    assert payload_1.get("results")
    details_1 = payload_1["results"][0]["details"]
    candidate_1 = details_1["registry_id"]
    dataset_artifact = details_1["dataset_artifact"]
    assert Path(dataset_artifact).exists()
    assert "feedback_evaluation" in details_1["metrics"]

    jobs = client.get("/api/v1/defender/train/jobs?domain=sql&limit=10", headers=headers)
    assert jobs.status_code == 200, jobs.text
    jobs_payload = jobs.json()
    assert any(row["id"] == payload_1["job_id"] for row in jobs_payload)

    job_detail = client.get(f"/api/v1/defender/train/jobs/{payload_1['job_id']}", headers=headers)
    assert job_detail.status_code == 200, job_detail.text
    assert job_detail.json()["status"] == "succeeded"

    promote_1 = client.post(
        "/api/v1/defender/models/promote",
        json={"registry_id": candidate_1, "force": True, "notes": "force promote first"},
        headers=headers,
    )
    assert promote_1.status_code == 200, promote_1.text
    assert promote_1.json()["id"] == candidate_1
    assert promote_1.json()["stage"] == "active"

    _submit_sql_feedback(
        client,
        headers,
        "UNION SELECT username,password FROM users",
        "Malicious",
        "Benign",
    )
    _submit_sql_feedback(
        client,
        headers,
        "SELECT 1",
        "Benign",
        "Malicious",
    )

    train_2 = client.post(
        "/api/v1/defender/train",
        json={"domain": "sql", "min_feedback_samples": 2, "promote_if_better": False, "notes": "v2-train-2"},
        headers=headers,
    )
    assert train_2.status_code == 200, train_2.text
    payload_2 = train_2.json()
    details_2 = payload_2["results"][0]["details"]
    candidate_2 = details_2["registry_id"]

    promote_2 = client.post(
        "/api/v1/defender/models/promote",
        json={"registry_id": candidate_2, "force": True, "notes": "force promote second"},
        headers=headers,
    )
    assert promote_2.status_code == 200, promote_2.text
    assert promote_2.json()["id"] == candidate_2
    assert promote_2.json()["stage"] == "active"

    rollback = client.post(
        "/api/v1/defender/models/rollback",
        json={"domain": "sql", "target_registry_id": candidate_1, "notes": "rollback test"},
        headers=headers,
    )
    assert rollback.status_code == 200, rollback.text
    rollback_payload = rollback.json()
    assert rollback_payload["domain"] == "sql"
    assert rollback_payload["active_registry"]["id"] == candidate_1

    with SessionLocal() as db:
        actions = (
            db.query(AuditLog.action)
            .filter(AuditLog.action.in_(["defender.train.run", "defender.model.promote", "defender.model.rollback"]))
            .all()
        )
    action_names = {row[0] for row in actions}
    assert "defender.train.run" in action_names
    assert "defender.model.promote" in action_names
    assert "defender.model.rollback" in action_names
