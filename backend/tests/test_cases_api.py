from __future__ import annotations

import uuid
from datetime import datetime, timezone

from backend.core.database import SessionLocal
from backend.core.models import Alert


def _login(client, email: str, password: str) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_user(client, admin_token: str, role: str) -> tuple[str, str]:
    email = f"{role}-{uuid.uuid4()}@example.com"
    password = f"{role}-password-123"
    response = client.post(
        "/api/v1/auth/users",
        headers=_auth(admin_token),
        json={"email": email, "password": password, "role": role},
    )
    assert response.status_code == 200, response.text
    return email, password


def test_cases_end_to_end_for_analyst(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    analyst_email, analyst_password = _create_user(client, admin_token, "analyst")
    viewer_email, viewer_password = _create_user(client, admin_token, "viewer")

    analyst_token = _login(client, analyst_email, analyst_password)
    viewer_token = _login(client, viewer_email, viewer_password)

    denied = client.get("/api/v1/cases", headers=_auth(viewer_token))
    assert denied.status_code == 403, denied.text

    create_payload = {
        "title": "Investigate suspicious SQL burst",
        "description": "Multiple high-risk SQL events detected in checkout service.",
        "severity": "High",
        "domain": "sql",
        "source_type": "query",
        "source_id": "sql-test-001",
        "tags": ["sql", "checkout"],
        "evidence": [{"type": "query", "value": "UNION SELECT ...", "score": 0.91}],
    }
    created = client.post("/api/v1/cases", headers=_auth(analyst_token), json=create_payload)
    assert created.status_code == 200, created.text
    case = created.json()
    case_id = case["id"]
    assert case["status"] == "new"
    assert case["severity"] == "High"
    assert case["title"] == create_payload["title"]
    assert len(case["timeline"]) >= 1

    listing = client.get("/api/v1/cases?page=1&page_size=10", headers=_auth(analyst_token))
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["total_cases"] >= 1
    assert any(item["id"] == case_id for item in body["cases"])

    detail = client.get(f"/api/v1/cases/{case_id}", headers=_auth(analyst_token))
    assert detail.status_code == 200, detail.text
    assert detail.json()["id"] == case_id

    status_update = client.patch(
        f"/api/v1/cases/{case_id}/status",
        headers=_auth(analyst_token),
        json={"status": "investigating", "note": "Triage complete; escalating to active investigation."},
    )
    assert status_update.status_code == 200, status_update.text
    assert status_update.json()["status"] == "investigating"

    note_add = client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=_auth(analyst_token),
        json={"note": "Attached DB query plan and request samples."},
    )
    assert note_add.status_code == 200, note_add.text
    assert any(
        entry.get("action") == "case.note"
        for entry in note_add.json().get("timeline", [])
    )

    assign = client.patch(
        f"/api/v1/cases/{case_id}/assign",
        headers=_auth(analyst_token),
        json={"owner_user_id": case["created_by_user_id"], "note": "Keep current owner."},
    )
    assert assign.status_code == 200, assign.text
    assert assign.json()["owner_user_id"] == case["created_by_user_id"]

    notes = client.get(f"/api/v1/cases/{case_id}/notes", headers=_auth(analyst_token))
    assert notes.status_code == 200, notes.text
    assert notes.json()["count"] >= 1

    activity = client.get(f"/api/v1/cases/{case_id}/activity", headers=_auth(analyst_token))
    assert activity.status_code == 200, activity.text
    assert any(item.get("action") == "case.note" for item in activity.json().get("activity", []))

    stats = client.get("/api/v1/cases/stats", headers=_auth(analyst_token))
    assert stats.status_code == 200, stats.text
    stats_payload = stats.json()
    assert stats_payload["total_cases"] >= 1
    assert stats_payload["open_cases"] >= 1


def test_create_case_from_alert(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    analyst_email, analyst_password = _create_user(client, admin_token, "analyst")
    analyst_token = _login(client, analyst_email, analyst_password)

    alert_id = f"alert-{uuid.uuid4()}"
    db = SessionLocal()
    try:
        db.add(
            Alert(
                id=alert_id,
                timestamp=datetime.now(timezone.utc),
                severity="High",
                title="File Alert: Unauthorized Type",
                message="Upload blocked due to unauthorized mime type.",
                target="File_Analyzer_Service",
                acknowledged=False,
            )
        )
        db.commit()
    finally:
        db.close()

    created = client.post(f"/api/v1/cases/from-alert/{alert_id}", headers=_auth(analyst_token))
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["source_type"] == "alert"
    assert body["source_id"] == alert_id
    assert body["severity"] == "High"
    assert any(str(link.get("alert_id")) == alert_id for link in body.get("alert_links", []))

    links = client.get(f"/api/v1/cases/{body['id']}/alerts", headers=_auth(analyst_token))
    assert links.status_code == 200, links.text
    assert any(str(link.get("alert_id")) == alert_id for link in links.json().get("links", []))

    timeline = client.get("/api/v1/investigation/timeline?limit=50", headers=_auth(analyst_token))
    assert timeline.status_code == 200, timeline.text
    assert timeline.json()["count"] >= 1
