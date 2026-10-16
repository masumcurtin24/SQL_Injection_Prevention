import importlib
import json
import os
import uuid
from datetime import datetime, timezone

import pytest

from backend.core.database import SessionLocal
from backend.core.models import AuditLog, DEFAULT_TENANT_ID, User


@pytest.fixture(autouse=True)
def _enforcement_disabled_for_governance_tests():
    keys = (
        "SQL_ENFORCEMENT_MODE",
        "SQL_REQUIRE_SERVICE_CONTEXT",
        "SQL_ALLOWLIST_PATTERNS",
    )
    previous = {k: os.environ.get(k) for k in keys}
    os.environ["SQL_ENFORCEMENT_MODE"] = "off"
    os.environ["SQL_REQUIRE_SERVICE_CONTEXT"] = "false"
    os.environ.setdefault("SQL_ALLOWLIST_PATTERNS", "")
    import backend.security.sql_enforcer as sql_enforcer

    importlib.reload(sql_enforcer)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        importlib.reload(sql_enforcer)


def _admin_headers(client):
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_governance_overview_exposes_domain_support_matrix(client):
    headers = _admin_headers(client)
    response = client.get("/api/v1/config/governance-overview", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()

    domains = payload.get("domains") or {}
    assert set(("sql", "file", "email", "suppressions")).issubset(set(domains.keys()))

    assert domains["sql"]["support"] == "editable"
    assert "config.sql_enforcement.patch" in (domains["sql"].get("writable_actions") or [])
    assert domains["file"]["support"] == "read_only"
    assert domains["email"]["support"] == "partially_supported"
    assert domains["suppressions"]["support"] == "partially_supported"
    sql_expiry = ((domains["sql"].get("metadata") or {}).get("sql_construction_expiry") or {})
    assert "approved_raw_sql" in sql_expiry
    assert "raw_sql_exceptions" in sql_expiry
    assert "expired" in (sql_expiry.get("approved_raw_sql") or {})
    assert "near_expiry" in (sql_expiry.get("raw_sql_exceptions") or {})
    assert isinstance(payload.get("recent_changes"), list)


def test_governance_overview_includes_recent_governance_audit_entries(client):
    headers = _admin_headers(client)

    db = SessionLocal()
    audit_id = str(uuid.uuid4())
    try:
        admin_user = db.query(User).filter(User.email == "admin@example.com").first()
        assert admin_user is not None
        tenant_id = str(getattr(admin_user, "tenant_id", "") or DEFAULT_TENANT_ID)

        row = AuditLog(
            id=audit_id,
            timestamp=datetime.now(timezone.utc),
            tenant_id=tenant_id,
            actor_user_id=admin_user.id,
            action="spam.settings.update",
            resource_type="config",
            resource_id="spam-settings",
            success=True,
            details_json=json.dumps({"changed_keys": ["final_threshold"]}),
        )
        db.add(row)
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/config/governance-overview", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    changes = payload.get("recent_changes") or []
    assert any(change.get("id") == audit_id and change.get("action") == "spam.settings.update" for change in changes)
