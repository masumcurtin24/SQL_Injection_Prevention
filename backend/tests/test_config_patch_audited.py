import json
from pathlib import Path

import yaml

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


def test_config_patch_updates_file_and_is_audited(client):
    config_path = Path(__file__).resolve().parents[1] / "security" / "prevention_rules.yml"
    original_raw = config_path.read_bytes()

    try:
        current = yaml.safe_load(original_raw.decode("utf-8")) or {}
        old_backoff = int(current["monitor"]["backoff_n"])
        new_backoff = old_backoff + 1

        headers = _admin_headers_with_step_up(client, actions=["config.sql_enforcement.patch"])

        patched = client.patch(
            "/api/v1/config/sql-enforcement",
            headers=headers,
            json={"monitor": {"backoff_n": new_backoff}},
        )
        assert patched.status_code == 200, patched.text
        payload = patched.json()
        assert payload["restart_required"] is True
        assert "monitor.backoff_n" in payload["changed_paths"]
        assert len(payload["before_sha256"]) == 64
        assert len(payload["after_sha256"]) == 64
        assert payload["before_sha256"] != payload["after_sha256"]

        updated_raw = config_path.read_bytes()
        assert updated_raw
        updated = yaml.safe_load(updated_raw.decode("utf-8"))
        assert int(updated["monitor"]["backoff_n"]) == new_backoff

        db = SessionLocal()
        try:
            row = (
                db.query(AuditLog)
                .filter(AuditLog.action == "config.sql_enforcement.patch")
                .order_by(AuditLog.timestamp.desc())
                .first()
            )
            assert row is not None
            assert row.success is True
            details = json.loads(row.details_json or "{}")
            assert details.get("before_sha256") == payload["before_sha256"]
            assert details.get("after_sha256") == payload["after_sha256"]
            assert "monitor.backoff_n" in (details.get("changed_paths") or [])
        finally:
            db.close()
    finally:
        config_path.write_bytes(original_raw)
