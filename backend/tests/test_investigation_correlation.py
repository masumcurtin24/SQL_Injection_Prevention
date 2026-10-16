from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

from backend.core.database import SessionLocal
from backend.core.models import Alert, SQLAnalysisLog, FileAnalysisLog


def _login(client, email: str, password: str) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _auth(token: str, tenant_id: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id
    return headers


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


def _seed_sql_log(
    *,
    row_id: str,
    query_text: str,
    risk_level: str,
    ts: datetime,
    tenant_id: str = "tenant-primary",
) -> None:
    db = SessionLocal()
    try:
        row = SQLAnalysisLog(
            id=row_id,
            tenant_id=tenant_id,
            timestamp=ts,
            query_received=query_text,
            risk_level=risk_level,
            suggested_action="BLOCK_IMMEDIATE" if risk_level.lower() in {"high", "critical"} else "WARN",
            category="blocked" if risk_level.lower() in {"high", "critical"} else "suspicious",
            is_malicious=risk_level.lower() in {"high", "critical"},
        )
        row.anomaly_detection_result = {
            "is_anomalous": True,
            "score": 0.91,
            "prediction_label": "Anomalous",
        }
        row.query_validation_result = {
            "classification_label": "Malicious Signature",
            "classification_score": 0.88,
        }
        row.combined_assessment = {
            "overall_risk_level": risk_level,
            "suggested_action": row.suggested_action,
            "reasoning": ["Seeded for investigation correlation test."],
        }
        db.add(row)
        db.commit()
    finally:
        db.close()


def _seed_file_log(
    *,
    row_id: str,
    filename: str,
    ts: datetime,
    tenant_id: str = "tenant-primary",
    structured_iocs: list[dict] | None = None,
    legacy_hash: str | None = None,
) -> None:
    db = SessionLocal()
    try:
        row = FileAnalysisLog(
            id=row_id,
            tenant_id=tenant_id,
            timestamp=ts,
            filename=filename,
            filesize_kb=12.2,
            overall_status="Suspicious",
            recommended_action="FLAG_FOR_REVIEW",
            risk_score_value=0.73,
            category="suspicious",
        )
        details: dict = {
            "type_validation": {"detected_mime_type": "text/plain", "is_allowed_type": True},
            "malware_scan": {"is_malicious": False, "threat_name": None, "scan_details": {}},
            "ml_scan": {"is_suspicious_ml": True, "prediction_label_ml": "Suspicious_Text", "prediction_score_ml": 0.71},
        }
        if structured_iocs is not None:
            details["structured_verdict"] = {
                "analysis_id": row_id,
                "sample_id": filename,
                "classification": "suspicious",
                "severity": "medium",
                "score": 0.73,
                "confidence": 0.73,
                "declared_type": ".txt",
                "detected_type": "text/plain",
                "matched_rules": [],
                "matched_signatures": [],
                "iocs": structured_iocs,
                "evidence_items": [],
                "archive_lineage": [],
                "analysis_stages": [],
                "analyst_summary": "Seeded IOC verdict",
            }
        if legacy_hash:
            details["malware_scan"]["scan_details"]["sha256"] = legacy_hash
        row.file_details = details
        row.overall_assessment = {
            "overall_status": "Suspicious",
            "risk_score": 0.73,
            "recommended_action": "FLAG_FOR_REVIEW",
            "reasoning": ["Seeded file log for investigation IOC correlation tests."],
        }
        db.add(row)
        db.commit()
    finally:
        db.close()


def test_investigation_correlation_shared_query_fingerprint(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    analyst_email, analyst_password = _create_user(client, admin_token, "analyst")
    analyst_token = _login(client, analyst_email, analyst_password)

    base = datetime.now(timezone.utc).replace(microsecond=0)
    sql_id_1 = f"sql-corr-{uuid.uuid4()}"
    sql_id_2 = f"sql-corr-{uuid.uuid4()}"
    _seed_sql_log(
        row_id=sql_id_1,
        query_text="SELECT * FROM invoices WHERE invoice_id = 10 AND customer_id = 901",
        risk_level="High",
        ts=base - timedelta(minutes=2),
    )
    _seed_sql_log(
        row_id=sql_id_2,
        query_text="SELECT * FROM invoices WHERE invoice_id = 99 AND customer_id = 123",
        risk_level="Medium",
        ts=base - timedelta(minutes=1),
    )

    alert_id = f"alert-{sql_id_1}"
    db = SessionLocal()
    try:
        db.add(
            Alert(
                id=alert_id,
                tenant_id="tenant-primary",
                timestamp=base - timedelta(minutes=1),
                severity="High",
                title="SQL Alert: fingerprint chain",
                message="Correlated SQL threat candidate.",
                query="SELECT * FROM invoices WHERE invoice_id = 10 AND customer_id = 901",
            )
        )
        db.commit()
    finally:
        db.close()

    created = client.post(f"/api/v1/cases/from-alert/{alert_id}", headers=_auth(analyst_token))
    assert created.status_code == 200, created.text

    timeline = client.get(
        "/api/v1/investigation/timeline",
        headers=_auth(analyst_token),
        params={
            "limit": 120,
            "event_types": "query,alert,case,case_alert_link",
        },
    )
    assert timeline.status_code == 200, timeline.text
    payload = timeline.json()
    items = payload.get("items", [])
    assert items, payload

    first_query = next((item for item in items if item.get("id") == f"query:{sql_id_1}"), None)
    second_query = next((item for item in items if item.get("id") == f"query:{sql_id_2}"), None)
    assert first_query is not None, payload
    assert second_query is not None, payload

    related_events = first_query.get("related_events", [])
    paired = next((row for row in related_events if row.get("id") == f"query:{sql_id_2}"), None)
    assert paired is not None, related_events
    reason_codes = {str(reason.get("code")) for reason in paired.get("correlation_reasons", [])}
    assert "same_query_fingerprint" in reason_codes, paired

    aggregate_codes = {str(reason.get("code")) for reason in first_query.get("correlation_reasons", [])}
    assert "same_query_fingerprint" in aggregate_codes, first_query


def test_investigation_tenant_scope_enforced(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    analyst_email, analyst_password = _create_user(client, admin_token, "analyst")
    analyst_token = _login(client, analyst_email, analyst_password)

    base = datetime.now(timezone.utc).replace(microsecond=0)
    default_sql_id = f"sql-tenant-default-{uuid.uuid4()}"
    other_sql_id = f"sql-tenant-other-{uuid.uuid4()}"
    _seed_sql_log(
        row_id=default_sql_id,
        query_text="SELECT id FROM accounts WHERE id = 1",
        risk_level="Low",
        ts=base - timedelta(minutes=3),
        tenant_id="tenant-primary",
    )
    _seed_sql_log(
        row_id=other_sql_id,
        query_text="SELECT id FROM accounts WHERE id = 2",
        risk_level="High",
        ts=base - timedelta(minutes=2),
        tenant_id="tenant-other",
    )

    denied = client.get(
        "/api/v1/investigation/timeline",
        headers=_auth(analyst_token, tenant_id="tenant-other"),
        params={"limit": 50, "event_types": "query"},
    )
    assert denied.status_code == 403, denied.text

    scoped = client.get(
        "/api/v1/investigation/timeline",
        headers=_auth(analyst_token),
        params={"limit": 80, "event_types": "query"},
    )
    assert scoped.status_code == 200, scoped.text
    ids = {str(item.get("id")) for item in scoped.json().get("items", [])}
    assert f"query:{default_sql_id}" in ids, ids
    assert f"query:{other_sql_id}" not in ids, ids


def test_investigation_file_ioc_correlation_uses_structured_iocs(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    analyst_email, analyst_password = _create_user(client, admin_token, "analyst")
    analyst_token = _login(client, analyst_email, analyst_password)

    base = datetime.now(timezone.utc).replace(microsecond=0)
    file_id_1 = f"file-ioc-{uuid.uuid4()}"
    file_id_2 = f"file-ioc-{uuid.uuid4()}"
    common_domain = "evil.example"

    _seed_file_log(
        row_id=file_id_1,
        filename="first.txt",
        ts=base - timedelta(minutes=2),
        structured_iocs=[
            {
                "type": "domain",
                "value": common_domain,
                "source_stage": "content_scan",
                "source_path": None,
                "archive_lineage": None,
                "confidence": 0.88,
                "severity_hint": "medium",
                "dedup_key": f"domain:{common_domain}",
            },
            {
                "type": "url",
                "value": f"https://{common_domain}/login",
                "source_stage": "content_scan",
                "source_path": None,
                "archive_lineage": None,
                "confidence": 0.9,
                "severity_hint": "medium",
                "dedup_key": f"url:https://{common_domain}/login",
            },
        ],
    )
    _seed_file_log(
        row_id=file_id_2,
        filename="second.txt",
        ts=base - timedelta(minutes=1),
        structured_iocs=[
            {
                "type": "domain",
                "value": common_domain,
                "source_stage": "content_scan",
                "source_path": None,
                "archive_lineage": None,
                "confidence": 0.87,
                "severity_hint": "medium",
                "dedup_key": f"domain:{common_domain}",
            }
        ],
    )

    timeline = client.get(
        "/api/v1/investigation/timeline",
        headers=_auth(analyst_token),
        params={"limit": 120, "event_types": "file_scan"},
    )
    assert timeline.status_code == 200, timeline.text
    items = timeline.json().get("items", [])
    assert items

    left = next((item for item in items if item.get("id") == f"file_scan:{file_id_1}"), None)
    right = next((item for item in items if item.get("id") == f"file_scan:{file_id_2}"), None)
    assert left is not None, items
    assert right is not None, items

    reasons = {str(reason.get("code")) for reason in left.get("correlation_reasons", [])}
    assert "same_domain" in reasons or "same_url_host" in reasons, left


def test_investigation_file_ioc_backward_compat_without_structured_iocs(client):
    admin_token = _login(client, "admin@example.com", "admin-password-123")
    analyst_email, analyst_password = _create_user(client, admin_token, "analyst")
    analyst_token = _login(client, analyst_email, analyst_password)

    base = datetime.now(timezone.utc).replace(microsecond=0)
    file_id_1 = f"file-legacy-{uuid.uuid4()}"
    file_id_2 = f"file-legacy-{uuid.uuid4()}"
    shared_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649bf2e6b6fa3f31c0b5d5d8"

    _seed_file_log(
        row_id=file_id_1,
        filename="legacy-hash.txt",
        ts=base - timedelta(minutes=2),
        structured_iocs=None,
        legacy_hash=shared_hash,
    )
    _seed_file_log(
        row_id=file_id_2,
        filename="structured-hash.txt",
        ts=base - timedelta(minutes=1),
        structured_iocs=[
            {
                "type": "hash",
                "value": shared_hash,
                "source_stage": "hashing",
                "source_path": None,
                "archive_lineage": None,
                "confidence": 0.99,
                "severity_hint": "medium",
                "dedup_key": f"hash:{shared_hash}",
            }
        ],
    )

    timeline = client.get(
        "/api/v1/investigation/timeline",
        headers=_auth(analyst_token),
        params={"limit": 120, "event_types": "file_scan"},
    )
    assert timeline.status_code == 200, timeline.text
    items = timeline.json().get("items", [])

    left = next((item for item in items if item.get("id") == f"file_scan:{file_id_1}"), None)
    right = next((item for item in items if item.get("id") == f"file_scan:{file_id_2}"), None)
    assert left is not None and right is not None, items

    related = next((evt for evt in left.get("related_events", []) if evt.get("id") == f"file_scan:{file_id_2}"), None)
    assert related is not None, left
    reason_codes = {str(reason.get("code")) for reason in related.get("correlation_reasons", [])}
    assert "same_file_hash" in reason_codes, related
