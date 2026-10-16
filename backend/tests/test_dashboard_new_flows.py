from __future__ import annotations

from datetime import datetime, timezone
import uuid

from backend.core.database import SessionLocal
from backend.core.models import Alert, FileAnalysisLog, SQLAnalysisLog, SpamAnalysisLog
from backend.services.dashboard_service import DashboardService


def _admin_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _create_user_and_login(client, role: str) -> str:
    admin_token = _admin_token(client)
    email = f"{role}-{uuid.uuid4()}@example.com"
    password = f"{role}-password-123"
    created = client.post(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email": email, "password": password, "role": role},
    )
    assert created.status_code == 200, created.text

    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _seed_dashboard_rows() -> dict[str, str]:
    now = datetime.now(timezone.utc)
    day = now.date().isoformat()

    ids = {
        "day": day,
        "sql_safe": f"sql-safe-{uuid.uuid4()}",
        "sql_suspicious": f"sql-suspicious-{uuid.uuid4()}",
        "sql_blocked": f"sql-blocked-{uuid.uuid4()}",
        "file_safe": f"file-safe-{uuid.uuid4()}",
        "file_suspicious": f"file-suspicious-{uuid.uuid4()}",
        "file_blocked": f"file-blocked-{uuid.uuid4()}",
        "spam_safe": f"email-spam-safe-{uuid.uuid4()}",
        "spam_suspicious": f"email-spam-suspicious-{uuid.uuid4()}",
        "spam_blocked": f"email-spam-blocked-{uuid.uuid4()}",
    }
    ids["alert"] = f"alert-{ids['sql_blocked']}"

    db = SessionLocal()
    try:
        sql_safe = SQLAnalysisLog(id=ids["sql_safe"], timestamp=now, query_received="SELECT 1")
        sql_safe.anomaly_detection_result = {"is_anomalous": False, "score": 0.1, "prediction_label": "Normal"}
        sql_safe.query_validation_result = {"classification_label": "Benign", "classification_score": 0.2}
        sql_safe.combined_assessment = {"overall_risk_level": "Low", "suggested_action": "ALLOW", "reasoning": []}
        sql_safe.risk_level = "Low"
        sql_safe.suggested_action = "ALLOW"
        sql_safe.category = "safe"
        sql_safe.is_malicious = False

        sql_suspicious = SQLAnalysisLog(id=ids["sql_suspicious"], timestamp=now, query_received="SELECT * FROM products WHERE id=1 OR 1=1")
        sql_suspicious.anomaly_detection_result = {"is_anomalous": True, "score": 0.8, "prediction_label": "Anomalous"}
        sql_suspicious.query_validation_result = {"classification_label": "Suspicious", "classification_score": 0.7}
        sql_suspicious.combined_assessment = {
            "overall_risk_level": "Medium",
            "suggested_action": "FLAG_REVIEW",
            "reasoning": ["Boolean condition pattern detected"],
        }
        sql_suspicious.risk_level = "Medium"
        sql_suspicious.suggested_action = "FLAG_REVIEW"
        sql_suspicious.category = "suspicious"
        sql_suspicious.is_malicious = False

        sql_blocked = SQLAnalysisLog(id=ids["sql_blocked"], timestamp=now, query_received="SELECT * FROM users; DROP TABLE users; --")
        sql_blocked.anomaly_detection_result = {"is_anomalous": True, "score": 0.99, "prediction_label": "Anomalous"}
        sql_blocked.query_validation_result = {"classification_label": "Malicious", "classification_score": 0.99}
        sql_blocked.combined_assessment = {
            "overall_risk_level": "High",
            "suggested_action": "BLOCK_IMMEDIATE",
            "reasoning": ["DDL abuse detected"],
        }
        sql_blocked.risk_level = "High"
        sql_blocked.suggested_action = "BLOCK_IMMEDIATE"
        sql_blocked.category = "blocked"
        sql_blocked.is_malicious = True

        file_safe = FileAnalysisLog(id=ids["file_safe"], timestamp=now, filename="safe-notes.txt", filesize_kb=4.2)
        file_safe.file_details = {
            "type_validation": {"detected_mime_type": "text/plain", "is_allowed_type": True},
            "malware_scan": {"is_malicious": False, "threat_name": None, "scan_details": {}},
            "ml_scan": {"is_suspicious_ml": False, "prediction_label_ml": "Benign_Text", "prediction_score_ml": 0.11},
        }
        file_safe.overall_assessment = {
            "overall_status": "Safe",
            "risk_score": 0.1,
            "recommended_action": "ALLOW_UPLOAD",
            "reasoning": ["No suspicious indicators found"],
        }
        file_safe.overall_status = "Safe"
        file_safe.risk_score_value = 0.1
        file_safe.recommended_action = "ALLOW_UPLOAD"
        file_safe.category = "safe"

        file_suspicious = FileAnalysisLog(id=ids["file_suspicious"], timestamp=now, filename="suspicious-report.html", filesize_kb=24.4)
        file_suspicious.file_details = {
            "type_validation": {"detected_mime_type": "text/html", "is_allowed_type": True},
            "malware_scan": {"is_malicious": False, "threat_name": None, "scan_details": {}},
            "ml_scan": {"is_suspicious_ml": True, "prediction_label_ml": "Suspicious_Text", "prediction_score_ml": 0.73},
        }
        file_suspicious.overall_assessment = {
            "overall_status": "Suspicious",
            "risk_score": 0.66,
            "recommended_action": "FLAG_REVIEW",
            "reasoning": ["HTML script indicators found"],
        }
        file_suspicious.overall_status = "Suspicious"
        file_suspicious.risk_score_value = 0.66
        file_suspicious.recommended_action = "FLAG_REVIEW"
        file_suspicious.category = "suspicious"

        file_blocked = FileAnalysisLog(id=ids["file_blocked"], timestamp=now, filename="blocked-payload.pdf", filesize_kb=90.1)
        file_blocked.file_details = {
            "type_validation": {"detected_mime_type": "application/pdf", "is_allowed_type": True},
            "malware_scan": {"is_malicious": True, "threat_name": "exploit_poc_pdf", "scan_details": {"outer_yara_matches": ["exploit_poc_pdf"]}},
            "ml_scan": {"is_suspicious_ml": True, "prediction_label_ml": "Malicious_Text", "prediction_score_ml": 0.94},
        }
        file_blocked.overall_assessment = {
            "overall_status": "Malicious",
            "risk_score": 0.95,
            "recommended_action": "BLOCK_UPLOAD_QUARANTINE",
            "reasoning": ["YARA match: exploit_poc_pdf"],
        }
        file_blocked.overall_status = "Malicious"
        file_blocked.risk_score_value = 0.95
        file_blocked.recommended_action = "BLOCK_UPLOAD_QUARANTINE"
        file_blocked.category = "blocked"

        spam_safe = SpamAnalysisLog(id=ids["spam_safe"], timestamp=now, received_subject="Team sync agenda")
        spam_safe.spam_classification_result = {"is_spam": False, "spam_score": 0.09, "classification_label": "Ham"}
        spam_safe.errors = None
        spam_safe.is_spam = False
        spam_safe.spam_score = 0.09
        spam_safe.classification_label = "Ham"
        spam_safe.category = "safe"

        spam_suspicious = SpamAnalysisLog(id=ids["spam_suspicious"], timestamp=now, received_subject="Invoice update required")
        spam_suspicious.spam_classification_result = {"is_spam": True, "spam_score": 0.72, "classification_label": "Spam"}
        spam_suspicious.errors = None
        spam_suspicious.is_spam = True
        spam_suspicious.spam_score = 0.72
        spam_suspicious.classification_label = "Spam"
        spam_suspicious.category = "suspicious"

        spam_blocked = SpamAnalysisLog(id=ids["spam_blocked"], timestamp=now, received_subject="Urgent phishing confirmation")
        spam_blocked.spam_classification_result = {"is_spam": True, "spam_score": 0.96, "classification_label": "Phishing"}
        spam_blocked.errors = None
        spam_blocked.is_spam = True
        spam_blocked.spam_score = 0.96
        spam_blocked.classification_label = "Phishing"
        spam_blocked.category = "blocked"

        alert = Alert(
            id=ids["alert"],
            timestamp=now,
            severity="High",
            title="SQL Alert: High Risk Query",
            message="Detected malicious SQL pattern.",
            query=sql_blocked.query_received,
            acknowledged=False,
        )
        alert.tags = ["sqli", "block"]

        db.add_all(
            [
                sql_safe,
                sql_suspicious,
                sql_blocked,
                file_safe,
                file_suspicious,
                file_blocked,
                spam_safe,
                spam_suspicious,
                spam_blocked,
                alert,
            ]
        )
        db.commit()
        return ids
    finally:
        db.close()


def test_dashboard_files_scanned_endpoint_and_categories(client):
    ids = _seed_dashboard_rows()
    token = _admin_token(client)
    res = client.get(
        f"/api/v1/dashboard/files-scanned?day={ids['day']}&limit=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload["day"] == ids["day"]
    by_id = {row["analysis_id"]: row for row in payload["files"]}
    assert by_id[ids["file_safe"]]["category"] == "safe"
    assert by_id[ids["file_suspicious"]]["category"] == "suspicious"
    assert by_id[ids["file_blocked"]]["category"] == "blocked"


def test_dashboard_sql_queries_endpoint_and_categories(client):
    ids = _seed_dashboard_rows()
    token = _admin_token(client)
    res = client.get(
        f"/api/v1/dashboard/sql-queries?day={ids['day']}&limit=1000&malicious_only=false",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    payload = res.json()
    by_id = {row["analysis_id"]: row for row in payload["queries"]}
    assert by_id[ids["sql_safe"]]["category"] == "safe"
    assert by_id[ids["sql_suspicious"]]["category"] == "suspicious"
    assert by_id[ids["sql_blocked"]]["category"] == "blocked"

    malicious = client.get(
        f"/api/v1/dashboard/sql-queries?day={ids['day']}&limit=1000&malicious_only=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert malicious.status_code == 200, malicious.text
    m_payload = malicious.json()
    m_ids = {row["analysis_id"] for row in m_payload["queries"]}
    assert ids["sql_blocked"] in m_ids
    assert ids["sql_safe"] not in m_ids
    assert ids["sql_suspicious"] not in m_ids


def test_dashboard_spam_detections_endpoint_and_categories(client):
    ids = _seed_dashboard_rows()
    token = _admin_token(client)
    res = client.get(
        f"/api/v1/dashboard/spam-detections?day={ids['day']}&limit=1000&detected_only=false",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    payload = res.json()
    by_id = {row["analysis_id"]: row for row in payload["detections"]}
    assert by_id[ids["spam_safe"]]["category"] == "safe"
    assert by_id[ids["spam_suspicious"]]["category"] == "suspicious"
    assert by_id[ids["spam_blocked"]]["category"] == "blocked"

    detected = client.get(
        f"/api/v1/dashboard/spam-detections?day={ids['day']}&limit=1000&detected_only=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert detected.status_code == 200, detected.text
    d_payload = detected.json()
    d_ids = {row["analysis_id"] for row in d_payload["detections"]}
    assert ids["spam_safe"] not in d_ids
    assert ids["spam_suspicious"] in d_ids
    assert ids["spam_blocked"] in d_ids


def test_dashboard_stats_includes_sql_risk_posture_card_fields(client):
    ids = _seed_dashboard_rows()
    token = _admin_token(client)
    res = client.get(
        f"/api/v1/dashboard/stats?scope=today&day={ids['day']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    payload = res.json()

    assert "sql_risk_posture_score" in payload
    assert "sql_precision_score" in payload  # Deprecated compatibility alias, not statistical precision.
    assert "sql_avg_calibrated_risk" in payload
    assert "sql_high_risk_rate" in payload
    assert "sql_precision_sample_size" in payload

    assert 0.0 <= float(payload["sql_risk_posture_score"]) <= 100.0
    assert 0.0 <= float(payload["sql_precision_score"]) <= 100.0
    assert float(payload["sql_precision_score"]) == float(payload["sql_risk_posture_score"])
    assert 0.0 <= float(payload["sql_avg_calibrated_risk"]) <= 1.0
    assert 0.0 <= float(payload["sql_high_risk_rate"]) <= 100.0
    assert int(payload["sql_precision_sample_size"]) >= 0


def test_dashboard_executive_overview_endpoint_returns_posture_and_domain_breakdown(client):
    ids = _seed_dashboard_rows()
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    day_res = client.get(
        f"/api/v1/dashboard/executive-overview?scope=today&day={ids['day']}",
        headers=headers,
    )
    assert day_res.status_code == 200, day_res.text
    day_payload = day_res.json()

    assert day_payload["scope"] == "today"
    assert day_payload["day"] == ids["day"]
    assert day_payload["security_posture"] in {"stable", "watch", "critical"}
    assert 0 <= int(day_payload["posture_score"]) <= 100

    totals = day_payload["totals"]
    assert int(totals["analysis_events"]) >= 9
    assert int(totals["blocked"]) >= 3
    assert int(totals["suspicious"]) >= 3

    domains = day_payload["domains"]
    assert int(domains["sql"]["blocked"]) >= 1
    assert int(domains["file"]["blocked"]) >= 1
    assert int(domains["spam"]["blocked"]) >= 1
    assert isinstance(day_payload["top_risks"], list)

    total_res = client.get(
        "/api/v1/dashboard/executive-overview?scope=total",
        headers=headers,
    )
    assert total_res.status_code == 200, total_res.text
    total_payload = total_res.json()
    assert total_payload["scope"] == "total"
    assert total_payload["day"] is None


def test_dashboard_detail_endpoints_support_pagination_search_and_category_filters(client):
    ids = _seed_dashboard_rows()
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    files_page = client.get(
        f"/api/v1/dashboard/files-scanned?day={ids['day']}&page=1&page_size=1",
        headers=headers,
    )
    assert files_page.status_code == 200, files_page.text
    files_page_payload = files_page.json()
    assert files_page_payload["page"] == 1
    assert files_page_payload["page_size"] == 1
    assert files_page_payload["count"] == 1
    assert files_page_payload["total"] >= 3
    assert files_page_payload["total_pages"] >= 3

    files_filtered = client.get(
        f"/api/v1/dashboard/files-scanned?day={ids['day']}&page=1&page_size=10&search={ids['file_blocked']}&category=blocked",
        headers=headers,
    )
    assert files_filtered.status_code == 200, files_filtered.text
    files_payload = files_filtered.json()
    assert files_payload["total"] >= 1
    file_ids = {row["analysis_id"] for row in files_payload["files"]}
    assert ids["file_blocked"] in file_ids
    assert all(row["category"] == "blocked" for row in files_payload["files"])

    sql_filtered = client.get(
        f"/api/v1/dashboard/sql-queries?day={ids['day']}&page=1&page_size=10&search={ids['sql_blocked']}&category=blocked&malicious_only=true",
        headers=headers,
    )
    assert sql_filtered.status_code == 200, sql_filtered.text
    sql_payload = sql_filtered.json()
    sql_ids = {row["analysis_id"] for row in sql_payload["queries"]}
    assert ids["sql_blocked"] in sql_ids
    assert all(row["category"] == "blocked" for row in sql_payload["queries"])

    sql_empty = client.get(
        f"/api/v1/dashboard/sql-queries?day={ids['day']}&page=1&page_size=10&category=safe&malicious_only=true",
        headers=headers,
    )
    assert sql_empty.status_code == 200, sql_empty.text
    sql_empty_payload = sql_empty.json()
    assert sql_empty_payload["total"] == 0
    assert sql_empty_payload["count"] == 0
    assert sql_empty_payload["queries"] == []

    spam_filtered = client.get(
        f"/api/v1/dashboard/spam-detections?day={ids['day']}&page=1&page_size=10&search={ids['spam_blocked']}&category=blocked&detected_only=true",
        headers=headers,
    )
    assert spam_filtered.status_code == 200, spam_filtered.text
    spam_payload = spam_filtered.json()
    spam_ids = {row["analysis_id"] for row in spam_payload["detections"]}
    assert ids["spam_blocked"] in spam_ids
    assert all(row["category"] == "blocked" for row in spam_payload["detections"])


def test_dashboard_live_event_detail_endpoint_for_all_supported_types(client):
    ids = _seed_dashboard_rows()
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    query_res = client.get(
        f"/api/v1/dashboard/live-events/detail?event_type=query&event_id={ids['sql_blocked']}",
        headers=headers,
    )
    assert query_res.status_code == 200, query_res.text
    assert query_res.json()["type"] == "query"

    file_res = client.get(
        f"/api/v1/dashboard/live-events/detail?event_type=file_scan&event_id={ids['file_blocked']}",
        headers=headers,
    )
    assert file_res.status_code == 200, file_res.text
    assert file_res.json()["type"] == "file_scan"

    spam_res = client.get(
        f"/api/v1/dashboard/live-events/detail?event_type=spam_check&event_id={ids['spam_blocked']}",
        headers=headers,
    )
    assert spam_res.status_code == 200, spam_res.text
    assert spam_res.json()["type"] == "spam_check"

    alert_res = client.get(
        f"/api/v1/dashboard/live-events/detail?event_type=alert&event_id={ids['alert']}",
        headers=headers,
    )
    assert alert_res.status_code == 200, alert_res.text
    payload = alert_res.json()
    assert payload["type"] == "alert"
    assert payload["details"]["id"] == ids["alert"]


def test_dashboard_live_events_endpoint_supports_day_cursor_and_type_filters(client):
    ids = _seed_dashboard_rows()
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    day_res = client.get(
        f"/api/v1/dashboard/live-events?day={ids['day']}&limit=2",
        headers=headers,
    )
    assert day_res.status_code == 200, day_res.text
    day_payload = day_res.json()
    assert day_payload["day"] == ids["day"]
    assert day_payload["limit"] == 2
    assert len(day_payload["events"]) <= 2
    assert all(str(event.get("timestamp") or "").startswith(ids["day"]) for event in day_payload["events"])

    type_res = client.get(
        "/api/v1/dashboard/live-events?limit=10&event_types=file_scan",
        headers=headers,
    )
    assert type_res.status_code == 200, type_res.text
    type_payload = type_res.json()
    assert all(event["type"] == "file_scan" for event in type_payload["events"])

    next_before = day_payload.get("next_before")
    if next_before:
        page2 = client.get(
            "/api/v1/dashboard/live-events",
            params={"day": ids["day"], "limit": 2, "before": next_before},
            headers=headers,
        )
        assert page2.status_code == 200, page2.text
        page2_payload = page2.json()
        assert all(str(event.get("timestamp") or "") < str(next_before) for event in page2_payload.get("events", []))


def test_dashboard_live_events_viewer_scope_forces_today_and_non_alert_types(client):
    ids = _seed_dashboard_rows()
    viewer_token = _create_user_and_login(client, role="viewer")
    headers = {"Authorization": f"Bearer {viewer_token}"}

    requested_day = "2000-01-01"
    res = client.get(
        f"/api/v1/dashboard/live-events?limit=100&day={requested_day}&event_types=alert",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload.get("scope") == "viewer"
    assert payload.get("day") == ids["day"]
    assert payload.get("event_types") == "query,file_scan,spam_check"
    assert all(event.get("type") in {"query", "file_scan", "spam_check"} for event in payload.get("events", []))
    assert all(str(event.get("timestamp") or "").startswith(ids["day"]) for event in payload.get("events", []))


def test_dashboard_category_helpers_explicit_logic():
    assert DashboardService.classify_file_category(
        {"overall_status": "Safe", "recommended_action": "ALLOW_UPLOAD", "risk_score": 0.1}
    ) == "safe"
    assert DashboardService.classify_file_category(
        {"overall_status": "Suspicious", "recommended_action": "FLAG_REVIEW", "risk_score": 0.7}
    ) == "suspicious"
    assert DashboardService.classify_file_category(
        {"overall_status": "Malicious", "recommended_action": "BLOCK_UPLOAD_QUARANTINE", "risk_score": 0.95}
    ) == "blocked"

    assert DashboardService.classify_sql_category(
        {"risk_level": "Low", "suggested_action": "ALLOW", "is_anomalous": False}
    ) == "safe"
    assert DashboardService.classify_sql_category(
        {"risk_level": "Medium", "suggested_action": "FLAG_REVIEW", "is_anomalous": True}
    ) == "suspicious"
    assert DashboardService.classify_sql_category(
        {"risk_level": "High", "suggested_action": "BLOCK_IMMEDIATE", "is_anomalous": True}
    ) == "blocked"

    assert DashboardService.classify_spam_category(
        {"is_spam": False, "spam_score": 0.1, "classification_label": "Ham"}
    ) == "safe"
    assert DashboardService.classify_spam_category(
        {"is_spam": True, "spam_score": 0.7, "classification_label": "Spam"}
    ) == "suspicious"
    assert DashboardService.classify_spam_category(
        {"is_spam": True, "spam_score": 0.95, "classification_label": "Phishing"}
    ) == "blocked"


def test_dashboard_platform_health_endpoint_returns_aggregated_payload(client):
    _seed_dashboard_rows()
    token = _admin_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get(
        "/api/v1/dashboard/platform-health?top=10&fp_days=30&analyst_only=true",
        headers=headers,
    )
    assert res.status_code == 200, res.text
    payload = res.json()

    assert payload["overall_status"] in {"healthy", "degraded", "critical", "unknown"}
    assert isinstance(payload.get("score"), int)
    assert "as_of" in payload
    assert isinstance(payload.get("issues"), list)
    assert isinstance(payload.get("warnings"), list)

    components = payload.get("components") or {}
    assert "http" in components
    assert "websocket" in components
    assert "queue" in components
    assert "models" in components
    assert "quality" in components

    assert components["http"]["status"] in {"healthy", "degraded", "critical", "unknown"}
    assert isinstance(components["http"].get("top_error_endpoints"), list)
    assert isinstance(components["http"].get("top_slow_endpoints"), list)
    assert components["quality"]["status"] in {"healthy", "degraded", "critical", "unknown"}


def test_dashboard_platform_health_requires_analyst_role(client):
    viewer_token = _create_user_and_login(client, role="viewer")
    headers = {"Authorization": f"Bearer {viewer_token}"}

    res = client.get("/api/v1/dashboard/platform-health", headers=headers)
    assert res.status_code == 403, res.text
