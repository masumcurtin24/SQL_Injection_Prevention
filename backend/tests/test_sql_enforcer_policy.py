import os
import importlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from backend.security.request_context import reset_current_service, set_current_service, sql_service_context


def reload_enforcer(env: dict):
    # Apply env vars for this test, then reload module
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = str(v)
    import backend.security.sql_enforcer as se
    importlib.reload(se)
    return se


def _text_execution_context(sql: str):
    return SimpleNamespace(compiled=SimpleNamespace(statement=text(sql)))


def test_union_select_critical():
    se = reload_enforcer({
        "SQL_ENFORCEMENT_MODE": "block_critical",
        "SQL_ALLOWLIST_PATTERNS": "",
    })
    res = se.decide("SELECT * FROM users WHERE id=1 UNION SELECT 1,2,3", None)
    assert res["decision"] in ("BLOCK_IMMEDIATE",), res
    assert res["risk"] == "Critical"
    assert "UNION" in res["explanation"].upper()


def test_tautology_high():
    se = reload_enforcer({
        "SQL_ENFORCEMENT_MODE": "block_high",
        "SQL_ALLOWLIST_PATTERNS": "",
    })
    res = se.decide("SELECT * FROM users WHERE username='a' OR '1'='1'", None)
    assert res["risk"] in ("High", "Critical")
    assert "TAUTOLOGY" in res["explanation"].upper()


def test_blind_subquery_exfiltration_is_critical_in_block_critical_mode():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_critical",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    payload = "SELECT * FROM invoices WHERE invoice_id = 10 AND SUBSTRING((SELECT version()),1,1)='1' --;"
    res = se.decide(payload, None)
    assert res["decision"] == "BLOCK_IMMEDIATE", res
    assert res["risk"] == "Critical"
    assert "blind_subquery_exfiltration" in (res.get("hits") or [])


def test_parameterization_required_flags():
    se = reload_enforcer({
        "SQL_ENFORCEMENT_MODE": "block_high",
        "SQL_REQUIRE_PARAMETERIZATION": "true",
    })

    token = set_current_service("/tests/sql-enforcer-policy")
    try:
        # Non-parameterized DML with literal
        res = se.decide("UPDATE users SET role='admin' WHERE id=42", None)
        assert res["decision"] in ("FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE")
        assert "parameter" in res["explanation"].lower()

        # Parameterized should pass
        res2 = se.decide("UPDATE users SET role=:role WHERE id=:id", {"role": "admin", "id": 1})
        assert res2["decision"] == "ALLOW"
        assert "allowed" in res2["explanation"].lower()
    finally:
        reset_current_service(token)


def test_ddl_exec_default_deny():
    se = reload_enforcer({
        "SQL_ENFORCEMENT_MODE": "block_critical",
        "SQL_DDL_EXEC_POLICY": "deny_non_migration",
        "SQL_DDL_EXEC_ALLOWED_SERVICES": "^alembic$",
    })
    res = se.decide("DROP TABLE users", None)
    assert res["decision"] == "BLOCK_IMMEDIATE"
    assert "DDL" in res["explanation"].upper()


def test_allowlist_safe_literal():
    se = reload_enforcer({
        "SQL_ALLOWLIST_MODE": "safe",
        "SQL_ALLOWLIST_PATTERNS": "SELECT 1",
    })
    res = se.decide("SELECT 1", None)
    assert res["decision"] == "ALLOW"
    assert "allowed by global allowlist".lower() in res["explanation"].lower()


def test_raw_sql_requires_approved_template_when_unparameterized():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_SECURE_CONSTRUCTION_MODE": "strict",
            "SQL_REQUIRE_APPROVED_RAW_SQL": "true",
            "SQL_RAW_SQL_ALLOW_CONSTANT_SELECT": "false",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    token = set_current_service("/tests/sql-enforcer-policy")
    try:
        sql = "SELECT * FROM users WHERE username='admin'"
        res = se.decide(sql, None, execution_context=_text_execution_context(sql))
        assert res["decision"] in ("FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"), res
        assert "unapproved_raw_sql" in (res.get("hits") or [])
    finally:
        reset_current_service(token)


def test_raw_sql_parameterized_text_clause_allowed_without_registry():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_SECURE_CONSTRUCTION_MODE": "strict",
            "SQL_REQUIRE_APPROVED_RAW_SQL": "true",
        }
    )
    token = set_current_service("/tests/sql-enforcer-policy")
    try:
        sql = "SELECT * FROM users WHERE username=:username"
        res = se.decide(
            sql,
            {"username": "admin"},
            execution_context=_text_execution_context(sql),
        )
        assert res["decision"] == "ALLOW", res
        assert "raw_sql_parameterized" in (res.get("hits") or [])
    finally:
        reset_current_service(token)


def test_raw_sql_health_probe_allowed_by_approved_template():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_SECURE_CONSTRUCTION_MODE": "strict",
            "SQL_REQUIRE_APPROVED_RAW_SQL": "true",
            "SQL_RAW_SQL_ALLOW_CONSTANT_SELECT": "false",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    se.SQL_RAW_SQL_ALLOW_CONSTANT_SELECT = False
    se.RAW_SQL_APPROVALS = se._compile_raw_sql_registry(
        [
            {
                "id": "approved-health-probe",
                "enabled": True,
                "service": "^/health/readiness$",
                "template": "SELECT 1",
                "reason": "Health readiness probe query",
                "role": "*",
                "tenant_id": "*",
                "allow_unparameterized": True,
            }
        ],
        section="approved_raw_sql",
    )
    se.RAW_SQL_EXCEPTIONS = []
    token = set_current_service("/health/readiness")
    try:
        sql = "SELECT 1"
        res = se.decide(sql, None, execution_context=_text_execution_context(sql))
        assert res["decision"] == "ALLOW", res
        assert "approved_raw_sql_template" in (res.get("hits") or [])
    finally:
        reset_current_service(token)


def test_raw_sql_service_mismatch_blocks_health_probe_template():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_SECURE_CONSTRUCTION_MODE": "strict",
            "SQL_REQUIRE_APPROVED_RAW_SQL": "true",
            "SQL_RAW_SQL_ALLOW_CONSTANT_SELECT": "false",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    se.SQL_RAW_SQL_ALLOW_CONSTANT_SELECT = False
    se.RAW_SQL_APPROVALS = se._compile_raw_sql_registry(
        [
            {
                "id": "approved-health-probe",
                "enabled": True,
                "service": "^/health/readiness$",
                "template": "SELECT 1",
                "reason": "Health readiness probe query",
                "role": "*",
                "tenant_id": "*",
                "allow_unparameterized": True,
            }
        ],
        section="approved_raw_sql",
    )
    se.RAW_SQL_EXCEPTIONS = []
    token = set_current_service("/tests/not-health")
    try:
        sql = "SELECT 1"
        res = se.decide(sql, None, execution_context=_text_execution_context(sql))
        assert res["decision"] in ("FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"), res
        assert "unapproved_raw_sql" in (res.get("hits") or [])
    finally:
        reset_current_service(token)


def test_raw_sql_migration_context_allows_unapproved_sql():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_SECURE_CONSTRUCTION_MODE": "strict",
            "SQL_REQUIRE_APPROVED_RAW_SQL": "true",
            "SQL_RAW_SQL_ALLOW_CONSTANT_SELECT": "false",
            "SQL_RAW_SQL_MIGRATION_SERVICE_PATTERN": "^alembic$",
        }
    )
    token = set_current_service("alembic")
    try:
        sql = "UPDATE users SET role='admin' WHERE id=42"
        res = se.decide(sql, None, execution_context=_text_execution_context(sql))
        assert res["decision"] == "ALLOW", res
        assert "raw_sql_migration_context" in (res.get("hits") or [])
    finally:
        reset_current_service(token)


def test_internal_balanced_profile_allows_non_parameterized_readonly_select():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_REQUIRE_PARAMETERIZATION": "true",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    se.SERVICE_PROFILES = se._compile_service_profiles(
        [
            {
                "id": "internal-balanced",
                "service": "^orders-api$",
                "require_parameterized_select": False,
                "require_parameterized_write": True,
                "require_approved_raw_sql": True,
            },
            {
                "id": "fallback-strict",
                "service": ".*",
                "require_parameterized_select": True,
                "require_parameterized_write": True,
                "require_approved_raw_sql": True,
            },
        ]
    )

    token = set_current_service("orders-api")
    try:
        res = se.decide("SELECT id, status FROM orders WHERE tenant_id = 55 AND status = 'pending'", None)
        assert res["decision"] == "ALLOW", res
        assert "non_parameterized_sql_advisory" in (res.get("hits") or [])
    finally:
        reset_current_service(token)


def test_external_strict_profile_blocks_non_parameterized_readonly_select():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_REQUIRE_PARAMETERIZATION": "true",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    se.SERVICE_PROFILES = se._compile_service_profiles(
        [
            {
                "id": "external-strict",
                "service": "^public-web-api$",
                "require_parameterized_select": True,
                "require_parameterized_write": True,
                "require_approved_raw_sql": True,
            }
        ]
    )
    token = set_current_service("public-web-api")
    try:
        res = se.decide("SELECT id, status FROM users WHERE tenant_id = 77 AND status = 'active'", None)
        assert res["decision"] in ("FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"), res
        assert "non_parameterized_sql" in (res.get("hits") or [])
    finally:
        reset_current_service(token)


def test_metadata_introspection_query_not_blocked_by_unknown_service_context():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_REQUIRE_SERVICE_CONTEXT": "true",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    res = se.decide('PRAGMA main.table_xinfo("users")', None)
    assert res["decision"] == "ALLOW", res
    assert "unknown_service" not in (res.get("hits") or [])


def test_auth_service_context_allows_parameterized_orm_lookup_without_unknown_service():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_REQUIRE_SERVICE_CONTEXT": "true",
            "SQL_REQUIRE_PARAMETERIZATION": "true",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    sql = "SELECT users.id AS users_id, users.email AS users_email FROM users WHERE users.email = ? LIMIT ? OFFSET ?"
    with sql_service_context("auth_service"):
        res = se.decide(sql, ("admin@example.com", 1, 0))
    assert res["decision"] == "ALLOW", res
    assert res["service"] == "auth_service"
    assert "unknown_service" not in (res.get("hits") or [])


def test_unknown_service_parameterized_auth_lookup_is_not_globally_allowed():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_REQUIRE_SERVICE_CONTEXT": "true",
            "SQL_REQUIRE_PARAMETERIZATION": "true",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    sql = "SELECT users.id AS users_id, users.email AS users_email FROM users WHERE users.email = ? LIMIT ? OFFSET ?"
    token = set_current_service("")
    try:
        res = se.decide(sql, ("admin@example.com", 1, 0))
    finally:
        reset_current_service(token)
    assert res["decision"] in ("FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"), res
    assert res["service"] == "unknown"
    assert "unknown_service" in (res.get("hits") or [])


def test_trusted_auth_service_context_does_not_bypass_malicious_sql():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_REQUIRE_SERVICE_CONTEXT": "true",
            "SQL_REQUIRE_PARAMETERIZATION": "true",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    sql = "SELECT * FROM users WHERE email = 'admin@example.com' OR '1'='1'"
    with sql_service_context("auth_service"):
        res = se.decide(sql, None)
        with pytest.raises(PermissionError):
            se.enforce(sql, None)
    assert res["decision"] in ("FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"), res
    assert res["service"] == "auth_service"
    assert "unknown_service" not in (res.get("hits") or [])
    assert {"quoted_tautology", "non_parameterized_sql"}.intersection(set(res.get("hits") or []))


def test_unknown_service_suspicious_sql_still_blocks():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_REQUIRE_SERVICE_CONTEXT": "true",
            "SQL_REQUIRE_PARAMETERIZATION": "true",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    sql = "SELECT * FROM users WHERE email = 'admin@example.com' OR '1'='1'"
    token = set_current_service("")
    try:
        with pytest.raises(PermissionError):
            se.enforce(sql, None)
        res = se.decide(sql, None)
    finally:
        reset_current_service(token)
    assert "unknown_service" in (res.get("hits") or [])
    assert res["decision"] in ("FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"), res


def test_expired_raw_sql_exception_does_not_match():
    se = reload_enforcer(
        {
            "SQL_ENFORCEMENT_MODE": "block_high",
            "SQL_SECURE_CONSTRUCTION_MODE": "strict",
            "SQL_REQUIRE_APPROVED_RAW_SQL": "true",
            "SQL_RAW_SQL_ALLOW_CONSTANT_SELECT": "false",
            "SQL_ALLOWLIST_PATTERNS": "",
        }
    )
    expired_iso = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d")
    se.RAW_SQL_APPROVALS = []
    se.RAW_SQL_EXCEPTIONS = se._compile_raw_sql_registry(
        [
            {
                "id": "expired-exception",
                "enabled": True,
                "service": "^legacy-admin-console$",
                "template": "SELECT * FROM users WHERE username='admin'",
                "reason": "Temporary emergency exception",
                "expires_at": expired_iso,
                "allow_unparameterized": True,
            }
        ],
        section="raw_sql_exceptions",
    )
    token = set_current_service("legacy-admin-console")
    try:
        sql = "SELECT * FROM users WHERE username='admin'"
        res = se.decide(sql, None, execution_context=_text_execution_context(sql))
        assert res["decision"] in ("FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"), res
        assert "raw_sql_exception" not in (res.get("hits") or [])
        assert "unapproved_raw_sql" in (res.get("hits") or [])
    finally:
        reset_current_service(token)
