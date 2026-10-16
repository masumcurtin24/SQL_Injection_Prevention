# backend/security/sql_enforcer.py
from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

from backend.utils.logging_utils import setup_logger

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

from .sql_normalizer import canonicalize

logger = setup_logger(__name__)

# Modes: off | monitor | block_high | block_critical
ENFORCEMENT_MODE = os.getenv("SQL_ENFORCEMENT_MODE", "block_critical").strip().lower()
SQL_REQUIRE_PARAMETERIZATION = os.getenv("SQL_REQUIRE_PARAMETERIZATION", "false").strip().lower() in {"1", "true", "yes", "y"}
DDL_EXEC_POLICY = os.getenv("SQL_DDL_EXEC_POLICY", "deny_non_migration").strip().lower()  # deny | monitor | allow | deny_non_migration
DDL_EXEC_ALLOWED_SERVICES = os.getenv("SQL_DDL_EXEC_ALLOWED_SERVICES", "").strip()  # regex for service path/name
DDL_EXEC_ALLOWLIST_PATTERNS = [p.strip() for p in os.getenv("SQL_DDL_EXEC_ALLOWLIST_PATTERNS", "").split(",") if p.strip()]
ALLOWLIST_MODE = os.getenv("SQL_ALLOWLIST_MODE", "safe").strip().lower()  # safe | regex
SQL_REQUIRE_SERVICE_CONTEXT = os.getenv("SQL_REQUIRE_SERVICE_CONTEXT", "true").strip().lower() in {"1", "true", "yes", "y"}
SQL_HEURISTICS_TIMEOUT_MS = int(os.getenv("SQL_HEURISTICS_TIMEOUT_MS", "200"))  # budget for heuristics
ALLOWLIST_MAX_AGE_DAYS = int(os.getenv("ALLOWLIST_MAX_AGE_DAYS", "180"))
ALLOWLIST_LAST_REVIEWED_AT = os.getenv("SQL_ALLOWLIST_LAST_REVIEWED_AT", "")  # YYYY-MM-DD
SQL_TELEMETRY_FILE = os.getenv("SQL_TELEMETRY_FILE", "")

# Secure-by-construction controls.
# off: disabled, monitor: annotate/report, strict: enforce block/flag on violations
SQL_SECURE_CONSTRUCTION_MODE = os.getenv("SQL_SECURE_CONSTRUCTION_MODE", "strict").strip().lower()
SQL_REQUIRE_APPROVED_RAW_SQL = os.getenv("SQL_REQUIRE_APPROVED_RAW_SQL", "true").strip().lower() in {"1", "true", "yes", "y"}
SQL_RAW_SQL_UNKNOWN_ACTION = os.getenv("SQL_RAW_SQL_UNKNOWN_ACTION", "flag_for_review_block").strip().lower()
SQL_RAW_SQL_MIGRATION_SERVICE_PATTERN = os.getenv(
    "SQL_RAW_SQL_MIGRATION_SERVICE_PATTERN",
    "^alembic$|^/admin/migrations$|^/startup/bootstrap-admin$",
).strip()
SQL_RAW_SQL_ALLOW_CONSTANT_SELECT = os.getenv("SQL_RAW_SQL_ALLOW_CONSTANT_SELECT", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "y",
}

ROLE_ORDER: Dict[str, int] = {"viewer": 1, "reviewer": 2, "analyst": 3, "admin": 4}

RAW_SQL_APPROVALS: List[Dict[str, Any]] = []
RAW_SQL_EXCEPTIONS: List[Dict[str, Any]] = []
SERVICE_PROFILES: List[Dict[str, Any]] = []

try:
    HEURISTICS_HIGH_THRESHOLD = float(os.getenv("HEURISTICS_HIGH_THRESHOLD", "0.75"))
except Exception:
    HEURISTICS_HIGH_THRESHOLD = 0.75

_DEFAULT_CRITICAL_CODES = {
    "stacked_query_dml",
    "xp_cmdshell",
    "union_select",
    "time_sleep",
    "time_pg_sleep",
    "time_benchmark",
    "time_waitfor_delay",
    "xp_dirtree",
    "xp_regread",
    "openrowset",
    "copy_to_program",
    "sp_oacreate",
    "blind_subquery_exfiltration",
    "oracle_utl",
    "oracle_dbms_pipe",
}
_env_codes = os.getenv("HEURISTICS_CRITICAL_CODES", "").strip()
CRITICAL_CODES: set = set([c.strip() for c in _env_codes.split(",") if c.strip()]) or _DEFAULT_CRITICAL_CODES
YAML_CRITICAL_PATTERNS: List[re.Pattern] = []
_SERVICE_HEURISTICS_UNAVAILABLE_LOGGED = False

_SMART_SQL_TRANSLATION = str.maketrans(
    {
        "\u2018": "'",
        "\u2019": "'",
        "\u201a": "'",
        "\u201b": "'",
        "\u2032": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u201e": '"',
        "\u201f": '"',
        "\u2033": '"',
        "\uff07": "'",
        "\uff02": '"',
    }
)


def _parse_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _normalize_sql_template(sql: str) -> str:
    norm, _ = canonicalize(sql or "")
    if not norm:
        return ""
    s = re.sub(r"'(?:''|[^'])*'", "?", norm)
    s = re.sub(r"\b0x[0-9a-f]+\b", "?", s, flags=re.IGNORECASE)
    s = re.sub(r"\b\d+(?:\.\d+)?\b", "?", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _fingerprint_sql_template(sql: str) -> str:
    template = _normalize_sql_template(sql or "")
    if not template:
        return ""
    return hashlib.sha256(template.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _role_meets_minimum(current_role: str, required_role: str) -> bool:
    req = str(required_role or "").strip().lower()
    cur = str(current_role or "").strip().lower()
    if req in {"", "*", "any"}:
        return True
    if req not in ROLE_ORDER:
        return False
    return ROLE_ORDER.get(cur, 0) >= ROLE_ORDER[req]


def _parse_expiry(raw: Any) -> Optional[datetime]:
    text = str(raw or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _compile_raw_sql_registry(raw_items: Any, *, section: str) -> List[Dict[str, Any]]:
    if not isinstance(raw_items, list):
        return []
    compiled: List[Dict[str, Any]] = []
    for idx, item in enumerate(raw_items, start=1):
        if not isinstance(item, dict):
            continue
        entry_id = str(item.get("id") or f"{section}-{idx}").strip()
        enabled = _parse_bool(item.get("enabled"), True)
        service_pattern = str(item.get("service") or ".*").strip() or ".*"
        try:
            service_re = re.compile(service_pattern)
        except re.error as exc:
            logger.error("Invalid sql_construction.%s service pattern '%s': %s", section, service_pattern, exc)
            continue
        fingerprint = str(item.get("fingerprint") or "").strip().lower()
        template = str(item.get("template") or "").strip()
        template_fp = _fingerprint_sql_template(template) if template else ""
        fingerprints = {fp for fp in [fingerprint, template_fp] if fp}
        compiled.append(
            {
                "id": entry_id,
                "enabled": enabled,
                "service_pattern": service_pattern,
                "service_re": service_re,
                "tenant_id": str(item.get("tenant_id") or "*").strip() or "*",
                "role": str(item.get("role") or "*").strip().lower() or "*",
                "reason": str(item.get("reason") or "").strip(),
                "expires_at_raw": str(item.get("expires_at") or "").strip() or None,
                "expires_at": _parse_expiry(item.get("expires_at")),
                "owner": str(item.get("owner") or "").strip() or None,
                "allow_unparameterized": _parse_bool(item.get("allow_unparameterized"), True),
                "fingerprints": fingerprints,
                "template": template or None,
            }
        )
    return compiled


def _compile_service_profiles(raw_items: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_items, list):
        return []
    compiled: List[Dict[str, Any]] = []
    for idx, item in enumerate(raw_items, start=1):
        if not isinstance(item, dict):
            continue
        profile_id = str(item.get("id") or f"profile-{idx}").strip()
        enabled = _parse_bool(item.get("enabled"), True)
        service_pattern = str(item.get("service") or ".*").strip() or ".*"
        try:
            service_re = re.compile(service_pattern)
        except re.error as exc:
            logger.error("Invalid sql_construction.service_profiles service pattern '%s': %s", service_pattern, exc)
            continue
        compiled.append(
            {
                "id": profile_id,
                "enabled": enabled,
                "service_pattern": service_pattern,
                "service_re": service_re,
                "description": str(item.get("description") or "").strip() or None,
                "require_parameterized_select": _parse_bool(item.get("require_parameterized_select"), True),
                "require_parameterized_write": _parse_bool(item.get("require_parameterized_write"), True),
                "require_approved_raw_sql": _parse_bool(item.get("require_approved_raw_sql"), SQL_REQUIRE_APPROVED_RAW_SQL),
                "unknown_raw_sql_action": str(item.get("unknown_raw_sql_action") or SQL_RAW_SQL_UNKNOWN_ACTION).strip().lower(),
            }
        )
    if not compiled:
        compiled.append(
            {
                "id": "default-strict",
                "enabled": True,
                "service_pattern": ".*",
                "service_re": re.compile(".*"),
                "description": "Fallback strict profile",
                "require_parameterized_select": True,
                "require_parameterized_write": True,
                "require_approved_raw_sql": SQL_REQUIRE_APPROVED_RAW_SQL,
                "unknown_raw_sql_action": SQL_RAW_SQL_UNKNOWN_ACTION,
            }
        )
    return compiled


try:
    rules_path = os.path.join(os.path.dirname(__file__), "prevention_rules.yml")
    if yaml and os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as fp:
            pr = yaml.safe_load(fp) or {}

        _crit = pr.get("critical_patterns") or []
        compiled_crit: List[re.Pattern] = []
        for patt in _crit:
            try:
                if isinstance(patt, str) and patt.lower().startswith("re:"):
                    s = patt[3:].strip()
                    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
                        s = s[1:-1]
                    compiled_crit.append(re.compile(s, re.IGNORECASE | re.DOTALL))
                elif isinstance(patt, str):
                    compiled_crit.append(re.compile(re.escape(patt), re.IGNORECASE | re.DOTALL))
            except re.error as rex:
                logger.error("Invalid critical pattern in YAML: %s (%s)", patt, rex)
        if compiled_crit:
            YAML_CRITICAL_PATTERNS = compiled_crit

        _ddl = pr.get("ddl_exec") or {}
        DDL_EXEC_POLICY = str(_ddl.get("policy") or DDL_EXEC_POLICY)
        DDL_EXEC_ALLOWED_SERVICES = str(_ddl.get("allowed_services") or DDL_EXEC_ALLOWED_SERVICES)
        DDL_EXEC_ALLOWLIST_PATTERNS = list(_ddl.get("allowlist_patterns") or DDL_EXEC_ALLOWLIST_PATTERNS)

        _al = pr.get("allowlist") or {}
        ALLOWLIST_MODE = str(_al.get("mode") or ALLOWLIST_MODE)
        if _al.get("last_reviewed_at"):
            ALLOWLIST_LAST_REVIEWED_AT = str(_al.get("last_reviewed_at"))
        if _al.get("max_age_days"):
            ALLOWLIST_MAX_AGE_DAYS = int(_al.get("max_age_days"))

        _mon = pr.get("monitor") or {}
        if _mon.get("backoff_n"):
            MONITOR_BACKOFF_N = int(_mon.get("backoff_n"))

        _par = pr.get("parameterization") or {}
        if "require" in _par:
            SQL_REQUIRE_PARAMETERIZATION = bool(_par.get("require"))

        _svc = pr.get("service_context") or {}
        if "require" in _svc:
            SQL_REQUIRE_SERVICE_CONTEXT = bool(_svc.get("require"))

        _tel = pr.get("telemetry") or {}
        if _tel.get("file"):
            SQL_TELEMETRY_FILE = str(_tel.get("file"))

        _sc = pr.get("sql_construction") or {}
        if isinstance(_sc, dict):
            SQL_SECURE_CONSTRUCTION_MODE = str(_sc.get("mode") or SQL_SECURE_CONSTRUCTION_MODE).strip().lower()
            if "require_parameterized_default" in _sc:
                SQL_REQUIRE_PARAMETERIZATION = _parse_bool(_sc.get("require_parameterized_default"), SQL_REQUIRE_PARAMETERIZATION)
            if "require_approved_raw_sql" in _sc:
                SQL_REQUIRE_APPROVED_RAW_SQL = _parse_bool(_sc.get("require_approved_raw_sql"), SQL_REQUIRE_APPROVED_RAW_SQL)
            if "unknown_raw_sql_action" in _sc:
                SQL_RAW_SQL_UNKNOWN_ACTION = str(_sc.get("unknown_raw_sql_action") or SQL_RAW_SQL_UNKNOWN_ACTION).strip().lower()
            if "migration_service_pattern" in _sc:
                SQL_RAW_SQL_MIGRATION_SERVICE_PATTERN = str(_sc.get("migration_service_pattern") or SQL_RAW_SQL_MIGRATION_SERVICE_PATTERN).strip()
            if "allow_constant_select" in _sc:
                SQL_RAW_SQL_ALLOW_CONSTANT_SELECT = _parse_bool(_sc.get("allow_constant_select"), SQL_RAW_SQL_ALLOW_CONSTANT_SELECT)
            RAW_SQL_APPROVALS = _compile_raw_sql_registry(_sc.get("approved_raw_sql"), section="approved_raw_sql")
            RAW_SQL_EXCEPTIONS = _compile_raw_sql_registry(_sc.get("raw_sql_exceptions"), section="raw_sql_exceptions")
            SERVICE_PROFILES = _compile_service_profiles(_sc.get("service_profiles"))
except Exception as e_yaml:
    logger.error("Failed to load prevention_rules.yml: %s", e_yaml)

if not SERVICE_PROFILES:
    SERVICE_PROFILES = _compile_service_profiles(
        [
            {
                "id": "default-strict",
                "enabled": True,
                "service": ".*",
                "description": "Fallback strict SQL secure-construction profile.",
                "require_parameterized_select": True,
                "require_parameterized_write": True,
                "require_approved_raw_sql": SQL_REQUIRE_APPROVED_RAW_SQL,
                "unknown_raw_sql_action": SQL_RAW_SQL_UNKNOWN_ACTION,
            }
        ]
    )


_raw_allowlist = [p.strip() for p in os.getenv("SQL_ALLOWLIST_PATTERNS", "").split(",") if p.strip()]
ALLOWLIST_PATTERNS: List[re.Pattern] = []
for patt in _raw_allowlist:
    try:
        if patt.lower().startswith("re:") or ALLOWLIST_MODE == "regex":
            compiled = re.compile(patt[3:] if patt.lower().startswith("re:") else patt, re.IGNORECASE | re.DOTALL)
        else:
            compiled = re.compile(re.escape(patt), re.IGNORECASE | re.DOTALL)
        ALLOWLIST_PATTERNS.append(compiled)
    except re.error:
        logger.error("Invalid allowlist pattern (global): %s", patt)
        continue


_svc_allow_str = os.getenv("SQL_ALLOWLIST_SERVICE_PATTERNS", "")
SERVICE_ALLOWLIST: Dict[str, List[re.Pattern]] = {}
for entry in _svc_allow_str.split(";"):
    if "=" in entry:
        key, pats = entry.split("=", 1)
        key = key.strip()
        if key:
            compiled_pats: List[re.Pattern] = []
            for p in [pp.strip() for pp in pats.split("|") if pp.strip()]:
                try:
                    if p.lower().startswith("re:") or ALLOWLIST_MODE == "regex":
                        compiled_pats.append(re.compile(p[3:] if p.lower().startswith("re:") else p, re.IGNORECASE | re.DOTALL))
                    else:
                        compiled_pats.append(re.compile(re.escape(p), re.IGNORECASE | re.DOTALL))
                except re.error:
                    logger.error("Invalid allowlist pattern (svc=%s): %s", key, p)
                    continue
            SERVICE_ALLOWLIST[key] = compiled_pats


try:
    from backend.security.request_context import (
        get_current_role,
        get_current_service,
        get_current_tenant_id,
    )
except Exception:

    def get_current_service() -> str:
        return "unknown"

    def get_current_tenant_id() -> str:
        return ""

    def get_current_role() -> str:
        return ""


MONITOR_BACKOFF_N = int(os.getenv("SQL_MONITOR_BACKOFF_N", "5"))
_monitor_counters: Dict[str, int] = {}


HIT_DESCRIPTIONS: Dict[str, str] = {
    "union_select": "Detected UNION SELECT clause which can merge attacker-controlled result sets.",
    "quoted_tautology": "Boolean tautology inside quotes (e.g., 'OR '1'='1') was detected.",
    "tautology_or_1eq1": "Boolean tautology OR 1=1 detected in predicate.",
    "stacked_query_dml": "Multiple SQL statements (stacked query) detected in a single execution.",
    "multi_statement": "More than one SQL statement detected.",
    "time_sleep": "Found SLEEP() time delay function, common in blind SQLi.",
    "time_pg_sleep": "Found pg_sleep() time delay function, common in blind SQLi.",
    "time_benchmark": "Found BENCHMARK() time delay function, common in blind SQLi.",
    "time_waitfor_delay": "Found WAITFOR DELAY time delay function, common in blind SQLi.",
    "xp_cmdshell": "xp_cmdshell invocation would execute operating-system commands.",
    "xp_dirtree": "xp_dirtree invocation enumerates filesystem paths.",
    "xp_regread": "xp_regread invocation reads Windows registry.",
    "openrowset": "OPENROWSET call can access external data sources.",
    "copy_to_program": "COPY ... PROGRAM can spawn processes on PostgreSQL.",
    "sp_oacreate": "sp_OACreate allows COM automation; high risk of command execution.",
    "blind_subquery_exfiltration": "Detected blind exfiltration probe using nested SELECT with substring/ascii extraction.",
    "metadata_function_probe": "Database metadata function probe detected (e.g., version/user/database).",
    "ddl_statement": "DDL command (CREATE/ALTER/DROP/TRUNCATE/RENAME) detected.",
    "exec_statement": "EXEC/CALL statement detected.",
    "non_parameterized_sql": "Query uses literals without parameter binding; enforce prepared statements.",
    "non_parameterized_sql_advisory": "Query uses literals without parameter binding in a balanced profile; review for parameterization migration.",
    "heuristics_unavailable": "Heuristic engine unavailable or timed out; fallback heuristics were used.",
    "unknown_service": "Service context missing; cannot apply scoped policy.",
    "yaml_critical_pattern": "Matched critical pattern from prevention_rules.yml.",
    "raw_sql_text_clause": "Execution path used raw SQL text; strict construction policy applied.",
    "approved_raw_sql_template": "Raw SQL matched an approved template/fingerprint policy entry.",
    "raw_sql_exception": "Raw SQL matched a governed exception entry.",
    "unapproved_raw_sql": "Raw SQL not in approved template/fingerprint registry for this service context.",
    "raw_sql_constant_select": "Raw SQL is a constant SELECT probe and allowed by policy.",
    "raw_sql_migration_context": "Raw SQL executed in migration/admin context allowed by governance.",
    "raw_sql_parameterized": "Raw SQL used parameter binding and passed secure construction checks.",
    "schema_column_enumeration": "INFORMATION_SCHEMA column-name enumeration detected.",
    "schema_not_in_probe": "Metadata enumeration excludes system schemas, a common reconnaissance pattern.",
    "privileged_grant": "GRANT statement detected in a request-path context.",
    "quote_comment_truncation": "Quote followed by SQL comment syntax can truncate intended predicates.",
    "metadata_length_probe": "Length comparison over database metadata detected.",
    "metadata_substring_probe": "Substring comparison over database metadata detected.",
    "metadata_self_compare": "Self-comparison over database metadata functions detected.",
    "conditional_error_probe": "Conditional branch appears to trigger a database error for inference.",
    "double_quoted_tautology": "Double-quoted boolean tautology detected.",
    "mssql_sys_tables_probe": "Conditional SQL Server catalog probe detected.",
    "mysql_comment_escape_probe": "MySQL comment or parser-escape probe detected.",
    "oracle_utl": "Oracle UTL out-of-band or file primitive detected.",
    "oracle_dbms_pipe": "Oracle DBMS_PIPE timing primitive detected.",
    "request_query_sqli_trace": "HTTP request or URL contains SQL injection syntax.",
    "sql_error_trace": "SQL error text detected in request-path input.",
}


def _compose_explanation(action: str, risk: str, hits: List[str], score: float) -> str:
    parts: List[str] = []
    for h in sorted(set(hits)):
        desc = HIT_DESCRIPTIONS.get(h)
        if desc:
            parts.append(desc)
    if not parts:
        if risk.lower() == "low":
            parts.append(f"No suspicious patterns detected (heuristic score {score:.2f}).")
        else:
            parts.append(f"Risk assessed as {risk} (heuristic score {score:.2f}).")
    policy_note = {
        "BLOCK_IMMEDIATE": "Policy: query blocked immediately.",
        "FLAG_FOR_REVIEW_BLOCK": "Policy: query requires manual review before execution.",
        "ALLOW": "Policy: query allowed to execute under current mode.",
    }.get(action, f"Policy decision: {action}.")
    parts.append(policy_note)
    return " ".join(parts)


def _run_heuristics(sql: str) -> Tuple[bool, Dict[str, Any]]:
    try:
        from backend.services.query_analysis_service import QueryAnalysisService
        import time

        t0 = time.perf_counter()
        svc = QueryAnalysisService.get_instance()
        hr = svc._heuristics_scan(sql)  # type: ignore[attr-defined]
        dt_ms = (time.perf_counter() - t0) * 1000.0
        if dt_ms > SQL_HEURISTICS_TIMEOUT_MS:
            logger.error("Heuristics runtime exceeded budget: %.1fms > %sms", dt_ms, SQL_HEURISTICS_TIMEOUT_MS)
            return False, {
                "suspected": bool(getattr(hr, "suspected", False)),
                "hits": list(getattr(hr, "hits", []) or []),
                "score": float(getattr(hr, "heuristic_score", 0.0) or 0.0),
            }
        return True, {
            "suspected": bool(getattr(hr, "suspected", False)),
            "hits": list(getattr(hr, "hits", []) or []),
            "score": float(getattr(hr, "heuristic_score", 0.0) or 0.0),
        }
    except Exception as e:
        global _SERVICE_HEURISTICS_UNAVAILABLE_LOGGED
        msg = str(e)
        if isinstance(e, RuntimeError) and "has not been initialized" in msg:
            if not _SERVICE_HEURISTICS_UNAVAILABLE_LOGGED:
                logger.info("SQL enforcement: QueryAnalysisService not initialized; using fallback heuristics.")
                _SERVICE_HEURISTICS_UNAVAILABLE_LOGGED = True
        else:
            logger.error("SQL enforcement: heuristics unavailable: %s", e)
        hits: List[str] = []
        score = 0.0
        patterns = [
            (r"(?i)'\s*or\s*'1'\s*=\s*'1", "quoted_tautology", 0.9),
            (r"(?i)\bor\b\s*1\s*=\s*1", "tautology_or_1eq1", 0.9),
            (r"(?i)union\s+(?:all\s+)?(?:select|\(\s*select)\b", "union_select", 0.85),
            (r"(?i);\s*(drop|delete|insert|update|alter|exec|execute)\b", "stacked_query_dml", 0.95),
            (r"(?i)sleep\s*\(\s*(?:\d+|__time__|[a-z_][\w]*)\s*\)", "time_sleep", 0.85),
            (r"(?i)pg_sleep\s*\(", "time_pg_sleep", 0.85),
            (r"(?i)benchmark\s*\(\s*\d+\s*,", "time_benchmark", 0.85),
            (r"(?i)\bxp_cmdshell\b", "xp_cmdshell", 1.0),
            (r"(?i)waitfor\s+delay\s+'\d+:\d+:(?:\d+|__time__)'", "time_waitfor_delay", 0.85),
            (r"(?is)\bcopy\b[\s\S]{0,400}\bto\s+program\b", "copy_to_program", 0.95),
            (r"(?i)\butl_(?:http|inaddr|file)\b|\bget_host_address\s*\(", "oracle_utl", 0.9),
            (r"(?i)dbms_pipe\.receive_message\s*\(", "oracle_dbms_pipe", 0.85),
            (r"(?is)\b(?:and|or)\b\s*\(?\s*1\s*\)?\s*=\s*\(?\s*[12]\s*\)?[\s\S]{0,80}(?:--|#|/\*)", "boolean_probe_with_comment", 0.82),
            (r"(?i)\bor\b\s*\(?\s*[\"'][^\"']+[\"']?\s*=\s*[\"'][^\"']+[\"']?", "double_quoted_tautology", 0.9),
            (r"(?is)(?:^|[\s:=,(\\])(?:[a-z0-9_]+)?\\?[\"']\s*(?:--|#|/\*)", "quote_comment_truncation", 0.82),
            (
                r"(?is)\b(?:length|len)\s*\([^)]*(?:@@hostname|@@version|version\s*\(|database\s*\(|current_database\s*\(|user\s*\()[^)]*\)\s*(?:=|>|<|between|like)",
                "metadata_length_probe",
                0.82,
            ),
            (
                r"(?is)\b(?:substring|substr|mid)\s*\([^)]*(?:@@hostname|@@version|version\s*\(|database\s*\(|current_database\s*\(|user\s*\()[\s\S]{0,120}(?:=|>|<|like|between|not\s+in)",
                "metadata_substring_probe",
                0.88,
            ),
            (
                r"(?is)\bcase\s+when\b[\s\S]{0,200}\belse\b[\s\S]{0,80}(?:json\s*\(\s*''\s*\)|1\s*/\s*0|convert\s*\()",
                "conditional_error_probe",
                0.82,
            ),
            (r"(?is)\bcase\s+when\b[\s\S]{0,160}\bsys\.(?:tables|objects|databases)\b", "mssql_sys_tables_probe", 0.82),
            (
                r"(?is)(?:information_schema\.columns[\s\S]{0,220}\bcolumn_name\b|\bcolumn_name\b[\s\S]{0,220}information_schema\.columns)",
                "schema_column_enumeration",
                0.82,
            ),
            (r"(?is)information_schema\.tables[\s\S]{0,220}\bnot\s+in\b", "schema_not_in_probe", 0.8),
            (r"(?i)\bgrant\s+(?:all|connect|resource|dba|select|insert|update|delete)\b", "privileged_grant", 0.85),
            (
                r"(?is)\b(substring|substr|mid|ascii|ord)\s*\(\s*\(\s*select\b.*?\)\s*,\s*\d+\s*(?:,\s*\d+\s*)?\)\s*(=|>|<|like)\s*(?:'[^']*'|\"[^\"]*\"|\d+)",
                "blind_subquery_exfiltration",
                1.0,
            ),
            (
                r"(?i)\b(?:@@version|version\s*\(\s*\)|current_database\s*\(\s*\)|database\s*\(\s*\)|current_user\b|session_user\b|system_user\b|user\s*\(\s*\))\b",
                "metadata_function_probe",
                0.65,
            ),
        ]
        for surface in _fallback_detection_surfaces(sql):
            for pat, code, weight in patterns:
                try:
                    if re.search(pat, surface, flags=re.DOTALL):
                        if code not in hits:
                            hits.append(code)
                            score += weight
                except re.error:
                    continue
        return False, {"suspected": bool(hits), "hits": hits, "score": min(1.0, score)}


def _hash_sig(s: str) -> str:
    try:
        return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:12]
    except Exception:
        return str(abs(hash(s)))


def _normalize_fallback_surface(text: str) -> str:
    try:
        out = unicodedata.normalize("NFKC", str(text or ""))
    except Exception:
        out = str(text or "")
    out = out.translate(_SMART_SQL_TRANSLATION)
    out = re.sub(r"(?is)/\*!\d{3,5}\s*(.*?)\*/", r" \1 ", out)
    return re.sub(r"\s+", " ", out).strip()


def _fallback_detection_surfaces(sql: str) -> List[str]:
    raw = str(sql or "")
    surfaces: List[str] = []

    def add(value: str) -> None:
        normalized = _normalize_fallback_surface(value)
        if normalized and normalized not in surfaces:
            surfaces.append(normalized[:8000])

    add(raw)
    current = raw
    for _ in range(2):
        try:
            decoded = unquote_plus(current)
        except Exception:
            decoded = current
        if decoded == current:
            break
        add(decoded)
        current = decoded
    if "+" in raw:
        add(raw.replace("+", " "))
    try:
        ascii_fold = re.sub(r"[^\x00-\x7F]+", " ", raw)
        if ascii_fold != raw:
            add(ascii_fold)
    except Exception:
        pass
    return surfaces


def _extract_execution_metadata(
    *,
    statement: str,
    parameters: Any,
    execution_context: Any = None,
    executemany: bool = False,
) -> Dict[str, Any]:
    placeholder_pattern = r"(\?|%s|:\w+|\$\d+|@\w+)"
    has_placeholder = bool(re.search(placeholder_pattern, statement or ""))

    has_bound_parameters = False
    parameter_count = 0
    try:
        if isinstance(parameters, dict):
            parameter_count = len(parameters)
            has_bound_parameters = parameter_count > 0
        elif isinstance(parameters, (list, tuple)):
            parameter_count = len(parameters)
            if executemany and parameter_count > 0 and isinstance(parameters[0], (dict, list, tuple)):
                has_bound_parameters = True
            else:
                has_bound_parameters = parameter_count > 0
        elif parameters is not None:
            has_bound_parameters = True
            parameter_count = 1
    except Exception:
        has_bound_parameters = bool(parameters)

    compiled = getattr(execution_context, "compiled", None) if execution_context is not None else None
    statement_kind = "unknown"
    is_text_clause = False
    try:
        stmt_obj = getattr(compiled, "statement", None) if compiled is not None else None
        if stmt_obj is not None:
            statement_kind = stmt_obj.__class__.__name__
            from sqlalchemy.sql.elements import TextClause

            is_text_clause = isinstance(stmt_obj, TextClause)
    except Exception:
        is_text_clause = False

    return {
        "has_placeholder": has_placeholder,
        "has_bound_parameters": has_bound_parameters,
        "parameter_count": parameter_count,
        "is_text_clause": is_text_clause,
        "statement_kind": statement_kind,
        "executemany": bool(executemany),
    }


def _match_registry_entry(
    entries: List[Dict[str, Any]],
    *,
    service: str,
    tenant_id: str,
    actor_role: str,
    template_fingerprint: str,
) -> Optional[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    for entry in entries:
        if not bool(entry.get("enabled", True)):
            continue
        service_re = entry.get("service_re")
        try:
            if service_re is None or not service_re.search(service or "unknown"):
                continue
        except Exception:
            continue

        entry_tenant = str(entry.get("tenant_id") or "*").strip()
        if entry_tenant not in {"", "*", "any"} and entry_tenant != (tenant_id or ""):
            continue

        required_role = str(entry.get("role") or "*").strip().lower()
        if not _role_meets_minimum(actor_role, required_role):
            continue

        expires_at = entry.get("expires_at")
        if isinstance(expires_at, datetime) and expires_at < now:
            continue

        fingerprints = entry.get("fingerprints") or set()
        if fingerprints and template_fingerprint not in fingerprints:
            continue
        return entry
    return None


def _is_constant_select_query(norm_sql: str) -> bool:
    if not norm_sql:
        return False
    pattern = (
        r"^select\s+"
        r"(?:\?|\d+|true|false|null|'[^']*')"
        r"(?:\s+as\s+[a-z_][a-z0-9_]*)?"
        r"(?:\s*,\s*(?:\?|\d+|true|false|null|'[^']*')(?:\s+as\s+[a-z_][a-z0-9_]*)?)*$"
    )
    return bool(re.match(pattern, norm_sql, flags=re.IGNORECASE))


def _resolve_service_profile(service: str) -> Dict[str, Any]:
    svc = str(service or "").strip() or "unknown"
    for profile in SERVICE_PROFILES:
        if not bool(profile.get("enabled", True)):
            continue
        service_re = profile.get("service_re")
        try:
            if service_re is not None and service_re.search(svc):
                return profile
        except Exception:
            continue
    return {
        "id": "runtime-fallback-strict",
        "require_parameterized_select": True,
        "require_parameterized_write": True,
        "require_approved_raw_sql": SQL_REQUIRE_APPROVED_RAW_SQL,
        "unknown_raw_sql_action": SQL_RAW_SQL_UNKNOWN_ACTION,
    }


def _classify_sql_operation(norm_sql: str) -> Dict[str, bool]:
    text = str(norm_sql or "").strip().lower()
    is_select = bool(re.match(r"^(?:with\b[\s\S]+?\bselect\b|select\b)", text, flags=re.IGNORECASE))
    is_write = bool(re.search(r"\b(insert|update|delete|merge|replace|upsert)\b", text, flags=re.IGNORECASE))
    is_exec_like = bool(re.search(r"\b(exec|execute|call)\b", text, flags=re.IGNORECASE))
    is_ddl = bool(re.search(r"\b(drop|alter|create|truncate|rename)\b", text, flags=re.IGNORECASE))
    is_read_only_select = is_select and not is_write and not is_exec_like and not is_ddl
    return {
        "is_select": is_select,
        "is_write": is_write,
        "is_exec_like": is_exec_like,
        "is_ddl": is_ddl,
        "is_read_only_select": is_read_only_select,
    }


def _contains_unbound_literal_predicates(norm_sql: str) -> bool:
    """Detect common literal-driven predicate/value patterns that should be parameterized."""
    if not norm_sql:
        return False
    literal = r"(?:'[^']*'|\b\d+(?:\.\d+)?\b|0x[0-9a-f]+|true|false|null)"
    patterns = [
        rf"(?is)\bwhere\b[\s\S]*?(?:=|!=|<>|<=|>=|<|>|like)\s*{literal}",
        rf"(?is)\bwhere\b[\s\S]*?\bin\s*\(\s*{literal}",
        rf"(?is)\bset\b[\s\S]*?=\s*{literal}",
        rf"(?is)\bvalues\s*\([\s\S]*?{literal}",
    ]
    return any(bool(re.search(p, norm_sql, flags=re.IGNORECASE)) for p in patterns)


def _resolve_unknown_raw_sql_action(mode: str, action_override: Optional[str] = None) -> Tuple[str, str]:
    action = str(action_override or SQL_RAW_SQL_UNKNOWN_ACTION).strip().lower()
    if mode == "monitor":
        return "Medium", "FLAG_FOR_REVIEW_BLOCK"
    if action in {"allow", "monitor"}:
        return "Medium", "FLAG_FOR_REVIEW_BLOCK"
    if action in {"block_immediate", "block_critical"}:
        return "Critical", "BLOCK_IMMEDIATE"
    return "High", "FLAG_FOR_REVIEW_BLOCK"


def _requires_service_context_enforcement(norm_sql: str) -> bool:
    text = (norm_sql or "").strip().lower()
    if not text:
        return False
    if text.startswith("pragma "):
        return False
    if re.match(r"^select\s+name\s+from\s+sqlite_master\b", text):
        return False
    if text.startswith("show ") or text.startswith("set "):
        return False
    if text in {"begin", "commit", "rollback"}:
        return False
    return bool(re.search(r"\b(select|insert|update|delete|exec|execute|call|drop|alter|create|truncate|rename)\b", text))


def decide(
    statement: str,
    parameters: Any,
    execution_context: Any = None,
    *,
    executemany: bool = False,
) -> Dict[str, Any]:
    norm, meta = canonicalize(statement or "")

    svc = get_current_service() or "unknown"
    tenant_id = get_current_tenant_id() or ""
    actor_role = get_current_role() or ""
    service_profile = _resolve_service_profile(svc)
    require_approved_raw_sql = bool(service_profile.get("require_approved_raw_sql", SQL_REQUIRE_APPROVED_RAW_SQL))
    enforce_parameterized_select = bool(service_profile.get("require_parameterized_select", SQL_REQUIRE_PARAMETERIZATION))
    enforce_parameterized_write = bool(service_profile.get("require_parameterized_write", SQL_REQUIRE_PARAMETERIZATION))
    service_unknown_raw_action = str(service_profile.get("unknown_raw_sql_action") or SQL_RAW_SQL_UNKNOWN_ACTION).strip().lower()

    for patt in ALLOWLIST_PATTERNS:
        try:
            if patt.search(norm):
                if ALLOWLIST_LAST_REVIEWED_AT:
                    try:
                        dt = datetime.strptime(ALLOWLIST_LAST_REVIEWED_AT, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - dt).days
                        if age_days > ALLOWLIST_MAX_AGE_DAYS:
                            logger.warning("Allowlist hit on stale pattern (> %sd): %s", ALLOWLIST_MAX_AGE_DAYS, patt.pattern)
                    except Exception:
                        pass
                explanation = f"Allowed by global allowlist pattern '{patt.pattern}'."
                if ALLOWLIST_LAST_REVIEWED_AT:
                    explanation += f" Last reviewed: {ALLOWLIST_LAST_REVIEWED_AT}."
                return {
                    "decision": "ALLOW",
                    "risk": "Low",
                    "suspected": False,
                    "hits": [],
                    "score": 0.0,
                    "normalized": norm,
                    "meta": meta,
                    "service": svc,
                    "tenant_id": tenant_id or None,
                    "actor_role": actor_role or None,
                    "sig": _hash_sig(norm),
                    "template_fingerprint": _fingerprint_sql_template(norm),
                    "reason": "allowlist_global",
                    "explanation": explanation,
                    "allowlist_pattern": patt.pattern,
                }
        except re.error:
            continue

    for key, pats in SERVICE_ALLOWLIST.items():
        try:
            if key and svc and re.search(key, svc):
                for patt in pats:
                    try:
                        if patt.search(norm):
                            explanation = f"Allowed by service allowlist '{key}' pattern '{patt.pattern}'."
                            return {
                                "decision": "ALLOW",
                                "risk": "Low",
                                "suspected": False,
                                "hits": [],
                                "score": 0.0,
                                "normalized": norm,
                                "meta": meta,
                                "service": svc,
                                "tenant_id": tenant_id or None,
                                "actor_role": actor_role or None,
                                "sig": _hash_sig(norm),
                                "template_fingerprint": _fingerprint_sql_template(norm),
                                "reason": f"svc_allow:{key}",
                                "explanation": explanation,
                                "allowlist_pattern": patt.pattern,
                            }
                    except re.error:
                        continue
        except re.error:
            continue

    ok, heur = _run_heuristics(statement or norm)
    hits = set(heur.get("hits") or [])
    score = float(heur.get("score") or 0.0)
    suspected = bool(heur.get("suspected", False))

    try:
        import sqlparse

        parsed = sqlparse.parse(norm)
        if len(parsed) > 1:
            hits.add("multi_statement")
        ddl_kw = {"DROP", "ALTER", "CREATE", "TRUNCATE", "RENAME"}
        exec_kw = {"EXEC", "EXECUTE", "CALL"}
        for stmt in parsed:
            for t in stmt.flatten():
                if t.ttype in sqlparse.tokens.Keyword:
                    val = t.value.upper()
                    if val in ddl_kw:
                        hits.add("ddl_statement")
                    if val in exec_kw:
                        hits.add("exec_statement")
    except Exception:
        if ";" in norm:
            hits.add("multi_statement")
        if re.search(r"\b(drop|alter|create|truncate|rename)\b", norm):
            hits.add("ddl_statement")
        if re.search(r"\b(exec|execute|call)\b", norm):
            hits.add("exec_statement")

    for patt in YAML_CRITICAL_PATTERNS or []:
        try:
            if any(patt.search(surface) for surface in _fallback_detection_surfaces(statement or norm)):
                hits.add("yaml_critical_pattern")
        except re.error:
            continue

    execution_meta = _extract_execution_metadata(
        statement=statement or "",
        parameters=parameters,
        execution_context=execution_context,
        executemany=executemany,
    )
    template_fingerprint = _fingerprint_sql_template(norm)

    level = "Low"
    action = "ALLOW"
    matched_registry: Optional[Dict[str, Any]] = None
    registry_reason: Optional[str] = None

    migration_context = False
    if bool(execution_meta.get("is_text_clause")):
        hits.add("raw_sql_text_clause")
        try:
            migration_context = bool(
                SQL_RAW_SQL_MIGRATION_SERVICE_PATTERN and re.search(SQL_RAW_SQL_MIGRATION_SERVICE_PATTERN, svc or "unknown")
            )
        except re.error:
            migration_context = False

        if migration_context:
            hits.add("raw_sql_migration_context")
        else:
            matched_registry = _match_registry_entry(
                RAW_SQL_APPROVALS,
                service=svc,
                tenant_id=tenant_id,
                actor_role=actor_role,
                template_fingerprint=template_fingerprint,
            )
            if matched_registry is not None:
                hits.add("approved_raw_sql_template")
                registry_reason = "approved_raw_sql_template"
            else:
                matched_registry = _match_registry_entry(
                    RAW_SQL_EXCEPTIONS,
                    service=svc,
                    tenant_id=tenant_id,
                    actor_role=actor_role,
                    template_fingerprint=template_fingerprint,
                )
                if matched_registry is not None:
                    hits.add("raw_sql_exception")
                    registry_reason = "raw_sql_exception"

            if matched_registry is None:
                has_parameterized_raw = bool(execution_meta.get("has_placeholder")) or bool(
                    execution_meta.get("has_bound_parameters")
                )
                if has_parameterized_raw:
                    hits.add("raw_sql_parameterized")
                elif SQL_RAW_SQL_ALLOW_CONSTANT_SELECT and _is_constant_select_query(_normalize_sql_template(norm)):
                    hits.add("raw_sql_constant_select")
                elif SQL_SECURE_CONSTRUCTION_MODE != "off" and require_approved_raw_sql:
                    hits.add("unapproved_raw_sql")
                    if SQL_SECURE_CONSTRUCTION_MODE == "strict":
                        level, action = _resolve_unknown_raw_sql_action(
                            SQL_SECURE_CONSTRUCTION_MODE,
                            action_override=service_unknown_raw_action,
                        )
                    elif SQL_SECURE_CONSTRUCTION_MODE == "monitor" and level == "Low":
                        level, action = "Medium", "FLAG_FOR_REVIEW_BLOCK"

    if SQL_REQUIRE_PARAMETERIZATION:
        operation = _classify_sql_operation(norm)
        dml_or_select = bool(operation.get("is_select") or operation.get("is_write"))
        has_placeholders = bool(execution_meta.get("has_placeholder"))
        has_bound_parameters = bool(execution_meta.get("has_bound_parameters"))
        if dml_or_select:
            can_skip = False
            if migration_context:
                can_skip = True
            if matched_registry is not None:
                can_skip = bool(matched_registry.get("allow_unparameterized", True))
            if SQL_RAW_SQL_ALLOW_CONSTANT_SELECT and _is_constant_select_query(_normalize_sql_template(norm)):
                can_skip = True

            has_unbound_literals = _contains_unbound_literal_predicates(norm)
            if not can_skip and has_unbound_literals and not has_placeholders and not has_bound_parameters:
                should_enforce = False
                if bool(operation.get("is_write") or operation.get("is_exec_like")):
                    should_enforce = enforce_parameterized_write
                elif bool(operation.get("is_read_only_select")):
                    should_enforce = enforce_parameterized_select
                else:
                    should_enforce = enforce_parameterized_select or enforce_parameterized_write

                if should_enforce:
                    hits.add("non_parameterized_sql")
                    if level != "Critical":
                        level, action = "High", "FLAG_FOR_REVIEW_BLOCK"
                else:
                    hits.add("non_parameterized_sql_advisory")

    if hits & CRITICAL_CODES:
        level, action = "Critical", "BLOCK_IMMEDIATE"
    elif suspected and score >= HEURISTICS_HIGH_THRESHOLD and level == "Low":
        level, action = "High", "FLAG_FOR_REVIEW_BLOCK"

    if not ok:
        hits.add("heuristics_unavailable")
        if ENFORCEMENT_MODE in ("block_high", "block_critical") and suspected and level == "Low":
            level, action = "High", "FLAG_FOR_REVIEW_BLOCK"

    if SQL_REQUIRE_SERVICE_CONTEXT and (not svc or svc.lower() == "unknown") and _requires_service_context_enforcement(norm):
        hits.add("unknown_service")
        if level != "Critical":
            level, action = "High", "FLAG_FOR_REVIEW_BLOCK"

    if "ddl_statement" in hits or "exec_statement" in hits:
        allowed = False
        try:
            if DDL_EXEC_POLICY == "allow":
                allowed = True
            elif DDL_EXEC_POLICY in ("deny", "deny_non_migration"):
                if DDL_EXEC_ALLOWED_SERVICES and re.search(DDL_EXEC_ALLOWED_SERVICES, svc):
                    allowed = True
                else:
                    for patt in DDL_EXEC_ALLOWLIST_PATTERNS:
                        try:
                            if re.search(patt, norm):
                                allowed = True
                                break
                        except re.error:
                            continue
            elif DDL_EXEC_POLICY == "monitor":
                allowed = True
        except re.error:
            allowed = False
        if not allowed:
            level, action = "Critical", "BLOCK_IMMEDIATE"

    res: Dict[str, Any] = {
        "decision": action,
        "risk": level,
        "suspected": suspected,
        "hits": sorted(list(hits)),
        "score": score,
        "normalized": norm,
        "meta": meta,
        "service": svc,
        "tenant_id": tenant_id or None,
        "actor_role": actor_role or None,
        "service_profile_id": service_profile.get("id"),
        "sig": _hash_sig(norm),
        "template_fingerprint": template_fingerprint,
        "execution_meta": execution_meta,
    }
    if matched_registry is not None:
        res["raw_sql_registry_entry"] = {
            "id": matched_registry.get("id"),
            "reason": matched_registry.get("reason"),
            "owner": matched_registry.get("owner"),
            "expires_at": matched_registry.get("expires_at_raw"),
        }
        if registry_reason:
            res["reason"] = registry_reason
    if "reason" not in res:
        res["reason"] = " | ".join(sorted(res["hits"])) if res["hits"] else "clean"

    res["explanation"] = _compose_explanation(action, level, res["hits"], score)
    if matched_registry is not None and matched_registry.get("reason"):
        res["explanation"] += f" Governance reason: {matched_registry.get('reason')}."

    try:
        if SQL_TELEMETRY_FILE:
            safe_norm = str(res["normalized"][:300]).replace('"', "'")
            with open(SQL_TELEMETRY_FILE, "a", encoding="utf-8", errors="ignore") as f:
                f.write(
                    f"{res['service']},{res['risk']},{res['decision']},{res['sig']},{template_fingerprint},\"{safe_norm}\"\n"
                )
    except Exception:
        pass
    return res


def enforce(
    statement: str,
    parameters: Any,
    *,
    execution_context: Any = None,
    executemany: bool = False,
) -> None:
    """Raise PermissionError to block execution when policy requires it."""
    if ENFORCEMENT_MODE == "off":
        return

    res = decide(
        statement,
        parameters,
        execution_context=execution_context,
        executemany=executemany,
    )
    decision = str(res.get("decision") or "ALLOW")
    risk = str(res.get("risk") or "Low")

    if ENFORCEMENT_MODE == "monitor":
        logger.warning(
            "SQL monitor: %s decision=%s svc=%s hits=%s sql='%s'",
            risk,
            decision,
            res.get("service"),
            res.get("hits"),
            str(res.get("normalized") or "")[:200],
        )
        key = f"{res.get('service')}::{res.get('sig')}"
        _monitor_counters[key] = _monitor_counters.get(key, 0) + 1
        if _monitor_counters[key] >= MONITOR_BACKOFF_N and decision in ("BLOCK_IMMEDIATE", "FLAG_FOR_REVIEW_BLOCK"):
            logger.error("SQL monitor backoff reached; blocking now key=%s", key)
            raise PermissionError("SQL enforcement (monitor backoff) blocked query")
        return

    if ENFORCEMENT_MODE == "block_high":
        if decision in ("BLOCK_IMMEDIATE", "FLAG_FOR_REVIEW_BLOCK"):
            logger.error("SQL blocked (High): hits=%s sql='%s'", res.get("hits"), str(res.get("normalized") or "")[:200])
            raise PermissionError("SQL enforcement blocked High/Critical query")
        return

    if decision == "BLOCK_IMMEDIATE":
        logger.error("SQL blocked (Critical): hits=%s sql='%s'", res.get("hits"), str(res.get("normalized") or "")[:200])
        raise PermissionError("SQL enforcement blocked Critical query")
