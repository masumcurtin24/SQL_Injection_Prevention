# backend/services/query_analysis_service.py (Complete Code)
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
import os
import re
import joblib
import uuid
import logging
import sys
from sqlalchemy.orm import Session
from pathlib import Path
import pandas as pd
import json
import asyncio
import unicodedata
from urllib.parse import unquote_plus

# --- Project Module Imports ---
try:
    from backend.core.ai_models.anomaly_detection.model import AnomalyDetectionModel
    from backend.utils.logging_utils import setup_logger
    from backend.server.schemas.responses import (
        AnomalyDetectionResult, QueryValidationResult, CombinedRiskAssessment,
        AnalysisResponse, Alert as AlertSchema, SQLHeuristicsResult,
        XAIExplanation, XAIExplanationEvidence, XAIExplanationTraceStep,
    )
    from backend.services.ai_reliability_service import assess_ai_reliability
    from backend.services.explainability_contract import complete_explainability_contract
    from backend.services.alerts_service import AlertsService
    from backend.services.incident_response_service import IncidentResponseService
    from backend.core.models import DEFAULT_TENANT_ID, SQLAnalysisLog as SQLAnalysisLogModel
    from backend.server.websockets import manager
except ImportError:
    print("INFO: QueryAnalysisService using fallback imports.")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir_path = os.path.join(current_dir, '..')
    if backend_dir_path not in sys.path:
        sys.path.insert(0, backend_dir_path)
    from core.ai_models.anomaly_detection.model import AnomalyDetectionModel
    from utils.logging_utils import setup_logger
    from server.schemas.responses import *
    from services.ai_reliability_service import assess_ai_reliability
    from services.explainability_contract import complete_explainability_contract
    from services.alerts_service import AlertsService
    from services.incident_response_service import IncidentResponseService
    from core.models import DEFAULT_TENANT_ID, SQLAnalysisLog as SQLAnalysisLogModel
    from server.websockets import manager

logger = setup_logger(__name__)

# --- Heuristics configuration via environment variables ---
try:
    HEURISTICS_HIGH_THRESHOLD = float(os.getenv("HEURISTICS_HIGH_THRESHOLD", "0.75"))
except Exception:
    HEURISTICS_HIGH_THRESHOLD = 0.75

try:
    SQL_PRECISION_MEDIUM_THRESHOLD = float(os.getenv("SQL_PRECISION_MEDIUM_THRESHOLD", "0.50"))
except Exception:
    SQL_PRECISION_MEDIUM_THRESHOLD = 0.50

try:
    SQL_PRECISION_HIGH_THRESHOLD = float(os.getenv("SQL_PRECISION_HIGH_THRESHOLD", "0.75"))
except Exception:
    SQL_PRECISION_HIGH_THRESHOLD = 0.75

try:
    SQL_PRECISION_BLOCK_THRESHOLD = float(os.getenv("SQL_PRECISION_BLOCK_THRESHOLD", "0.90"))
except Exception:
    SQL_PRECISION_BLOCK_THRESHOLD = 0.90

try:
    SQL_NLP_MALICIOUS_REVIEW_THRESHOLD = float(os.getenv("SQL_NLP_MALICIOUS_REVIEW_THRESHOLD", "0.50"))
except Exception:
    SQL_NLP_MALICIOUS_REVIEW_THRESHOLD = 0.50

try:
    SQL_NLP_MALICIOUS_HIGH_THRESHOLD = float(os.getenv("SQL_NLP_MALICIOUS_HIGH_THRESHOLD", "0.85"))
except Exception:
    SQL_NLP_MALICIOUS_HIGH_THRESHOLD = 0.85

_DEFAULT_CRITICAL_CODES = {
    "stacked_query_dml", "xp_cmdshell", "union_select",
    "time_sleep", "time_pg_sleep", "time_benchmark", "time_waitfor_delay",
    # Additional severe indicators
    "xp_dirtree", "xp_regread", "openrowset", "copy_to_program", "sp_oacreate",
    "blind_subquery_exfiltration", "oracle_utl", "oracle_dbms_pipe",
}
_env_codes = os.getenv("HEURISTICS_CRITICAL_CODES", "").strip()
CRITICAL_CODES: set = set([c.strip() for c in _env_codes.split(",") if c.strip()]) or _DEFAULT_CRITICAL_CODES

_DEFAULT_HIGH_RISK_FLOOR_HITS = {
    "tautology_or_1eq1",
    "quoted_tautology",
    "quoted_tautology_any",
    "or_exists_subquery",
    "error_extractvalue_probe",
    "error_updatexml_probe",
    "ascii_substring_probe",
    "char_obfuscation_predicate",
    "boolean_probe_with_comment",
    "conditional_error_probe",
    "double_quoted_tautology",
    "file_ops",
    "copy_to_program",
    "metadata_length_probe",
    "metadata_self_compare",
    "metadata_substring_probe",
    "mssql_sys_tables_probe",
    "mysql_comment_escape_probe",
    "oracle_utl",
    "oracle_dbms_pipe",
    "request_query_sqli_trace",
    "sql_error_trace",
    "quote_or_fragment",
    "privileged_account_ddl",
    "privileged_grant",
    "quote_comment_truncation",
    "schema_column_enumeration",
    "schema_not_in_probe",
    "yaml_critical_pattern",
}
_env_high_risk_hits = os.getenv("HEURISTICS_HIGH_RISK_FLOOR_HITS", "").strip()
HIGH_RISK_FLOOR_HITS: set = (
    set([c.strip() for c in _env_high_risk_hits.split(",") if c.strip()]) or _DEFAULT_HIGH_RISK_FLOOR_HITS
)

_DEFAULT_MEDIUM_RISK_FLOOR_HITS = {
    "metadata_function_probe",
    "information_schema",
    "pg_catalog",
    "sqlite_master",
    "oracle_v_version",
    "mssql_sysdatabases_enum",
}
_env_medium_risk_hits = os.getenv("HEURISTICS_MEDIUM_RISK_FLOOR_HITS", "").strip()
MEDIUM_RISK_FLOOR_HITS: set = (
    set([c.strip() for c in _env_medium_risk_hits.split(",") if c.strip()]) or _DEFAULT_MEDIUM_RISK_FLOOR_HITS
)

# --- Explainability (XAI) metadata for heuristics hit codes ---
_HIT_META: Dict[str, Dict[str, Any]] = {
    "dynamic_identifier_concatenation": {
        "label": "Dynamic SQL identifier concatenation",
        "severity": "high",
        "description": (
            "SQL structure appears to be built by concatenating identifiers "
            "(table/column/order clauses) from variables."
        ),
        "impact": "Potential identifier-level injection and query-shape manipulation.",
        "weight": 0.92,
        "pattern": r"(?is)\b(from|join|order\s+by|group\s+by|into|update)\b\s*[\"']?\s*\+\s*[a-zA-Z_][\w\.]*",
    },
    "dynamic_identifier_placeholder": {
        "label": "Dynamic SQL identifier placeholder",
        "severity": "high",
        "description": (
            "SQL structure contains template placeholders in identifier positions."
        ),
        "impact": "Potential identifier-level injection if placeholder content is user-controlled.",
        "weight": 0.88,
        "pattern": r"(?is)\b(from|join|order\s+by|group\s+by|into|update)\b\s*\{[^}]+\}",
    },
    "query_builder_concat_fragment": {
        "label": "Query-builder string concatenation fragment",
        "severity": "high",
        "description": (
            "Analyzer input looks like query-construction code fragment rather than finalized SQL."
        ),
        "impact": "Final runtime SQL may differ and hide injection risk; requires strict review.",
        "weight": 0.78,
        "pattern": r"(?s)[\"']\s*\+\s*[a-zA-Z_][\w\.]*\s*\+\s*[\"']",
    },
    "union_select": {
        "label": "UNION SELECT detected",
        "severity": "high",
        "description": "UNION-based SQLi can merge attacker-controlled result sets with sensitive columns.",
        "impact": "Potential data exfiltration (e.g., usernames/password hashes).",
        "weight": 0.85,
        "pattern": r"(?i)union\\s+(?:all\\s+)?(?:select|\\(\\s*select)\\b",
    },
    "stacked_query_dml": {
        "label": "Stacked statements detected",
        "severity": "critical",
        "description": "Multiple statements (e.g., '; DROP/UPDATE') can allow destructive operations beyond the intended query.",
        "impact": "Data loss, schema damage, or privilege escalation.",
        "weight": 0.95,
        "pattern": r"(?i);\\s*(drop|delete|insert|update|alter|exec|execute)\\b",
    },
    "tautology_or_1eq1": {
        "label": "Boolean tautology (OR 1=1)",
        "severity": "high",
        "description": "A classic bypass technique that forces conditions to evaluate True.",
        "impact": "Authentication/authorization bypass or unrestricted record access.",
        "weight": 0.9,
        "pattern": r"(?i)\\bor\\b\\s*1\\s*=\\s*1",
    },
    "quoted_tautology": {
        "label": "Quoted tautology ('OR '1'='1')",
        "severity": "high",
        "description": "Quoted tautologies often appear in SQLi payloads targeting string-based WHERE clauses.",
        "impact": "Bypass of WHERE filters and login checks.",
        "weight": 0.95,
        "pattern": r"(?i)'\\s*or\\s*'1'\\s*=\\s*'1",
    },
    "quoted_tautology_simple": {
        "label": "Quoted tautology ('1'='1')",
        "severity": "medium",
        "description": "Always-true comparison that may indicate injection in a string context.",
        "impact": "Filter bypass in vulnerable string concatenation.",
        "weight": 0.9,
        "pattern": r"(?i)'\\s*1'\\s*=\\s*'1'",
    },
    "quoted_tautology_any": {
        "label": "Quoted tautology variant",
        "severity": "high",
        "description": "Quoted equality after OR is often used to force WHERE predicates true.",
        "impact": "Authentication/filter bypass in string-concatenated SQL.",
        "weight": 0.92,
        "pattern": r"(?i)\\bor\\b\\s*'[^']*'\\s*=\\s*'[^']*'",
    },
    "double_quoted_tautology": {
        "label": "Double-quoted tautology variant",
        "severity": "high",
        "description": "Double-quoted OR equality is a common auth-bypass payload variant.",
        "impact": "Authentication/filter bypass in vulnerable SQL construction.",
        "weight": 0.9,
        "pattern": r"(?i)\\bor\\b\\s*\\(?\\s*[\"'][^\"']+[\"']?\\s*=\\s*[\"'][^\"']+[\"']?",
    },
    "or_exists_subquery": {
        "label": "OR EXISTS subquery probe",
        "severity": "high",
        "description": "OR EXISTS predicates are commonly used for bypass and blind inference payloads.",
        "impact": "Potential authorization bypass and conditional data inference.",
        "weight": 0.8,
        "pattern": r"(?i)\\bor\\b\\s*exists\\s*\\(\\s*select\\b",
    },
    "error_extractvalue_probe": {
        "label": "Error-based probe (EXTRACTVALUE)",
        "severity": "high",
        "description": "EXTRACTVALUE is frequently abused for error-based SQLi exfiltration in MySQL.",
        "impact": "Potential metadata extraction via database error messages.",
        "weight": 0.85,
        "pattern": r"(?i)\\bextractvalue\\s*\\(",
    },
    "error_updatexml_probe": {
        "label": "Error-based probe (UPDATEXML)",
        "severity": "high",
        "description": "UPDATEXML is frequently abused for error-based SQLi exfiltration in MySQL.",
        "impact": "Potential metadata extraction via crafted XML errors.",
        "weight": 0.85,
        "pattern": r"(?i)\\bupdatexml\\s*\\(",
    },
    "ascii_substring_probe": {
        "label": "ASCII/SUBSTRING extraction probe",
        "severity": "high",
        "description": "ASCII/SUBSTRING comparisons often indicate blind character-by-character extraction.",
        "impact": "Potential progressive exfiltration of secrets without direct result output.",
        "weight": 0.9,
        "pattern": r"(?is)\\b(?:ascii|ord)\\s*\\(\\s*(?:substring|substr|mid)\\s*\\([^)]*\\)\\s*\\)\\s*(?:=|>|<|like)\\s*(?:\\d+|'[^']*'|\\\"[^\\\"]*\\\")",
    },
    "char_obfuscation_predicate": {
        "label": "CHAR() obfuscation in predicate",
        "severity": "high",
        "description": "CHAR()-encoded values in WHERE predicates can hide payload intent.",
        "impact": "Obfuscated SQL can evade simple signature filters and aid bypass attempts.",
        "weight": 0.85,
        "pattern": r"(?i)\\bwhere\\b[^;]*=\\s*char\\s*\\(\\s*\\d+",
    },
    "time_waitfor_delay": {
        "label": "Time delay (WAITFOR DELAY)",
        "severity": "high",
        "description": "Timing functions are used in blind SQLi to infer data through response delays.",
        "impact": "Data inference without visible errors or output.",
        "weight": 0.85,
        "pattern": r"(?i)waitfor\\s+delay\\s+'\\d+:\\d+:(?:\\d+|__time__)'",
    },
    "time_sleep": {
        "label": "Time delay (SLEEP)",
        "severity": "high",
        "description": "SLEEP() is commonly used for time-based blind SQLi.",
        "impact": "Data inference via timing side-channel.",
        "weight": 0.85,
        "pattern": r"(?i)sleep\\s*\\(\\s*\\d+\\s*\\)",
    },
    "time_pg_sleep": {
        "label": "Time delay (pg_sleep)",
        "severity": "high",
        "description": "pg_sleep() is commonly used for time-based blind SQLi in PostgreSQL.",
        "impact": "Data inference via timing side-channel.",
        "weight": 0.85,
        "pattern": r"(?i)pg_sleep\\s*\\(",
    },
    "time_benchmark": {
        "label": "Time delay (BENCHMARK)",
        "severity": "high",
        "description": "BENCHMARK() can cause measurable delays for blind SQLi probing.",
        "impact": "Data inference via timing side-channel.",
        "weight": 0.85,
        "pattern": r"(?i)benchmark\\s*\\(\\s*\\d+\\s*,",
    },
    "blind_subquery_exfiltration": {
        "label": "Blind subquery exfiltration probe",
        "severity": "critical",
        "description": "String/ASCII extraction over nested SELECT indicates blind SQLi data probing.",
        "impact": "Progressive exfiltration of database metadata/secrets one character at a time.",
        "weight": 1.0,
        "pattern": r"(?is)\\b(substring|substr|mid|ascii|ord)\\s*\\(\\s*\\(\\s*select\\b.*?\\)\\s*,\\s*\\d+\\s*(?:,\\s*\\d+\\s*)?\\)\\s*(=|>|<|like)\\s*(?:'[^']*'|\\\"[^\\\"]*\\\"|\\d+)",
    },
    "metadata_function_probe": {
        "label": "Database metadata function probe",
        "severity": "medium",
        "description": "Version/user/database metadata function usage is often part of SQLi reconnaissance.",
        "impact": "Attacker can fingerprint DB engine and refine payloads.",
        "weight": 0.65,
        "pattern": r"(?i)\\b(?:@@version|version\\s*\\(\\s*\\)|current_database\\s*\\(\\s*\\)|database\\s*\\(\\s*\\)|current_user\\b|session_user\\b|system_user\\b|user\\s*\\(\\s*\\))\\b",
    },
    "oracle_v_version": {
        "label": "Oracle version view enumeration",
        "severity": "medium",
        "description": "Querying Oracle version catalog views is commonly used for reconnaissance.",
        "impact": "Engine/version fingerprinting to tune attack payloads.",
        "weight": 0.7,
        "pattern": r"(?i)\\bv\\$version\\b",
    },
    "mssql_sysdatabases_enum": {
        "label": "MSSQL catalog enumeration",
        "severity": "medium",
        "description": "Listing SQL Server system database catalogs is a reconnaissance pattern.",
        "impact": "Database inventory disclosure to guide follow-on attacks.",
        "weight": 0.7,
        "pattern": r"(?i)\\b(?:master\\.dbo\\.sysdatabases|sys\\.databases)\\b",
    },
    "information_schema": {
        "label": "INFORMATION_SCHEMA enumeration",
        "severity": "medium",
        "description": "Information schema access is frequently used to enumerate tables and columns.",
        "impact": "Schema disclosure that accelerates injection exploitation.",
        "weight": 0.6,
        "pattern": r"(?i)information_schema\\.",
    },
    "schema_column_enumeration": {
        "label": "Schema column enumeration",
        "severity": "high",
        "description": "Column-name enumeration through INFORMATION_SCHEMA is a common SQLi reconnaissance step.",
        "impact": "Disclosure of table/column structure used for follow-on extraction.",
        "weight": 0.82,
        "pattern": r"(?is)(?:information_schema\\.columns[\\s\\S]{0,220}\\bcolumn_name\\b|\\bcolumn_name\\b[\\s\\S]{0,220}information_schema\\.columns)",
    },
    "schema_not_in_probe": {
        "label": "Schema exclusion enumeration probe",
        "severity": "high",
        "description": "Filtering out system schemas while listing metadata is typical attack reconnaissance.",
        "impact": "Focused disclosure of application tables and schemas.",
        "weight": 0.8,
        "pattern": r"(?is)information_schema\\.tables[\\s\\S]{0,220}\\bnot\\s+in\\b",
    },
    "file_ops": {
        "label": "File read/write SQL operation",
        "severity": "high",
        "description": "Database file functions can read local files or write exfiltrated content.",
        "impact": "Potential sensitive file disclosure or out-of-band exfiltration.",
        "weight": 0.8,
        "pattern": r"(?i)\\b(load_file|into\\s+outfile|into\\s+dumpfile)\\b",
    },
    "copy_to_program": {
        "label": "PostgreSQL COPY TO PROGRAM",
        "severity": "critical",
        "description": "COPY ... TO PROGRAM can execute an operating-system command from PostgreSQL.",
        "impact": "Potential command execution or out-of-band exfiltration from the database host.",
        "weight": 0.95,
        "pattern": r"(?is)\\bcopy\\b[\\s\\S]{0,400}\\bto\\s+program\\b",
    },
    "privileged_account_ddl": {
        "label": "Privileged account DDL",
        "severity": "high",
        "description": "User-management DDL is highly sensitive in request-path SQL contexts.",
        "impact": "Privilege escalation by creating or altering database accounts.",
        "weight": 0.9,
        "pattern": r"(?i)\\b(create|alter|drop)\\s+user\\b",
    },
    "privileged_grant": {
        "label": "Privileged GRANT statement",
        "severity": "high",
        "description": "GRANT statements in request-path SQL can expand privileges.",
        "impact": "Privilege escalation or unauthorized access expansion.",
        "weight": 0.85,
        "pattern": r"(?i)\\bgrant\\s+(?:all|connect|resource|dba|select|insert|update|delete)\\b",
    },
    "xp_cmdshell": {
        "label": "Dangerous procedure (xp_cmdshell)",
        "severity": "critical",
        "description": "xp_cmdshell may allow OS command execution from SQL Server when enabled.",
        "impact": "Remote code execution on the database host.",
        "weight": 1.0,
        "pattern": r"(?i)\\bxp_cmdshell\\b",
    },
    "oracle_utl": {
        "label": "Oracle UTL out-of-band primitive",
        "severity": "critical",
        "description": "Oracle UTL_HTTP/UTL_INADDR/UTL_FILE usage can enable out-of-band callbacks or file access.",
        "impact": "Potential DNS/HTTP exfiltration, SSRF-style callbacks, or local file access from Oracle.",
        "weight": 0.9,
        "pattern": r"(?i)\\butl_(?:http|inaddr|file)\\b|\\bget_host_address\\s*\\(",
    },
    "oracle_dbms_pipe": {
        "label": "Oracle DBMS_PIPE timing primitive",
        "severity": "critical",
        "description": "DBMS_PIPE.RECEIVE_MESSAGE is commonly used for Oracle time-based blind SQL injection.",
        "impact": "Data inference via response timing side-channel.",
        "weight": 0.85,
        "pattern": r"(?i)dbms_pipe\\.receive_message\\s*\\(",
    },
    "metadata_length_probe": {
        "label": "Metadata length inference probe",
        "severity": "high",
        "description": "Length checks over metadata functions are common blind SQLi inference probes.",
        "impact": "Potential data inference through boolean response differences.",
        "weight": 0.82,
        "pattern": r"(?is)\\b(?:length|len)\\s*\\([^)]*(?:@@hostname|@@version|version\\s*\\(|database\\s*\\(|current_database\\s*\\(|user\\s*\\()[^)]*\\)\\s*(?:=|>|<|between|like)",
    },
    "metadata_substring_probe": {
        "label": "Metadata substring inference probe",
        "severity": "high",
        "description": "Substring comparisons over metadata functions indicate blind character-by-character probing.",
        "impact": "Potential progressive exfiltration of database metadata.",
        "weight": 0.88,
        "pattern": r"(?is)\\b(?:substring|substr|mid)\\s*\\([^)]*(?:@@hostname|@@version|version\\s*\\(|database\\s*\\(|current_database\\s*\\(|user\\s*\\()[\\s\\S]{0,120}(?:=|>|<|like|between|not\\s+in)",
    },
    "metadata_self_compare": {
        "label": "Metadata self-comparison probe",
        "severity": "high",
        "description": "Comparing metadata functions against themselves is a low-noise boolean SQLi probe.",
        "impact": "Potential boolean inference over database metadata functions.",
        "weight": 0.78,
        "pattern": r"(?is)\\b(?:current_database|database|user|version)\\s*\\(\\s*\\)\\s*=\\s*\\b(?:current_database|database|user|version)\\s*\\(",
    },
    "conditional_error_probe": {
        "label": "Conditional error-based probe",
        "severity": "high",
        "description": "CASE/IF branches that intentionally trigger errors are used for blind/error-based SQLi.",
        "impact": "Potential data inference through controlled database errors.",
        "weight": 0.82,
        "pattern": r"(?is)\\bcase\\s+when\\b[\\s\\S]{0,200}\\belse\\b[\\s\\S]{0,80}(?:json\\s*\\(\\s*''\\s*\\)|1\\s*/\\s*0|convert\\s*\\()",
    },
    "mssql_sys_tables_probe": {
        "label": "SQL Server catalog conditional probe",
        "severity": "high",
        "description": "Conditional logic over sys.tables/sys.objects is a SQL Server reconnaissance/inference pattern.",
        "impact": "Potential schema enumeration or error-based inference.",
        "weight": 0.82,
        "pattern": r"(?is)\\bcase\\s+when\\b[\\s\\S]{0,160}\\bsys\\.(?:tables|objects|databases)\\b",
    },
    "boolean_probe_with_comment": {
        "label": "Boolean probe with comment truncation",
        "severity": "high",
        "description": "AND/OR boolean probes followed by comments are used to compare true/false application responses.",
        "impact": "Potential blind SQL injection validation through response differences.",
        "weight": 0.82,
        "pattern": r"(?is)\\b(?:and|or)\\b\\s*\\(?\\s*1\\s*\\)?\\s*=\\s*\\(?\\s*[12]\\s*\\)?[\\s\\S]{0,80}(?:--|#|/\\*)",
    },
    "request_query_sqli_trace": {
        "label": "HTTP request SQLi trace",
        "severity": "high",
        "description": "A URL or HTTP request line contains SQL metacharacters or query fragments.",
        "impact": "Potential SQL injection attempt captured before reaching the database layer.",
        "weight": 0.78,
        "pattern": r"(?is)\\b(?:get|post)\\s+/|https?://[^\\s]+[?&][^\\s]*(?:\\bselect\\b|\\bfrom\\b|\\bor\\b|\\band\\b|%27|')",
    },
    "mysql_comment_escape_probe": {
        "label": "MySQL comment/identifier escape probe",
        "severity": "high",
        "description": "Backtick, hash-comment, or null-byte style fragments are common MySQL parser escape probes.",
        "impact": "Potential parser confusion or identifier-context SQL injection.",
        "weight": 0.78,
        "pattern": r"(?is)(?:\\?#\\\\0|#\\\\0|`;#|`\\s+from\\s*\\(|#\\s*\\d+(?:st|nd|rd|th)\\s+payload)",
    },
    "sql_error_trace": {
        "label": "SQL error trace",
        "severity": "high",
        "description": "Database syntax/error output in request-path input often indicates active SQLi probing.",
        "impact": "Potential feedback loop for refining SQL injection payloads.",
        "weight": 0.78,
        "pattern": r"(?is)(?:sql syntax|unterminated quoted string|syntax error at or near|right syntax to use near)",
    },
    "quote_comment_truncation": {
        "label": "Quote plus comment truncation",
        "severity": "high",
        "description": "A quote immediately followed by SQL comment syntax is a classic string-context bypass.",
        "impact": "Potential truncation of the intended WHERE/authentication predicate.",
        "weight": 0.82,
        "pattern": r"(?is)(?:^|[\\s:=,(\\\\])(?:[a-z0-9_]+)?\\\\?[\"']\\s*(?:--|#|/\\*)",
    },
    "comment_inline": {
        "label": "Inline comment delimiter (--)",
        "severity": "medium",
        "description": "SQLi payloads often terminate the intended query using comment delimiters.",
        "impact": "Filter bypass by truncating the query.",
        "weight": 0.4,
        "pattern": r"--",
    },
    "comment_sequence": {
        "label": "Comment delimiter sequence",
        "severity": "low",
        "description": "Comment markers are frequently present in injection payloads.",
        "impact": "May truncate query logic in vulnerable concatenation.",
        "weight": 0.4,
        "pattern": r"(--|#)",
    },
    "ddl_statement_ast": {
        "label": "DDL statement detected (AST)",
        "severity": "high",
        "description": "Schema-modifying statements are unusual in typical request-driven queries.",
        "impact": "Schema modification or destructive operations.",
    },
    "exec_statement_ast": {
        "label": "EXEC/CALL detected (AST)",
        "severity": "high",
        "description": "EXEC/CALL may indicate execution of stored procedures in an injection context.",
        "impact": "Privilege escalation or command execution (DB dependent).",
    },
    "union_ast": {
        "label": "UNION detected (AST)",
        "severity": "high",
        "description": "UNION operators are commonly used to extract data across tables.",
        "impact": "Potential data exfiltration.",
    },
    "time_fn_ast": {
        "label": "Timing function detected (AST)",
        "severity": "high",
        "description": "Timing functions often indicate blind SQL injection probes.",
        "impact": "Data inference via timing side-channel.",
    },
}

def _unique_preserve_order(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out

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


def _normalize_sql_surface(text: str) -> str:
    try:
        out = unicodedata.normalize("NFKC", str(text or ""))
    except Exception:
        out = str(text or "")
    out = out.translate(_SMART_SQL_TRANSLATION)
    out = re.sub(r"(?is)/\*!\d{3,5}\s*(.*?)\*/", r" \1 ", out)
    out = re.sub(r"\s+", " ", out).strip()
    return out


def _sql_detection_surfaces(sql: str) -> List[str]:
    """Build bounded decoded/canonical surfaces for SQLi detection without losing traces."""
    raw = str(sql or "")
    candidates: List[str] = []

    def add(value: str) -> None:
        value = _normalize_sql_surface(value)
        if value and value not in candidates:
            candidates.append(value[:8000])

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
    try:
        mysql_unwrapped = re.sub(r"(?is)/\*!\d{3,5}\s*(.*?)\*/", r" \1 ", raw)
        add(mysql_unwrapped)
    except Exception:
        pass
    return candidates

def _merge_highlights(ranges: List[Dict[str, Any]], cap: int = 60) -> List[Dict[str, Any]]:
    """Merge overlapping/adjacent highlight ranges; keeps earliest label/severity."""
    if not ranges:
        return []
    ranges_sorted = sorted(
        (r for r in ranges if isinstance(r.get("start"), int) and isinstance(r.get("end"), int)),
        key=lambda r: (int(r["start"]), int(r["end"])),
    )
    merged: List[Dict[str, Any]] = []
    for r in ranges_sorted:
        if not merged:
            merged.append(r)
            continue
        prev = merged[-1]
        if int(r["start"]) <= int(prev["end"]):
            prev["end"] = max(int(prev["end"]), int(r["end"]))
            continue
        merged.append(r)
        if len(merged) >= cap:
            break
    return merged

class QueryAnalysisService:
    _instance: Optional['QueryAnalysisService'] = None
    _anomaly_model_instance: Optional[AnomalyDetectionModel] = None
    _query_validation_pipeline: Optional[Any] = None
    _alerts_service_instance: Optional[AlertsService] = None
    _incident_response_service_instance: Optional[IncidentResponseService] = None
    _initialized_flag: bool = False

    def __new__(cls, *args, **kwargs) -> 'QueryAnalysisService':
        if cls._instance is None:
            cls._instance = super(QueryAnalysisService, cls).__new__(cls)
        return cls._instance

    def __init__(self,
                 anomaly_model_path: str,
                 anomaly_scaler_path: str,
                 query_validation_model_path: str,
                 alerts_service: AlertsService):
        if self._initialized_flag:
            return
        logger.info("Initializing QueryAnalysisService...")
        try:
            self._anomaly_model_instance = AnomalyDetectionModel(
                model_path=anomaly_model_path, processor_scaler_path=anomaly_scaler_path
            )
            logger.info("✅ Anomaly Detection model loaded successfully.")
        except Exception as e:
            logger.critical(f"❌ FATAL: Failed to load Anomaly Detection model: {e}", exc_info=True)
        try:
            self._query_validation_pipeline = joblib.load(query_validation_model_path)
            logger.info("✅ NLP Query Validation pipeline loaded successfully.")
        except Exception as e:
            logger.critical(f"❌ FATAL: Failed to load NLP Query Validation pipeline: {e}", exc_info=True)
        self._alerts_service_instance = alerts_service
        try:
            self._incident_response_service_instance = IncidentResponseService.get_instance()
        except Exception:
            self._incident_response_service_instance = IncidentResponseService(alerts_service=alerts_service)
        self._initialized_flag = True
        logger.info("QueryAnalysisService initialization sequence finished.")
        if not self.are_models_loaded():
            logger.error("CRITICAL: One or more models failed to load.")

    @classmethod
    def get_instance(cls) -> 'QueryAnalysisService':
        if cls._instance is None:
            raise RuntimeError("QueryAnalysisService has not been initialized.")
        return cls._instance

    def are_models_loaded(self) -> bool:
        return self._anomaly_model_instance is not None and self._query_validation_pipeline is not None

    def _preprocess_query_for_nlp(self, query_text: str) -> str:
        if not isinstance(query_text, str): return ""
        text = query_text.lower()
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def _combine_assessments(
        self,
        anomaly_result: Optional[AnomalyDetectionResult],
        nlp_result: Optional[QueryValidationResult],
        heuristics: Optional[SQLHeuristicsResult],
        calibrated_risk_score: Optional[float] = None,
        signal_contributions: Optional[Dict[str, float]] = None,
        ast_features: Optional[Dict[str, Any]] = None,
    ) -> CombinedRiskAssessment:
        reasons, overall_risk, suggested_action = [], "Low", "ALLOW"
        if anomaly_result:
            reasons.append(f"Anomaly detection: '{anomaly_result.prediction_label}'.")
        nlp_is_malicious = bool(nlp_result and "malicious" in nlp_result.classification_label.lower())
        if nlp_is_malicious:
            reasons.append(f"NLP validation: '{nlp_result.classification_label}'.")
        heur_sus = bool(heuristics and heuristics.suspected)
        if heur_sus and heuristics and heuristics.hits:
            reasons.append("Heuristics: " + ", ".join(heuristics.hits[:5]))

        # High-confidence heuristics that should drive decisions immediately
        heur_hits = set(heuristics.hits if heuristics else [])
        high_conf_hits = set([h for h in heur_hits if h in CRITICAL_CODES])
        high_risk_floor_hits = set([h for h in heur_hits if h in HIGH_RISK_FLOOR_HITS])
        medium_risk_floor_hits = set([h for h in heur_hits if h in MEDIUM_RISK_FLOOR_HITS])
        dynamic_structure_hits = {
            "dynamic_identifier_concatenation",
            "dynamic_identifier_placeholder",
            "query_builder_concat_fragment",
        }
        has_dynamic_structure_risk = any(h in dynamic_structure_hits for h in heur_hits)
        ast = ast_features or {}
        ast_structural_support = bool(
            ast.get("has_union")
            or ast.get("has_stacked_statements")
            or ast.get("has_time_function")
            or ast.get("has_exec")
            or ast.get("has_ddl")
            or ast.get("has_tautology")
            or ast.get("has_comment")
        )
        risk_rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        nlp_conf = float(nlp_result.classification_score or 0.0) if nlp_result else 0.0
        supportive_signals = bool(
            high_conf_hits
            or high_risk_floor_hits
            or medium_risk_floor_hits
            or heur_sus
            or ast_structural_support
            or (anomaly_result and anomaly_result.is_anomalous)
        )

        # Precision-v2 score-driven decisioning (preferred path when available)
        if calibrated_risk_score is not None:
            if high_conf_hits or calibrated_risk_score >= SQL_PRECISION_BLOCK_THRESHOLD:
                overall_risk, suggested_action = "Critical", "BLOCK_IMMEDIATE"
            elif high_risk_floor_hits:
                overall_risk, suggested_action = "High", "FLAG_FOR_REVIEW_BLOCK"
            elif calibrated_risk_score >= SQL_PRECISION_HIGH_THRESHOLD:
                overall_risk, suggested_action = "High", "FLAG_FOR_REVIEW_BLOCK"
            elif calibrated_risk_score >= SQL_PRECISION_MEDIUM_THRESHOLD:
                overall_risk, suggested_action = "Medium", "FLAG_FOR_REVIEW"
            else:
                overall_risk, suggested_action = "Low", "ALLOW"
            reasons.append(
                f"Calibrated risk score: {calibrated_risk_score:.2f} "
                f"(medium={SQL_PRECISION_MEDIUM_THRESHOLD:.2f}, high={SQL_PRECISION_HIGH_THRESHOLD:.2f}, block={SQL_PRECISION_BLOCK_THRESHOLD:.2f})."
            )
            # NLP floor: keep protection, but avoid NLP-only hard escalation without corroboration.
            if nlp_is_malicious and nlp_conf >= SQL_NLP_MALICIOUS_HIGH_THRESHOLD:
                if risk_rank.get(overall_risk, 0) < risk_rank["High"]:
                    if supportive_signals:
                        overall_risk, suggested_action = "High", "FLAG_FOR_REVIEW_BLOCK"
                        reasons.append(
                            "NLP malicious confidence floor applied with corroborating indicators: "
                            f"{nlp_conf:.2f} >= {SQL_NLP_MALICIOUS_HIGH_THRESHOLD:.2f}."
                        )
                    elif risk_rank.get(overall_risk, 0) < risk_rank["Medium"]:
                        overall_risk, suggested_action = "Medium", "FLAG_FOR_REVIEW"
                        reasons.append(
                            "NLP-only malicious confidence raised to Medium pending corroboration: "
                            f"{nlp_conf:.2f} >= {SQL_NLP_MALICIOUS_HIGH_THRESHOLD:.2f}."
                        )
            elif nlp_is_malicious and nlp_conf >= SQL_NLP_MALICIOUS_REVIEW_THRESHOLD:
                if risk_rank.get(overall_risk, 0) < risk_rank["Medium"]:
                    overall_risk, suggested_action = "Medium", "FLAG_FOR_REVIEW"
                    if supportive_signals:
                        reasons.append(
                            "NLP malicious review floor applied with corroborating indicators: "
                            f"{nlp_conf:.2f} >= {SQL_NLP_MALICIOUS_REVIEW_THRESHOLD:.2f}."
                        )
                    else:
                        reasons.append(
                            "NLP malicious review floor applied pending corroboration: "
                            f"{nlp_conf:.2f} >= {SQL_NLP_MALICIOUS_REVIEW_THRESHOLD:.2f}."
                        )
        else:
            if high_conf_hits:
                overall_risk, suggested_action = "Critical", "BLOCK_IMMEDIATE"
            elif high_risk_floor_hits:
                overall_risk, suggested_action = "High", "FLAG_FOR_REVIEW_BLOCK"
            elif anomaly_result and anomaly_result.is_anomalous and nlp_is_malicious:
                overall_risk, suggested_action = "Critical", "BLOCK_IMMEDIATE"
            elif (heur_sus and (heuristics.heuristic_score or 0) >= HEURISTICS_HIGH_THRESHOLD) or (nlp_is_malicious and supportive_signals):
                overall_risk, suggested_action = "High", "FLAG_FOR_REVIEW_BLOCK"
            elif nlp_is_malicious:
                overall_risk, suggested_action = "Medium", "FLAG_FOR_REVIEW"
            elif anomaly_result and anomaly_result.is_anomalous:
                overall_risk, suggested_action = "Medium", "FLAG_FOR_REVIEW"

        # Structural risk floor: query-construction fragments and dynamic identifiers are high-risk by design.
        if has_dynamic_structure_risk and risk_rank.get(overall_risk, 0) < risk_rank["High"]:
            overall_risk, suggested_action = "High", "FLAG_FOR_REVIEW_BLOCK"
            reasons.append(
                "Dynamic SQL construction floor applied due to identifier/query-builder composition risk."
            )
        if high_risk_floor_hits and risk_rank.get(overall_risk, 0) < risk_rank["High"]:
            overall_risk, suggested_action = "High", "FLAG_FOR_REVIEW_BLOCK"
            reasons.append(
                "High-risk SQLi heuristic floor applied: "
                + ", ".join(sorted(list(high_risk_floor_hits))[:4])
                + "."
            )
        if medium_risk_floor_hits and risk_rank.get(overall_risk, 0) < risk_rank["Medium"]:
            overall_risk, suggested_action = "Medium", "FLAG_FOR_REVIEW"
            reasons.append(
                "Reconnaissance metadata floor applied: "
                + ", ".join(sorted(list(medium_risk_floor_hits))[:4])
                + "."
            )

        if heuristics and heuristics.hits and not any("Heuristic" in r for r in reasons):
            reasons.append("Heuristic hits: " + ", ".join(heuristics.hits[:5]))
        if heuristics and heuristics.heuristic_score is not None and not any("Heuristic score" in r for r in reasons):
            reasons.append(f"Heuristic score: {heuristics.heuristic_score:.2f}")
        if ast_features:
            reasons.append(
                "AST/structure: "
                f"statements={ast_features.get('statement_count', 1)}, "
                f"union={bool(ast_features.get('has_union'))}, "
                f"stacked={bool(ast_features.get('has_stacked_statements'))}, "
                f"ddl={bool(ast_features.get('has_ddl'))}."
            )
        if overall_risk in {"Critical", "High"}:
            reasons.append(f"Policy escalated to {overall_risk} ({suggested_action}).")
        if not reasons:
            reasons.append(f"No malicious indicators detected; overall risk {overall_risk}.")
        return CombinedRiskAssessment(
            overall_risk_level=overall_risk,
            suggested_action=suggested_action,
            reasoning=reasons,
            calibrated_risk_score=calibrated_risk_score,
            signal_contributions=signal_contributions,
            ast_features=ast_features,
        )

    def _heuristics_scan(self, sql: str) -> SQLHeuristicsResult:
        """Rule-based SQLi detector leveraging regex heuristics; returns matched hit codes and a score."""
        s = sql or ""
        hits: List[str] = []
        score = 0.0
        patterns = [
            (
                r"(?is)\b(from|join|order\s+by|group\s+by|into|update)\b\s*[\"']?\s*\+\s*[a-zA-Z_][\w\.]*",
                "dynamic_identifier_concatenation",
                0.92,
            ),
            (
                r"(?is)\b(from|join|order\s+by|group\s+by|into|update)\b\s*\{[^}]+\}",
                "dynamic_identifier_placeholder",
                0.88,
            ),
            (
                r"(?s)[\"']\s*\+\s*[a-zA-Z_][\w\.]*\s*\+\s*[\"']",
                "query_builder_concat_fragment",
                0.78,
            ),
            (r"(?i)'\s*1'\s*=\s*'1'", "quoted_tautology_simple", 0.9),
            (r"(?i)'\s*or\s*'1'\s*=\s*'1", "quoted_tautology", 0.95),
            (r"(?i)\bor\b\s*'[^']*'\s*=\s*'[^']*'", "quoted_tautology_any", 0.92),
            (r"(?i)\bor\b\s*\(?\s*[\"'][^\"']+[\"']?\s*=\s*[\"'][^\"']+[\"']?", "double_quoted_tautology", 0.9),
            (r"(?i)\bor\b\s*1\s*=\s*1", "tautology_or_1eq1", 0.9),
            (r"(?i)\bor\b\s*exists\s*\(\s*select\b", "or_exists_subquery", 0.8),
            (r"(?i)\band\b\s*1\s*=\s*1", "boolean_true", 0.7),
            (r"(?i)\band\b\s*1\s*=\s*2", "boolean_false", 0.7),
            (r"(?is)\b(?:and|or)\b\s*\(?\s*1\s*\)?\s*=\s*\(?\s*[12]\s*\)?[\s\S]{0,80}(?:--|#|/\*)", "boolean_probe_with_comment", 0.82),
            (r"(?i)union\s+(?:all\s+)?(?:select|\(\s*select)\b", "union_select", 0.85),
            (r"(?i);\s*(drop|delete|insert|update|alter|exec|execute)\b", "stacked_query_dml", 0.95),
            (r"(?i)\b(create|alter|drop)\s+user\b", "privileged_account_ddl", 0.9),
            (r"(?i)\bgrant\s+(?:all|connect|resource|dba|select|insert|update|delete)\b", "privileged_grant", 0.85),
            (r"(?i)waitfor\s+delay\s+'\d+:\d+:(?:\d+|__time__)'", "time_waitfor_delay", 0.85),
            (r"(?i)sleep\s*\(\s*(?:\d+|__time__|[a-z_][\w]*)\s*\)", "time_sleep", 0.85),
            (r"(?i)pg_sleep\s*\(", "time_pg_sleep", 0.85),
            (r"(?i)benchmark\s*\(\s*\d+\s*,", "time_benchmark", 0.85),
            (r"(?i)\bxp_cmdshell\b", "xp_cmdshell", 1.0),
            (r"(?i)\bxp_dirtree\b", "xp_dirtree", 0.9),
            (r"(?i)\bxp_reg(read|write)\b", "xp_regread", 0.9),
            (r"(?i)openrowset\s*\(", "openrowset", 0.8),
            (r"(?i)sp_OACreate\b", "sp_oacreate", 0.9),
            (
                r"(?is)\b(substring|substr|mid|ascii|ord)\s*\(\s*\(\s*select\b.*?\)\s*,\s*\d+\s*(?:,\s*\d+\s*)?\)\s*(=|>|<|like)\s*(?:'[^']*'|\"[^\"]*\"|\d+)",
                "blind_subquery_exfiltration",
                1.0,
            ),
            (
                r"(?is)\b(?:ascii|ord)\s*\(\s*(?:substring|substr|mid)\s*\([^)]*\)\s*\)\s*(?:=|>|<|like)\s*(?:\d+|'[^']*'|\"[^\"]*\")",
                "ascii_substring_probe",
                0.9,
            ),
            (r"(?i)\bextractvalue\s*\(", "error_extractvalue_probe", 0.85),
            (r"(?i)\bupdatexml\s*\(", "error_updatexml_probe", 0.85),
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
                r"(?is)\b(?:current_database|database|user|version)\s*\(\s*\)\s*=\s*\b(?:current_database|database|user|version)\s*\(",
                "metadata_self_compare",
                0.78,
            ),
            (
                r"(?is)\bcase\s+when\b[\s\S]{0,200}\belse\b[\s\S]{0,80}(?:json\s*\(\s*''\s*\)|1\s*/\s*0|convert\s*\()",
                "conditional_error_probe",
                0.82,
            ),
            (
                r"(?is)\bcase\s+when\b[\s\S]{0,160}\bsys\.(?:tables|objects|databases)\b",
                "mssql_sys_tables_probe",
                0.82,
            ),
            (
                r"(?i)\b(?:@@version|version\s*\(\s*\)|current_database\s*\(\s*\)|database\s*\(\s*\)|current_user\b|session_user\b|system_user\b|user\s*\(\s*\))\b",
                "metadata_function_probe",
                0.65,
            ),
            (r"(?i)\bv\$version\b", "oracle_v_version", 0.7),
            (r"(?i)\b(load_file|into\s+outfile|into\s+dumpfile)\b", "file_ops", 0.8),
            (r"(?i)information_schema\.", "information_schema", 0.6),
            (
                r"(?is)(?:information_schema\.columns[\s\S]{0,220}\bcolumn_name\b|\bcolumn_name\b[\s\S]{0,220}information_schema\.columns)",
                "schema_column_enumeration",
                0.82,
            ),
            (r"(?is)information_schema\.tables[\s\S]{0,220}\bnot\s+in\b", "schema_not_in_probe", 0.8),
            (r"(?i)\b(?:master\.dbo\.sysdatabases|sys\.databases)\b", "mssql_sysdatabases_enum", 0.7),
            (r"(?i)pg_catalog\.", "pg_catalog", 0.6),
            (r"(?i)sqlite_master\b", "sqlite_master", 0.6),
            (r"(?i)attach\s+database\b", "sqlite_attach", 0.7),
            (r"(?i)\bwhere\b[^;]*=\s*char\s*\(\s*\d+", "char_obfuscation_predicate", 0.85),
            (r"(?i)char\s*\(\s*\d+", "char_func", 0.6),
            (r"(?i)0x[0-9a-f]{4,}", "hex_literal", 0.5),
            (r"(?i)/\*!\d{3,5}\s", "mysql_versioned_comment", 0.7),
            (r"(?is)\bcopy\b[\s\S]{0,400}\bto\s+program\b", "copy_to_program", 0.95),
            (r"(?i)dbms_pipe\.receive_message\s*\(", "oracle_dbms_pipe", 0.85),
            (r"(?i)\butl_(?:http|inaddr|file)\b|\bget_host_address\s*\(", "oracle_utl", 0.9),
            (r"(?i)chr\s*\(\s*\d+\s*\)", "oracle_chr", 0.6),
            (
                r"(?is)\b(?:get|post)\s+/|https?://[^\s]+[?&][^\s]*(?:\bselect\b|\bfrom\b|\bor\b|\band\b|%27|')",
                "request_query_sqli_trace",
                0.78,
            ),
            (r"(?is)(?:\?#\\0|#\\0|`;#|`\s+from\s*\(|#\s*\d+(?:st|nd|rd|th)\s+payload)", "mysql_comment_escape_probe", 0.78),
            (r"(?is)(?:sql syntax|unterminated quoted string|syntax error at or near|right syntax to use near)", "sql_error_trace", 0.78),
            (r"(?is)^\s*[\"']\s*or\s+[\"']?[a-z0-9_]+", "quote_or_fragment", 0.78),
            (r"(?is)(?:^|[\s:=,(\\])(?:[a-z0-9_]+)?\\?[\"']\s*(?:--|#|/\*)", "quote_comment_truncation", 0.82),
            (r"/\*.*?\*/", "c_comment_block", 0.4),
            (r"--|#", "comment_sequence", 0.4),
        ]
        # finditer gives us flexibility for multiple hits per pattern
        for surface in _sql_detection_surfaces(s):
            for pat, code, weight in patterns:
                try:
                    if re.search(pat, surface, flags=re.DOTALL):
                        if code not in hits:
                            hits.append(code)
                            score += weight
                except re.error:
                    continue
        # Cap score
        score = min(score, 1.5)
        suspected = score >= 0.75 or any(
            h in hits
            for h in [
                "xp_cmdshell",
                "stacked_query_dml",
                "union_select",
                "blind_subquery_exfiltration",
                "quoted_tautology",
                "quoted_tautology_any",
                "tautology_or_1eq1",
                "or_exists_subquery",
                "error_extractvalue_probe",
                "error_updatexml_probe",
                "ascii_substring_probe",
                "char_obfuscation_predicate",
                "boolean_probe_with_comment",
                "conditional_error_probe",
                "copy_to_program",
                "double_quoted_tautology",
                "metadata_length_probe",
                "metadata_self_compare",
                "metadata_substring_probe",
                "mssql_sys_tables_probe",
                "mysql_comment_escape_probe",
                "oracle_dbms_pipe",
                "oracle_utl",
                "privileged_grant",
                "quote_comment_truncation",
                "request_query_sqli_trace",
                "schema_column_enumeration",
                "schema_not_in_probe",
                "sql_error_trace",
                "privileged_account_ddl",
                "file_ops",
                "dynamic_identifier_concatenation",
                "dynamic_identifier_placeholder",
                "query_builder_concat_fragment",
            ]
        )
        return SQLHeuristicsResult(suspected=suspected, hits=hits, heuristic_score=round(min(score, 1.0), 3))

    def _extract_sql_ast_features(self, sql: str) -> Dict[str, Any]:
        s = sql or ""
        s_upper = f" {s.upper()} "
        # Avoid splitting on semicolons inside quotes.
        split_pat = r";(?=(?:[^'\"`]|'[^']*'|\"[^\"]*\"|`[^`]*`)*$)"
        statements = [part.strip() for part in re.split(split_pat, s) if part.strip()]
        statement_count = len(statements) if statements else (1 if s.strip() else 0)

        features: Dict[str, Any] = {
            "statement_count": statement_count,
            "has_stacked_statements": statement_count > 1,
            "has_union": bool(re.search(r"(?i)\bunion\b", s)),
            "has_comment": bool(re.search(r"(--|#|/\*)", s)),
            "has_tautology": bool(
                re.search(r"(?i)\bor\b\s*1\s*=\s*1", s)
                or re.search(r"(?i)'\s*or\s*'1'\s*=\s*'1", s)
                or re.search(r"(?i)\bor\b\s*'[^']*'\s*=\s*'[^']*'", s)
            ),
            "has_time_function": bool(re.search(r"(?i)\b(sleep|pg_sleep|benchmark|waitfor\s+delay)\b", s)),
            "has_ddl": bool(re.search(r"(?i)\b(drop|alter|create|truncate|rename)\b", s)),
            "has_exec": bool(re.search(r"(?i)\b(exec|execute|call)\b", s)),
            "has_schema_enumeration": bool(re.search(r"(?i)\b(information_schema|pg_catalog|sqlite_master)\b", s)),
            "has_metadata_enumeration": bool(
                re.search(r"(?i)\b(information_schema|pg_catalog|sqlite_master|v\$version|master\.dbo\.sysdatabases|sys\.databases)\b", s)
            ),
            "has_file_exfil_ops": bool(re.search(r"(?i)\b(load_file|into\s+outfile|into\s+dumpfile)\b", s)),
            "has_user_management_ddl": bool(re.search(r"(?i)\b(create|alter|drop)\s+user\b", s)),
            "has_placeholder": bool(re.search(r"(%s|\?|:\w+|\$\d+)", s)),
            "literal_where_without_placeholder": False,
            "ast_parse_ok": False,
        }
        features["literal_where_without_placeholder"] = bool(
            re.search(r"(?i)\bwhere\b.{0,180}(['\"][^'\"]+['\"]|\b\d+\b)", s)
            and not bool(features["has_placeholder"])
        )

        # Lightweight structural parse when sqlglot is available.
        try:
            import sqlglot  # type: ignore

            parsed = sqlglot.parse(s, read=None, error_level="ignore")
            features["ast_parse_ok"] = bool(parsed)
            if parsed:
                node_types = [type(node).__name__ for node in parsed[:6]]
                features["ast_root_nodes"] = node_types
        except Exception:
            # Keep regex features only when parser is unavailable/fails.
            pass

        # Normalize overly broad keyword checks with space boundaries
        if any(k in s_upper for k in [" DROP ", " ALTER ", " CREATE ", " TRUNCATE ", " RENAME "]):
            features["has_ddl"] = True
        if any(k in s_upper for k in [" EXEC ", " EXECUTE ", " CALL "]):
            features["has_exec"] = True
        if " UNION " in s_upper:
            features["has_union"] = True
        if any(fn in s_upper for fn in [" SLEEP(", " PG_SLEEP(", " BENCHMARK(", " WAITFOR DELAY "]):
            features["has_time_function"] = True
        return features

    def _ast_semantics(self, sql: str) -> List[str]:
        features = self._extract_sql_ast_features(sql)
        hits: List[str] = []
        if bool(features.get("has_ddl")):
            hits.append("ddl_statement_ast")
        if bool(features.get("has_exec")):
            hits.append("exec_statement_ast")
        if bool(features.get("has_union")):
            hits.append("union_ast")
        if bool(features.get("has_time_function")):
            hits.append("time_fn_ast")
        return hits

    def _nlp_malicious_probability(self, nlp_result: Optional[QueryValidationResult]) -> float:
        if not nlp_result or nlp_result.classification_score is None:
            return 0.0
        score = max(0.0, min(1.0, float(nlp_result.classification_score)))
        label = str(nlp_result.classification_label or "").lower()
        if "malicious" in label:
            return score
        if "suspicious" in label:
            return max(score, 0.60)
        if "benign" in label or "safe" in label:
            return max(0.0, 1.0 - score)
        return score

    def _calibrated_signal_score(
        self,
        anomaly_result: Optional[AnomalyDetectionResult],
        nlp_result: Optional[QueryValidationResult],
        heuristics_result: Optional[SQLHeuristicsResult],
        ast_features: Optional[Dict[str, Any]],
    ) -> Tuple[float, Dict[str, float]]:
        heur_score = float((heuristics_result.heuristic_score if heuristics_result else 0.0) or 0.0)
        heur_score = max(0.0, min(1.0, heur_score))
        nlp_prob = self._nlp_malicious_probability(nlp_result)
        anomaly_prob = 0.0
        if anomaly_result and anomaly_result.is_anomalous:
            # Model score sign can vary by implementation; keep robust and monotonic.
            anomaly_prob = 0.75

        ast = ast_features or {}
        ast_points = 0.0
        ast_points += 0.35 if bool(ast.get("has_stacked_statements")) else 0.0
        ast_points += 0.30 if bool(ast.get("has_union")) else 0.0
        ast_points += 0.30 if bool(ast.get("has_ddl")) else 0.0
        ast_points += 0.25 if bool(ast.get("has_exec")) else 0.0
        ast_points += 0.20 if bool(ast.get("has_tautology")) else 0.0
        ast_points += 0.25 if bool(ast.get("has_time_function")) else 0.0
        ast_points += 0.15 if bool(ast.get("has_comment")) else 0.0
        ast_points += 0.20 if bool(ast.get("has_metadata_enumeration")) else 0.0
        ast_points += 0.20 if bool(ast.get("has_file_exfil_ops")) else 0.0
        ast_points += 0.20 if bool(ast.get("has_user_management_ddl")) else 0.0
        ast_points += 0.20 if bool(ast.get("literal_where_without_placeholder")) else 0.0
        ast_score = max(0.0, min(1.0, ast_points))

        # Weighted calibrated fusion for precision v2.
        weighted_heur = 0.45 * heur_score
        weighted_nlp = 0.25 * nlp_prob
        weighted_anomaly = 0.20 * anomaly_prob
        weighted_ast = 0.10 * ast_score
        fused = weighted_heur + weighted_nlp + weighted_anomaly + weighted_ast

        hits = list(heuristics_result.hits or []) if heuristics_result else []
        if any(h in CRITICAL_CODES for h in hits):
            fused = max(fused, 0.93)

        calibrated = round(max(0.0, min(1.0, fused)), 4)
        contributions = {
            "heuristics": round(weighted_heur, 4),
            "nlp": round(weighted_nlp, 4),
            "anomaly": round(weighted_anomaly, 4),
            "ast": round(weighted_ast, 4),
            "calibrated_total": calibrated,
        }
        return calibrated, contributions

    @staticmethod
    def _clamp01(value: Any) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return 0.0

    @classmethod
    def _decision_confidence_from_risk(
        cls,
        *,
        risk_score: Any,
        decision: str,
        uncertainty_score: Any = 0.0,
        ood_score: Any = 0.0,
    ) -> float:
        risk = cls._clamp01(risk_score)
        action = str(decision or "").strip().upper().replace("-", "_")
        safe_decision = action.startswith("ALLOW") or action in {"SAFE", "MONITOR"}
        base_confidence = (1.0 - risk) if safe_decision else risk
        _ = uncertainty_score, ood_score
        return round(cls._clamp01(base_confidence), 4)

    @staticmethod
    def _confidence_label(value: Optional[float]) -> Optional[str]:
        if not isinstance(value, (int, float)):
            return None
        if value >= 0.85:
            return "high"
        if value >= 0.60:
            return "medium"
        return "low"

    def _build_xai_explanation(
        self,
        sql_query: str,
        anomaly_result: Optional[AnomalyDetectionResult],
        nlp_result: Optional[QueryValidationResult],
        heuristics_result: Optional[SQLHeuristicsResult],
        combined_assessment: Optional[CombinedRiskAssessment],
    ) -> XAIExplanation:
        hits = _unique_preserve_order(list(heuristics_result.hits or []) if heuristics_result else [])

        evidence: List[XAIExplanationEvidence] = []
        highlights: List[Dict[str, Any]] = []
        attributions: List[Dict[str, Any]] = []

        for code in hits:
            meta = _HIT_META.get(code, {})
            label = str(meta.get("label") or code)
            severity = str(meta.get("severity") or ("critical" if code in CRITICAL_CODES else "medium"))
            description = meta.get("description")
            impact = meta.get("impact")
            weight = meta.get("weight")
            pattern = meta.get("pattern")

            snippet = None
            start = None
            end = None
            if isinstance(pattern, str) and pattern:
                try:
                    for m in re.finditer(pattern, sql_query, flags=re.DOTALL):
                        s_idx, e_idx = int(m.start()), int(m.end())
                        if e_idx - s_idx > 200:
                            e_idx = s_idx + 200
                        frag = sql_query[s_idx:e_idx]
                        if snippet is None:
                            snippet = frag
                            start = s_idx
                            end = e_idx
                        highlights.append(
                            {"start": s_idx, "end": e_idx, "label": label, "severity": severity}
                        )
                        if len(highlights) >= 40:
                            break
                    # no more than one pattern scan per hit
                except re.error:
                    pass

            evidence.append(
                XAIExplanationEvidence(
                    id=code,
                    label=label,
                    severity=severity,
                    description=description,
                    snippet=snippet,
                    start=start,
                    end=end,
                    score=float(weight) if isinstance(weight, (int, float)) else None,
                    source="heuristics" if code not in {"ddl_statement_ast", "exec_statement_ast", "union_ast", "time_fn_ast"} else "ast",
                    impact=impact,
                )
            )
            if isinstance(weight, (int, float)):
                attributions.append({"feature": code, "weight": float(weight)})

        # Threat category + impact summary
        threat_category = None
        if any(h in hits for h in ["time_sleep", "time_pg_sleep", "time_benchmark", "time_waitfor_delay", "time_fn_ast"]):
            threat_category = "Time-based SQL injection"
        elif any(h in hits for h in ["union_select", "union_ast"]):
            threat_category = "UNION-based SQL injection"
        elif any(h in hits for h in ["file_ops"]):
            threat_category = "File-based SQL exfiltration"
        elif any(h in hits for h in ["blind_subquery_exfiltration"]):
            threat_category = "Blind SQL injection / data inference"
        elif any(h in hits for h in ["stacked_query_dml", "ddl_statement_ast"]):
            threat_category = "Stacked statements / destructive SQL"
        elif any(h in hits for h in ["privileged_account_ddl"]):
            threat_category = "Privilege escalation / account management abuse"
        elif any(h in hits for h in ["information_schema", "pg_catalog", "sqlite_master", "oracle_v_version", "mssql_sysdatabases_enum", "metadata_function_probe"]):
            threat_category = "Database reconnaissance / metadata enumeration"
        elif any(h in hits for h in ["tautology_or_1eq1", "quoted_tautology", "quoted_tautology_simple"]):
            threat_category = "Boolean-based SQL injection"
        elif any(h in hits for h in ["xp_cmdshell"]):
            threat_category = "DB command execution attempt"

        risk_score = None
        if combined_assessment and combined_assessment.calibrated_risk_score is not None:
            risk_score = self._clamp01(combined_assessment.calibrated_risk_score)
        elif nlp_result and nlp_result.classification_score is not None:
            risk_score = self._clamp01(self._nlp_malicious_probability(nlp_result))
        elif heuristics_result and heuristics_result.heuristic_score is not None:
            risk_score = self._clamp01(heuristics_result.heuristic_score)

        decision = combined_assessment.suggested_action if combined_assessment else "ALLOW"
        severity = combined_assessment.overall_risk_level if combined_assessment else "Low"
        impact_summary = None
        if any(h in hits for h in ["xp_cmdshell"]):
            impact_summary = "Potential OS command execution via database features."
        elif threat_category == "Privilege escalation / account management abuse":
            impact_summary = "Potential creation/alteration of privileged DB users."
        elif threat_category == "Stacked statements / destructive SQL":
            impact_summary = "Potential execution of destructive statements (DROP/ALTER/UPDATE)."
        elif threat_category == "File-based SQL exfiltration":
            impact_summary = "Potential local file read/write or out-of-band exfiltration via DB file functions."
        elif threat_category == "Database reconnaissance / metadata enumeration":
            impact_summary = "Potential schema/version reconnaissance to guide exploit staging."
        elif threat_category == "UNION-based SQL injection":
            impact_summary = "Potential data exfiltration by UNIONing sensitive columns."
        elif threat_category == "Time-based SQL injection":
            impact_summary = "Potential data inference via response timing differences."
        elif threat_category == "Blind SQL injection / data inference":
            impact_summary = "Potential character-by-character extraction of sensitive DB metadata."
        elif threat_category == "Boolean-based SQL injection":
            impact_summary = "Potential bypass of filters or authentication checks."

        remediation: List[str] = [
            "Use parameterized queries / prepared statements; do not concatenate untrusted input into SQL strings.",
            "Enforce least-privilege DB accounts (no DROP/ALTER/EXEC for application roles).",
        ]
        if any(h in hits for h in ["stacked_query_dml", "ddl_statement_ast"]):
            remediation.append("Disable multi-statement execution; enforce single-statement queries in the DB driver.")
        if any(h in hits for h in ["union_select", "union_ast"]):
            remediation.append("Avoid dynamic SELECT list construction; use fixed queries, views, or stored procedures.")
        if any(h in hits for h in ["time_sleep", "time_pg_sleep", "time_benchmark", "time_waitfor_delay", "time_fn_ast"]):
            remediation.append("Block/monitor timing functions (SLEEP/pg_sleep/WAITFOR) and investigate repeated delays.")
        if any(h in hits for h in ["blind_subquery_exfiltration", "metadata_function_probe"]):
            remediation.append("Block metadata-exfiltration probes (VERSION/USER/DB functions in nested inference predicates).")
        if any(h in hits for h in ["information_schema", "pg_catalog", "sqlite_master", "oracle_v_version", "mssql_sysdatabases_enum"]):
            remediation.append("Restrict metadata catalog visibility and flag direct catalog enumeration in request-path SQL.")
        if any(h in hits for h in ["file_ops"]):
            remediation.append("Disable LOAD_FILE/OUTFILE capabilities for application roles and block UNC/network-path exfil patterns.")
        if any(h in hits for h in ["privileged_account_ddl"]):
            remediation.append("Disallow CREATE/ALTER/DROP USER in application SQL paths; reserve account DDL for controlled admin workflows.")
        if any(h in hits for h in ["comment_inline", "comment_sequence"]):
            remediation.append("Reject or escape comment delimiters in untrusted input when parameterization is not possible.")

        trace: List[XAIExplanationTraceStep] = []
        if anomaly_result:
            trace.append(
                XAIExplanationTraceStep(
                    stage="anomaly_model",
                    summary=f"{anomaly_result.prediction_label} (score={anomaly_result.score:.4f})",
                    details={"is_anomalous": anomaly_result.is_anomalous, "score": anomaly_result.score},
                )
            )
        if nlp_result:
            trace.append(
                XAIExplanationTraceStep(
                    stage="nlp_classifier",
                    summary=f"{nlp_result.classification_label} (p={nlp_result.classification_score})",
                    details={
                        "label": nlp_result.classification_label,
                        "confidence": nlp_result.classification_score,
                    },
                )
            )
        if heuristics_result:
            trace.append(
                XAIExplanationTraceStep(
                    stage="heuristics",
                    summary=f"suspected={heuristics_result.suspected} (score={heuristics_result.heuristic_score})",
                    details={
                        "hits": list(heuristics_result.hits or []),
                        "heuristic_score": heuristics_result.heuristic_score,
                        "critical_codes": sorted(list(CRITICAL_CODES))[:20],
                        "high_threshold": HEURISTICS_HIGH_THRESHOLD,
                    },
                )
            )
        if combined_assessment:
            trace.append(
                XAIExplanationTraceStep(
                    stage="aggregator",
                    summary=f"{combined_assessment.overall_risk_level} -> {combined_assessment.suggested_action}",
                    details={
                        "overall_risk_level": combined_assessment.overall_risk_level,
                        "suggested_action": combined_assessment.suggested_action,
                        "reasoning": list(combined_assessment.reasoning or []),
                        "calibrated_risk_score": combined_assessment.calibrated_risk_score,
                        "signal_contributions": combined_assessment.signal_contributions,
                        "ast_features": combined_assessment.ast_features,
                    },
                )
            )

        # Fidelity is a lightweight agreement score between main signal families and final decision.
        signal_total = 0
        signal_support = 0
        decision_is_restrictive = str(decision).upper() != "ALLOW"
        if anomaly_result is not None:
            signal_total += 1
            if bool(anomaly_result.is_anomalous) == decision_is_restrictive:
                signal_support += 1
        if nlp_result is not None:
            signal_total += 1
            nlp_malicious = "malicious" in str(nlp_result.classification_label or "").lower()
            if bool(nlp_malicious) == decision_is_restrictive:
                signal_support += 1
        if heuristics_result is not None:
            signal_total += 1
            if bool(heuristics_result.suspected) == decision_is_restrictive:
                signal_support += 1
        fidelity_score = round(signal_support / signal_total, 4) if signal_total > 0 else None

        # OOD (out-of-distribution) approximation for SQL payloads.
        ood_raw = 0.0
        q_len = len(sql_query or "")
        if q_len > 4000:
            ood_raw += 0.35
        elif q_len > 2000:
            ood_raw += 0.20
        if q_len > 0:
            non_ascii = sum(1 for ch in sql_query if ord(ch) > 127)
            non_ascii_ratio = non_ascii / q_len
            if non_ascii_ratio >= 0.15:
                ood_raw += 0.35
            elif non_ascii_ratio >= 0.05:
                ood_raw += 0.20
        if anomaly_result and anomaly_result.is_anomalous and not hits:
            low_nlp_conf = (nlp_result.classification_score if nlp_result else 0.0) or 0.0
            if low_nlp_conf < 0.55:
                ood_raw += 0.35
        ood_score = round(max(0.0, min(1.0, ood_raw)), 4)
        abstain_reason = None
        if ood_score >= 0.70 and str(severity).lower() not in {"critical"}:
            abstain_reason = "HIGH_OOD_LOW_SIGNAL_CONSENSUS"
            remediation.append("Escalate to manual analyst review due to out-of-distribution query characteristics.")

        # calibrated_risk_score remains SQL threat risk. Decision confidence is
        # confidence in the selected action, so allowed queries invert low risk.
        decision_confidence = None
        confidence_label = None
        uncertainty_score = None
        uncertainty_components = None
        if isinstance(risk_score, (int, float)):
            decision_confidence = self._decision_confidence_from_risk(
                risk_score=risk_score,
                decision=decision,
                ood_score=ood_score,
            )
            confidence_label = self._confidence_label(decision_confidence)
            threshold_distance = min(
                abs(float(risk_score) - threshold)
                for threshold in (
                    float(SQL_PRECISION_MEDIUM_THRESHOLD),
                    float(SQL_PRECISION_HIGH_THRESHOLD),
                    float(SQL_PRECISION_BLOCK_THRESHOLD),
                )
            )
            threshold_margin_uncertainty = 1.0 - min(threshold_distance / 0.20, 1.0)
            active_component_scores: List[float] = []
            if heuristics_result and isinstance(heuristics_result.heuristic_score, (int, float)):
                active_component_scores.append(self._clamp01(heuristics_result.heuristic_score))
            if nlp_result and isinstance(nlp_result.classification_score, (int, float)):
                active_component_scores.append(self._clamp01(self._nlp_malicious_probability(nlp_result)))
            if anomaly_result is not None:
                active_component_scores.append(0.75 if anomaly_result.is_anomalous else 0.0)
            signal_disagreement_uncertainty = (
                max(active_component_scores) - min(active_component_scores)
                if len(active_component_scores) >= 2
                else 0.0
            )
            missing_component_count = 0
            if anomaly_result is None:
                missing_component_count += 1
            if nlp_result is None:
                missing_component_count += 1
            if heuristics_result is None:
                missing_component_count += 1
            missing_component_uncertainty = min(0.30, 0.10 * missing_component_count)
            low_fidelity_uncertainty = (
                max(0.0, min(1.0, 1.0 - float(fidelity_score)))
                if isinstance(fidelity_score, (int, float))
                else 0.0
            )
            uncertainty_components = {
                "threshold_margin_uncertainty": round(max(0.0, min(1.0, threshold_margin_uncertainty)), 4),
                "signal_disagreement_uncertainty": round(max(0.0, min(1.0, signal_disagreement_uncertainty)), 4),
                "missing_component_uncertainty": round(missing_component_uncertainty, 4),
                "ood_score": round(ood_score, 4),
                "low_fidelity_uncertainty": round(low_fidelity_uncertainty, 4),
            }
            uncertainty_score = round(max(uncertainty_components.values()), 4)

        thresholds = {
            "heuristics_high": float(HEURISTICS_HIGH_THRESHOLD),
            "risk_medium": float(SQL_PRECISION_MEDIUM_THRESHOLD),
            "risk_high": float(SQL_PRECISION_HIGH_THRESHOLD),
            "risk_block": float(SQL_PRECISION_BLOCK_THRESHOLD),
        }
        model_parts: List[str] = []
        if self._anomaly_model_instance is not None:
            model_parts.append(self._anomaly_model_instance.__class__.__name__)
        if self._query_validation_pipeline is not None:
            model_parts.append(self._query_validation_pipeline.__class__.__name__)
        model_version = " + ".join(model_parts) if model_parts else None
        ruleset_version = f"sql_heuristics_v2:{len(_HIT_META)}_rules"
        policy_version = "sql_policy_precision_v2"
        caveats: List[str] = []
        if not self.are_models_loaded():
            caveats.append("One or more SQL models were unavailable; fallback signals may reduce confidence quality.")
        if signal_total <= 1:
            caveats.append("Decision relied on limited signal families.")
        if not hits and decision_is_restrictive:
            caveats.append("Restrictive decision triggered without explicit heuristic matches.")

        counterfactual = (
            "If the query were parameterized (placeholders) and contained no UNION/stacked statements/comments/timing "
            "functions, the overall risk would likely drop to Low."
        )

        return XAIExplanation(
            decision=decision,
            severity=severity,
            threat_category=threat_category,
            risk_score=risk_score,
            decision_confidence=decision_confidence,
            confidence=decision_confidence,
            confidence_label=confidence_label,
            uncertainty_score=uncertainty_score,
            uncertainty_components=uncertainty_components,
            fidelity_score=fidelity_score,
            ood_score=ood_score,
            abstain_reason=abstain_reason,
            impact=impact_summary,
            evidence=evidence or None,
            highlights=_merge_highlights(highlights) or None,
            model_attributions=attributions or None,
            decision_trace=trace or None,
            remediation=remediation or None,
            counterfactual=counterfactual,
            model_version=model_version,
            ruleset_version=ruleset_version,
            policy_version=policy_version,
            thresholds=thresholds,
            provenance={
                "pipeline": "sql_query_analysis_v2",
                "signal_families": signal_total,
                "supporting_signals": signal_support,
                "uncertainty_components": uncertainty_components,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            },
            caveats=caveats or None,
        )

    @staticmethod
    def _is_positive_label(label: str) -> bool:
        normalized = str(label or "").strip().lower()
        return normalized in {"malicious", "attack", "sqli", "positive", "true", "1", "blocked", "suspicious"}

    def evaluate_precision_dataset(
        self,
        samples: List[Dict[str, Any]],
        include_predictions: bool = False,
        max_examples: int = 20,
    ) -> Dict[str, Any]:
        if not samples:
            raise ValueError("At least one sample is required for evaluation.")

        tp = fp = tn = fn = 0
        predictions: List[Dict[str, Any]] = []
        false_positives: List[Dict[str, Any]] = []
        false_negatives: List[Dict[str, Any]] = []

        for idx, sample in enumerate(samples):
            query = str(sample.get("query") or "").strip()
            expected_label = str(sample.get("expected_label") or "").strip()
            if not query:
                continue

            anomaly_result: Optional[AnomalyDetectionResult] = None
            nlp_result: Optional[QueryValidationResult] = None
            heuristics_result = self._heuristics_scan(query)
            ast_features = self._extract_sql_ast_features(query)
            ast_hits = self._ast_semantics(query)
            if ast_hits:
                heuristics_result.hits = _unique_preserve_order(list(heuristics_result.hits or []) + ast_hits)

            # Use available models when loaded; fall back gracefully otherwise.
            if self._anomaly_model_instance:
                try:
                    pred, score = self._anomaly_model_instance.predict_and_score([query])[0]
                    anomaly_result = AnomalyDetectionResult(
                        is_anomalous=(pred == -1),
                        score=score,
                        prediction_label="Anomalous" if pred == -1 else "Normal",
                    )
                except Exception:
                    anomaly_result = None
            if self._query_validation_pipeline:
                try:
                    q_df = pd.DataFrame([self._preprocess_query_for_nlp(query)], columns=["query"])
                    pred_num = self._query_validation_pipeline.predict(q_df["query"])[0]
                    probs = self._query_validation_pipeline.predict_proba(q_df["query"])[0]
                    label = "Malicious Signature" if pred_num == 1 else "Benign"
                    nlp_result = QueryValidationResult(
                        classification_label=label,
                        classification_score=float(probs[pred_num]),
                    )
                except Exception:
                    nlp_result = None

            calibrated_risk_score, signal_contributions = self._calibrated_signal_score(
                anomaly_result=anomaly_result,
                nlp_result=nlp_result,
                heuristics_result=heuristics_result,
                ast_features=ast_features,
            )
            combined = self._combine_assessments(
                anomaly_result=anomaly_result,
                nlp_result=nlp_result,
                heuristics=heuristics_result,
                calibrated_risk_score=calibrated_risk_score,
                signal_contributions=signal_contributions,
                ast_features=ast_features,
            )

            predicted_positive = combined.overall_risk_level in {"High", "Critical"} or combined.suggested_action.upper().startswith("BLOCK")
            expected_positive = self._is_positive_label(expected_label)

            if predicted_positive and expected_positive:
                tp += 1
            elif predicted_positive and not expected_positive:
                fp += 1
            elif not predicted_positive and not expected_positive:
                tn += 1
            else:
                fn += 1

            row = {
                "index": idx,
                "query_preview": query[:180],
                "expected_label": expected_label,
                "predicted_label": "malicious" if predicted_positive else "benign",
                "risk_level": combined.overall_risk_level,
                "suggested_action": combined.suggested_action,
                "calibrated_risk_score": combined.calibrated_risk_score,
                "heuristic_hits": list(heuristics_result.hits or []),
            }
            if predicted_positive and not expected_positive and len(false_positives) < max_examples:
                false_positives.append(row)
            if (not predicted_positive) and expected_positive and len(false_negatives) < max_examples:
                false_negatives.append(row)
            if include_predictions:
                predictions.append(row)

        total = tp + fp + tn + fn

        def _safe_div(a: float, b: float) -> float:
            return float(a / b) if b else 0.0

        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
        accuracy = _safe_div(tp + tn, total)

        payload: Dict[str, Any] = {
            "sample_count": total,
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "thresholds": {
                "medium": SQL_PRECISION_MEDIUM_THRESHOLD,
                "high": SQL_PRECISION_HIGH_THRESHOLD,
                "block": SQL_PRECISION_BLOCK_THRESHOLD,
            },
            "false_positives": false_positives,
            "false_negatives": false_negatives,
        }
        if include_predictions:
            payload["predictions"] = predictions
        return payload

    def analyze_query(self, db: Session, sql_query: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        effective_tenant_id = str(tenant_id or "").strip() or DEFAULT_TENANT_ID
        analysis_timestamp = datetime.now(timezone.utc)
        analysis_id = f"sql-{uuid.uuid4()}"
        anomaly_result, nlp_result = None, None
        heuristics_result: Optional[SQLHeuristicsResult] = None

        if self._anomaly_model_instance:
            pred, score = self._anomaly_model_instance.predict_and_score([sql_query])[0]
            anomaly_result = AnomalyDetectionResult(is_anomalous=(pred == -1), score=score, prediction_label="Anomalous" if pred == -1 else "Normal")

        if self._query_validation_pipeline:
            query_as_df = pd.DataFrame([self._preprocess_query_for_nlp(sql_query)], columns=['query'])
            pred_num = self._query_validation_pipeline.predict(query_as_df['query'])[0]
            probs = self._query_validation_pipeline.predict_proba(query_as_df['query'])[0]
            label = "Malicious Signature" if pred_num == 1 else "Benign"
            nlp_result = QueryValidationResult(classification_label=label, classification_score=float(probs[pred_num]))

        # Run heuristics + AST irrespective of model availability
        try:
            heuristics_result = self._heuristics_scan(sql_query)
        except Exception as e:
            logger.error(f"Heuristics scan failed: {e}")
            heuristics_result = SQLHeuristicsResult(suspected=False, hits=[], heuristic_score=0.0)
        ast_features: Dict[str, Any] = {}
        try:
            ast_hits = self._ast_semantics(sql_query)
            ast_features = self._extract_sql_ast_features(sql_query)
            if ast_hits:
                # Merge AST hits into heuristics
                heuristics_result.hits.extend([h for h in ast_hits if h not in (heuristics_result.hits or [])])
        except Exception:
            ast_features = {}

        calibrated_risk_score, signal_contributions = self._calibrated_signal_score(
            anomaly_result=anomaly_result,
            nlp_result=nlp_result,
            heuristics_result=heuristics_result,
            ast_features=ast_features,
        )

        combined_assessment = self._combine_assessments(
            anomaly_result,
            nlp_result,
            heuristics_result,
            calibrated_risk_score=calibrated_risk_score,
            signal_contributions=signal_contributions,
            ast_features=ast_features,
        )
        explanation = self._build_xai_explanation(
            sql_query=sql_query,
            anomaly_result=anomaly_result,
            nlp_result=nlp_result,
            heuristics_result=heuristics_result,
            combined_assessment=combined_assessment,
        )
        ai_reliability = None
        try:
            ai_reliability = assess_ai_reliability(
                domain="sql",
                risk_score=combined_assessment.calibrated_risk_score if combined_assessment else None,
                decision_confidence=explanation.decision_confidence if explanation else None,
                uncertainty_score=explanation.uncertainty_score if explanation else 0.0,
                ood_score=explanation.ood_score if explanation else 0.0,
                fidelity_score=explanation.fidelity_score if explanation else 1.0,
                score_breakdown={
                    "signal_contributions": combined_assessment.signal_contributions if combined_assessment else None,
                    "heuristic_score": heuristics_result.heuristic_score if heuristics_result else None,
                    "nlp_score": nlp_result.classification_score if nlp_result else None,
                    "anomaly_score": 0.75 if (anomaly_result and anomaly_result.is_anomalous) else 0.0,
                    "ast_features": ast_features,
                },
                final_action=combined_assessment.suggested_action if combined_assessment else None,
                severity=combined_assessment.overall_risk_level if combined_assessment else None,
                rule_hits=list(heuristics_result.hits or []) if heuristics_result else [],
                model_version=explanation.model_version if explanation else None,
                ruleset_version=explanation.ruleset_version if explanation else None,
            )
            if explanation is not None:
                explanation.ai_reliability = ai_reliability
        except Exception as e_rel:
            logger.error(f"AI reliability assessment failed for SQL analysis: {e_rel}", exc_info=True)
        if explanation is not None:
            explanation = complete_explainability_contract(
                explanation,
                domain="sql",
                input_summary=f"query_length={len(sql_query or '')}",
                limitations=[
                    "SQL risk is derived from calibrated heuristic/model/AST fusion and enforcement policy, not benchmark precision.",
                    "Review may be required for threshold-near, OOD, low-fidelity, or conflicting SQL signals.",
                ],
            ) or explanation

        defender_action_summary: Optional[Dict[str, Any]] = None
        defender_actions: Optional[List[str]] = None
        try:
            ir_service = self._incident_response_service_instance or IncidentResponseService.get_instance()
            defender_action_summary = ir_service.execute_actions(
                db=db,
                domain="sql",
                entity_id=analysis_id,
                suggested_action=combined_assessment.suggested_action if combined_assessment else "ALLOW",
                risk_level=combined_assessment.overall_risk_level if combined_assessment else "Low",
                details={
                    "message": (
                        f"SQL query analyzed with decision "
                        f"{combined_assessment.suggested_action if combined_assessment else 'ALLOW'}."
                    )
                },
                create_alert_if_missing=False,
            )
            defender_actions = list(defender_action_summary.get("actions") or [])
        except Exception as e_ir:
            logger.error(f"Incident response action planning failed: {e_ir}", exc_info=True)

        # Persist analysis log for trends and dashboard stats
        try:
            from backend.core.models import SQLAnalysisLog as _SQLModel
            risk_level = str((combined_assessment.overall_risk_level if combined_assessment else "Low") or "Low")
            suggested_action = str((combined_assessment.suggested_action if combined_assessment else "ALLOW") or "ALLOW")
            validation_label = str((nlp_result.classification_label if nlp_result else "") or "").lower()
            blocked = risk_level.lower() in {"high", "critical"} or suggested_action.upper().startswith("BLOCK")
            suspicious_signal = (
                (risk_level.lower() == "medium")
                or bool(anomaly_result and anomaly_result.is_anomalous)
                or suggested_action.upper().startswith("WARN")
                or suggested_action.upper().startswith("FLAG")
                or ("suspicious" in validation_label)
                or ("malicious" in validation_label)
            )
            category = "blocked" if blocked else ("suspicious" if suspicious_signal else "safe")
            model = _SQLModel(
                id=analysis_id,
                tenant_id=effective_tenant_id,
                timestamp=analysis_timestamp,
                query_received=sql_query,
                risk_level=risk_level,
                suggested_action=suggested_action,
                category=category,
                is_malicious=bool(blocked),
            )
            model.anomaly_detection_result = anomaly_result.model_dump() if anomaly_result else None
            model.query_validation_result = nlp_result.model_dump() if nlp_result else None
            model.combined_assessment = combined_assessment.model_dump() if combined_assessment else None
            model.errors = None
            db.add(model)
            db.commit()
        except Exception as e_persist:
            logger.error(f"Failed to persist SQL analysis log: {e_persist}", exc_info=True)

        if combined_assessment.overall_risk_level in ["High", "Critical"] and self._alerts_service_instance:
            alert_to_create = AlertSchema(
                id=f"alert-{analysis_id}", timestamp=analysis_timestamp, severity=combined_assessment.overall_risk_level,
                title=f"SQL Alert: {combined_assessment.overall_risk_level} Risk Query", message=f"Query: '{sql_query[:200]}...'",
                query=sql_query, acknowledged=False,
                tags=[
                    *(heuristics_result.hits if heuristics_result and heuristics_result.hits else []),
                    f"decision:{combined_assessment.suggested_action}",
                    f"anomaly:{'yes' if (anomaly_result and anomaly_result.is_anomalous) else 'no'}",
                ]
            )
            created_alert_model = self._alerts_service_instance.create_alert(
                db=db,
                alert_data=alert_to_create,
                tenant_id=effective_tenant_id,
            )
            try:
                alert_details = AlertSchema.model_validate(created_alert_model)
                payload = {
                    "type": "NEW_ALERT_DETAILS",
                    "tenant_id": effective_tenant_id,
                    "alert": alert_details.model_dump(mode='json'),
                }
                manager.broadcast_nowait(json.dumps(payload))
            except Exception as e_ws:
                logger.error(f"Failed to broadcast WebSocket message: {e_ws}", exc_info=True)

        # Broadcast a lightweight live event for the dashboard feed
        try:
            live_event = {
                "id": analysis_id,
                "type": "query",
                "message": f"Analyzed SQL query ({'malicious' if combined_assessment.overall_risk_level in ['High','Critical'] else 'benign'})",
                "timestamp": analysis_timestamp.isoformat(),
                "isMalicious": combined_assessment.overall_risk_level in ["High", "Critical"],
                "tenant_id": effective_tenant_id,
            }
            manager.broadcast_nowait(json.dumps(live_event))
        except Exception:
            pass

        return {
            "query_received": sql_query,
            "analysis_timestamp": analysis_timestamp,
            "analysis_id": analysis_id,
            "anomaly_detection": anomaly_result,
            "query_validation": nlp_result,
            "heuristics_detection": heuristics_result,
            "combined_assessment": combined_assessment,
            "explanation": explanation,
            "ai_reliability": ai_reliability,
            "defender_actions": defender_actions,
            "defender_action_summary": defender_action_summary,
        }


