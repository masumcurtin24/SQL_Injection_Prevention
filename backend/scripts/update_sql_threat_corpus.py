"""
Build a richer SQL threat corpus from vetted online SQLi sources + analyst feedback.

Outputs:
- backend/data/corpus/sql/raw/sql_online_weaklabels.csv
- backend/data/corpus/sql/raw/sql_online_weaklabels_report.json

Usage:
  python -m backend.scripts.update_sql_threat_corpus
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote
from urllib.request import Request, urlopen

from backend.core.database import SessionLocal, create_db_tables, ensure_runtime_schema_compatibility
from backend.core.models import DefenderFeedback


SQL_FEEDS: List[Dict[str, str]] = [
    {
        "name": "payloadsallthethings_sqli_readme",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md",
        "format": "markdown",
    },
    {
        "name": "seclists_sqli_auth_bypass",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
        "format": "line_list",
    },
    {
        "name": "seclists_generic_blind",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt",
        "format": "line_list",
    },
    {
        "name": "seclists_sqli_polyglots",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
        "format": "line_list",
    },
    {
        "name": "seclists_mssql",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt",
        "format": "line_list",
    },
    {
        "name": "seclists_oracle",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Oracle.fuzzdb.txt",
        "format": "line_list",
    },
]

REFERENCE_SOURCES: List[str] = [
    "https://portswigger.net/web-security/sql-injection/cheat-sheet",
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    "https://github.com/sqlmapproject/sqlmap/wiki/usage",
]

REQUIRED_SCENARIOS: List[str] = [
    "benign_enterprise_query",
    "orm_generated_query",
    "cross_dialect_query",
    "obfuscated_sqli",
    "stored_procedure_abuse",
    "service_context_trace",
]


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _download_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": "DefenderAI-SQLCorpusBuilder/1.0"})
    with urlopen(req, timeout=25) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def _iter_lines(text: str) -> Iterable[str]:
    for line in (text or "").splitlines():
        yield line


def _normalize_candidate(raw: str) -> str:
    text = unicodedata.normalize("NFKC", str(raw or ""))
    text = text.replace("\x00", " ")
    text = unquote(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"', "`"}:
        text = text[1:-1].strip()
    if len(text) > 600:
        text = text[:600]
    return text


def _looks_like_sqli_payload(raw: str) -> bool:
    s = str(raw or "").strip().lower()
    if len(s) < 4:
        return False
    markers = [
        " or ",
        " union ",
        " union select",
        "information_schema",
        "xp_cmdshell",
        "xp_dirtree",
        "xp_reg",
        "sp_oacreate",
        "sleep(",
        "pg_sleep",
        "benchmark(",
        "waitfor delay",
        "substring(",
        "substr(",
        "ascii(",
        "ord(",
        "dbms_pipe",
        "utl_http",
        "utl_inaddr",
        "load_file(",
        "into outfile",
        "into dumpfile",
        "copy ",
        "attach database",
        "sqlite_master",
        "pg_catalog",
        "@@version",
        "current_database(",
        "database(",
        "--",
        "/*",
        "#",
    ]
    if any(m in s for m in markers):
        return True
    if re.search(r"(?i)(?:'|\")\s*or\s*(?:'?\d+'?\s*=\s*'?\d+'?)", s):
        return True
    if re.search(r"(?i)\b(exec|execute|call)\b", s):
        return True
    return False


def _extract_markdown_sql_candidates(markdown: str) -> List[str]:
    out: List[str] = []

    for block in re.findall(r"```(?:sql)?\s*(.*?)```", markdown or "", flags=re.IGNORECASE | re.DOTALL):
        for line in _iter_lines(block):
            cleaned = _normalize_candidate(line)
            if cleaned and _looks_like_sqli_payload(cleaned):
                out.append(cleaned)

    for inline in re.findall(r"`([^`\n]{4,500})`", markdown or ""):
        cleaned = _normalize_candidate(inline)
        if cleaned and _looks_like_sqli_payload(cleaned):
            out.append(cleaned)

    return out


def _extract_line_list_candidates(text: str) -> List[str]:
    out: List[str] = []
    for raw in _iter_lines(text):
        line = (raw or "").strip()
        if not line or line.startswith("#"):
            continue
        cleaned = _normalize_candidate(line)
        if not cleaned:
            continue
        if _looks_like_sqli_payload(cleaned):
            out.append(cleaned)
    return out


def _collect_online_payloads(max_payloads: int = 1800) -> Tuple[List[Dict[str, str]], Dict[str, int], List[str]]:
    payloads: List[Dict[str, str]] = []
    source_counts: Dict[str, int] = {}
    errors: List[str] = []
    seen: Set[str] = set()

    for feed in SQL_FEEDS:
        name = str(feed.get("name") or "unknown")
        url = str(feed.get("url") or "").strip()
        fmt = str(feed.get("format") or "line_list").strip().lower()
        if not url:
            continue
        try:
            text = _download_text(url)
            if fmt == "markdown":
                candidates = _extract_markdown_sql_candidates(text)
            else:
                candidates = _extract_line_list_candidates(text)
            added = 0
            for candidate in candidates:
                normalized = _normalize_candidate(candidate)
                if not normalized:
                    continue
                key = normalized.lower()
                if key in seen:
                    continue
                seen.add(key)
                payloads.append({"payload": normalized, "source": name, "url": url})
                added += 1
                if len(payloads) >= max(1, int(max_payloads)):
                    source_counts[name] = source_counts.get(name, 0) + added
                    return payloads, source_counts, errors
            source_counts[name] = source_counts.get(name, 0) + added
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            continue
    return payloads, source_counts, errors


def _is_positive_sql_label(value: Optional[str]) -> bool:
    token = str(value or "").strip().lower()
    return token in {"malicious", "sqli", "attack", "blocked", "suspicious", "high", "critical"}


def _is_negative_sql_label(value: Optional[str]) -> bool:
    token = str(value or "").strip().lower()
    return token in {"benign", "safe", "allow", "normal", "clean", "low"}


def _load_sql_feedback_samples(limit: int = 500) -> Tuple[List[str], List[str], int, int]:
    malicious: List[str] = []
    benign: List[str] = []
    false_negative_count = 0
    false_positive_count = 0

    try:
        create_db_tables()
        ensure_runtime_schema_compatibility()
        with SessionLocal() as db:
            rows = (
                db.query(DefenderFeedback)
                .filter(DefenderFeedback.domain == "sql", DefenderFeedback.source == "human")
                .order_by(DefenderFeedback.timestamp.desc())
                .limit(max(1, int(limit) * 4))
                .all()
            )
            for row in rows:
                payload = row.sample_payload or {}
                query = _normalize_candidate(str(payload.get("query") or ""))
                if not query:
                    continue

                true_pos = _is_positive_sql_label(row.true_label)
                true_neg = _is_negative_sql_label(row.true_label)
                pred_pos = _is_positive_sql_label(row.predicted_label)
                pred_neg = _is_negative_sql_label(row.predicted_label)

                if true_pos:
                    malicious.append(query)
                elif true_neg:
                    benign.append(query)
                else:
                    continue

                if true_pos and pred_neg:
                    false_negative_count += 1
                if true_neg and pred_pos:
                    false_positive_count += 1

                if len(malicious) + len(benign) >= max(1, int(limit)):
                    break
    except Exception:
        return [], [], 0, 0
    return malicious, benign, false_negative_count, false_positive_count


def _infer_scenario_dialect_service(payload: str) -> Tuple[str, str, str]:
    s = str(payload or "").lower()

    if any(x in s for x in ["xp_cmdshell", "xp_dirtree", "xp_reg", "sp_oacreate", "waitfor delay"]):
        return "stored_procedure_abuse", "sqlserver", "legacy-admin-console"
    if any(x in s for x in ["dbms_pipe", "utl_http", "utl_inaddr", "rawtohex", "lnnvl"]):
        return "stored_procedure_abuse", "oracle", "legacy-admin-console"
    if "copy " in s and " to program " in s:
        return "stored_procedure_abuse", "postgresql", "legacy-admin-console"
    if "exec " in s or s.startswith("exec") or s.startswith("execute "):
        return "stored_procedure_abuse", "sqlserver", "legacy-admin-console"
    if "call " in s or s.startswith("call "):
        return "stored_procedure_abuse", "mysql", "legacy-admin-console"

    if any(
        x in s
        for x in [
            "union select",
            "information_schema",
            "sqlite_master",
            "pg_catalog",
            "@@version",
            "version(",
            "current_database(",
            "database(",
            "substring(",
            "substr(",
            "ascii(",
            "ord(",
            "sleep(",
            "pg_sleep",
            "benchmark(",
            "load_file(",
            "into outfile",
            "into dumpfile",
            "attach database",
        ]
    ):
        if any(x in s for x in ["pg_sleep", "pg_catalog", "current_database(", "::int", "::integer"]):
            return "service_context_trace", "postgresql", "internet-facing-api"
        if any(x in s for x in ["sqlite_master", "attach database", "last_insert_rowid"]):
            return "service_context_trace", "sqlite", "internet-facing-api"
        if any(x in s for x in ["rawtohex", "dbms_pipe", "utl_http", "utl_inaddr"]):
            return "service_context_trace", "oracle", "internet-facing-api"
        return "service_context_trace", "mysql", "internet-facing-api"

    if any(x in s for x in ["--", "/*", "#", "%2f", "%2a", "%27", "%22", "/*!"]):
        return "obfuscated_sqli", "mysql", "public-web-api"
    return "obfuscated_sqli", "mysql", "public-web-api"


def _generate_benign_rows(max_rows: int, seed: int = 42) -> List[Dict[str, str]]:
    rng = random.Random(int(seed))
    tables = ["orders", "invoices", "customers", "inventory", "payments", "audit_logs", "subscriptions", "events"]
    statuses = ["active", "pending", "shipped", "paid", "queued", "closed"]
    services = ["billing-api", "orders-api", "reporting-api", "identity-api", "tenant-api", "analytics-api"]

    rows: List[Dict[str, str]] = []
    for idx in range(max(1, int(max_rows))):
        scenario_idx = idx % 3
        table = tables[idx % len(tables)]
        service = services[idx % len(services)]
        status = statuses[idx % len(statuses)]
        amount = (idx % 500) + 10

        if scenario_idx == 0:
            tenant_id = 1000 + idx
            min_amount = amount + (idx % 90)
            limit = 25 + (idx % 200)
            dialect = ["postgresql", "mysql", "sqlserver"][idx % 3]
            rows.append(
                {
                    "label": "benign",
                    "scenario": "benign_enterprise_query",
                    "query": (
                        f"SELECT id, tenant_id, status, total_amount FROM {table} "
                        f"WHERE tenant_id = {tenant_id} AND status = '{status}' "
                        f"AND total_amount > {min_amount} ORDER BY id DESC LIMIT {limit}"
                    ),
                    "dialect": dialect,
                    "orm_name": "none",
                    "service_context": service,
                    "notes": "enterprise benign workload",
                }
            )
        elif scenario_idx == 1:
            orm = ["sqlalchemy", "django_orm", "entity_framework", "sequelize"][idx % 4]
            if orm == "entity_framework":
                query = (
                    "SELECT [o].[Id], [o].[Status] FROM [Orders] AS [o] "
                    f"WHERE [o].[TenantId] = @__tenant_{idx % 97} AND [o].[Amount] > @__amount_{idx % 89}"
                )
                dialect = "sqlserver"
            elif orm == "sequelize":
                query = (
                    f'SELECT "id", "status" FROM "{table}" '
                    f'WHERE "tenant_id" = {1000 + idx} AND "status" = \'{status}\''
                )
                dialect = "postgresql"
            elif orm == "django_orm":
                query = (
                    f'SELECT "{table}"."id", "{table}"."status" FROM "{table}" '
                    f'WHERE "{table}"."tenant_id" = {2000 + idx} AND "{table}"."status" = \'{status}\''
                )
                dialect = "postgresql"
            else:
                query = (
                    f"SELECT {table}.id AS {table}_id, {table}.status AS {table}_status "
                    f"FROM {table} WHERE {table}.tenant_id = {3000 + idx} AND {table}.status = '{status}'"
                )
                dialect = "mysql"
            rows.append(
                {
                    "label": "benign",
                    "scenario": "orm_generated_query",
                    "query": query,
                    "dialect": dialect,
                    "orm_name": orm,
                    "service_context": service,
                    "notes": "ORM query",
                }
            )
        else:
            cross_variant = idx % 4
            if cross_variant == 0:
                query = (
                    f"SELECT DATE_TRUNC('day', NOW()) AS day_window, COUNT(*) "
                    f"FROM {table} WHERE tenant_id = {idx % 500} AND status = '{status}'"
                )
                dialect = "postgresql"
            elif cross_variant == 1:
                query = (
                    f"SELECT DATEADD(day, -{idx % 30}, GETDATE()) AS ref_day, COUNT(*) "
                    f"FROM {table} WHERE status = '{status}'"
                )
                dialect = "sqlserver"
            elif cross_variant == 2:
                query = (
                    f"SELECT CURRENT_TIMESTAMP(), SUM(total_amount) "
                    f"FROM {table} WHERE tenant_id = {idx % 900} AND total_amount > {amount}"
                )
                dialect = "mysql"
            else:
                query = (
                    f"SELECT COUNT(*) FROM {table} WHERE status = '{status}' "
                    f"AND tenant_id = {idx % 300} AND amount > {amount}"
                )
                dialect = "mysql"
            rows.append(
                {
                    "label": "benign",
                    "scenario": "cross_dialect_query",
                    "query": query,
                    "dialect": dialect,
                    "orm_name": "none",
                    "service_context": service,
                    "notes": "cross-dialect benign query",
                }
            )

    rng.shuffle(rows)
    return rows[: max(1, int(max_rows))]


def refresh_sql_threat_corpus(
    *,
    output_path: Optional[Path] = None,
    report_path: Optional[Path] = None,
    max_malicious_rows: int = 1200,
    max_benign_rows: int = 700,
    feedback_limit: int = 500,
    seed: int = 42,
) -> Dict[str, Any]:
    backend_root = _backend_root()
    if output_path is None:
        output_path = backend_root / "data" / "corpus" / "sql" / "raw" / "sql_online_weaklabels.csv"
    if report_path is None:
        report_path = backend_root / "data" / "corpus" / "sql" / "raw" / "sql_online_weaklabels_report.json"

    online_payloads, source_counts, fetch_errors = _collect_online_payloads(max_payloads=max_malicious_rows * 3)
    feedback_malicious, feedback_benign, false_negative_count, false_positive_count = _load_sql_feedback_samples(
        limit=feedback_limit
    )

    rows: List[Dict[str, str]] = []
    seen: Set[str] = set()
    source_usage: Dict[str, int] = {}
    malicious_count = 0
    benign_count = 0

    def add_row(row: Dict[str, str], key_prefix: str) -> bool:
        nonlocal malicious_count, benign_count
        query = _normalize_candidate(row.get("query") or "")
        if not query:
            return False
        row["query"] = query
        dedup_key = f"{key_prefix}|{row.get('label')}|{row.get('scenario')}|{query.lower()}"
        if dedup_key in seen:
            return False
        seen.add(dedup_key)
        rows.append(row)
        if str(row.get("label") or "").lower() == "malicious":
            malicious_count += 1
        elif str(row.get("label") or "").lower() == "benign":
            benign_count += 1
        return True

    # Analyst-labeled rows first.
    for q in feedback_malicious:
        scenario, dialect, service_context = _infer_scenario_dialect_service(q)
        added = add_row(
            {
                "label": "malicious",
                "scenario": scenario,
                "query": q,
                "dialect": dialect,
                "orm_name": "none",
                "service_context": service_context,
                "notes": "analyst-labeled SQL malicious sample",
            },
            "feedback_malicious",
        )
        if added and malicious_count >= max(1, int(max_malicious_rows)):
            break

    for entry in online_payloads:
        if malicious_count >= max(1, int(max_malicious_rows)):
            break
        payload = str(entry.get("payload") or "")
        scenario, dialect, service_context = _infer_scenario_dialect_service(payload)
        source_name = str(entry.get("source") or "online")
        added = add_row(
            {
                "label": "malicious",
                "scenario": scenario,
                "query": payload,
                "dialect": dialect,
                "orm_name": "none",
                "service_context": service_context,
                "notes": f"online SQLi weak label from {source_name}",
            },
            f"online:{source_name}",
        )
        if added:
            source_usage[source_name] = source_usage.get(source_name, 0) + 1

    for q in feedback_benign:
        added = add_row(
            {
                "label": "benign",
                "scenario": "benign_enterprise_query",
                "query": q,
                "dialect": "postgresql",
                "orm_name": "none",
                "service_context": "analyst-verified",
                "notes": "analyst-labeled SQL benign sample",
            },
            "feedback_benign",
        )
        if added and benign_count >= max(1, int(max_benign_rows)):
            break

    benign_seed = _generate_benign_rows(max_rows=max_benign_rows, seed=seed)
    for row in benign_seed:
        if benign_count >= max(1, int(max_benign_rows)):
            break
        add_row(row, "benign_seed")

    # Scenario coverage guardrails.
    scenario_set = {str(r.get("scenario") or "") for r in rows}
    if "stored_procedure_abuse" not in scenario_set:
        add_row(
            {
                "label": "malicious",
                "scenario": "stored_procedure_abuse",
                "query": "EXEC xp_cmdshell 'whoami'",
                "dialect": "sqlserver",
                "orm_name": "none",
                "service_context": "legacy-admin-console",
                "notes": "coverage safeguard",
            },
            "coverage",
        )
    if "service_context_trace" not in scenario_set:
        add_row(
            {
                "label": "malicious",
                "scenario": "service_context_trace",
                "query": "SELECT * FROM invoices WHERE invoice_id = 10 AND SUBSTRING((SELECT version()),1,1)='1' --",
                "dialect": "postgresql",
                "orm_name": "none",
                "service_context": "billing-api",
                "notes": "coverage safeguard",
            },
            "coverage",
        )
    if "obfuscated_sqli" not in scenario_set:
        add_row(
            {
                "label": "malicious",
                "scenario": "obfuscated_sqli",
                "query": "SeLeCt * FrOm users WhErE id=1/**/OR/**/1=1--",
                "dialect": "mysql",
                "orm_name": "none",
                "service_context": "public-web-api",
                "notes": "coverage safeguard",
            },
            "coverage",
        )
    if "orm_generated_query" not in scenario_set:
        add_row(
            {
                "label": "benign",
                "scenario": "orm_generated_query",
                "query": 'SELECT "user"."id", "user"."email" FROM "user" WHERE "user"."id" = $1',
                "dialect": "postgresql",
                "orm_name": "django_orm",
                "service_context": "identity-api",
                "notes": "coverage safeguard",
            },
            "coverage",
        )
    if "cross_dialect_query" not in scenario_set:
        add_row(
            {
                "label": "benign",
                "scenario": "cross_dialect_query",
                "query": "SELECT CURRENT_TIMESTAMP()",
                "dialect": "mysql",
                "orm_name": "none",
                "service_context": "healthcheck-service",
                "notes": "coverage safeguard",
            },
            "coverage",
        )
    if "benign_enterprise_query" not in scenario_set:
        add_row(
            {
                "label": "benign",
                "scenario": "benign_enterprise_query",
                "query": "SELECT id, tenant_id, status FROM orders WHERE tenant_id = ? AND status = ?",
                "dialect": "postgresql",
                "orm_name": "none",
                "service_context": "orders-api",
                "notes": "coverage safeguard",
            },
            "coverage",
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=["label", "scenario", "query", "dialect", "orm_name", "service_context", "notes"],
        )
        writer.writeheader()
        writer.writerows(rows)

    label_counts: Dict[str, int] = {}
    scenario_counts: Dict[str, int] = {}
    for row in rows:
        label = str(row.get("label") or "unknown")
        scenario = str(row.get("scenario") or "unknown")
        label_counts[label] = label_counts.get(label, 0) + 1
        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1

    missing_required = sorted(list(set(REQUIRED_SCENARIOS) - set(scenario_counts.keys())))

    report = {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": {
            "output_csv": str(output_path),
            "report_json": str(report_path),
        },
        "stats": {
            "total_rows": len(rows),
            "label_distribution": label_counts,
            "scenario_distribution": scenario_counts,
            "required_scenarios": REQUIRED_SCENARIOS,
            "missing_required_scenarios": missing_required,
        },
        "sources": {
            "online_feed_rows_by_source": source_counts,
            "online_rows_used_by_source": source_usage,
            "online_fetch_errors": fetch_errors,
            "feedback_samples": {
                "malicious": len(feedback_malicious),
                "benign": len(feedback_benign),
                "false_negatives": false_negative_count,
                "false_positives": false_positive_count,
            },
            "feed_list": SQL_FEEDS,
            "references": REFERENCE_SOURCES,
        },
        "params": {
            "max_malicious_rows": int(max_malicious_rows),
            "max_benign_rows": int(max_benign_rows),
            "feedback_limit": int(feedback_limit),
            "seed": int(seed),
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Build weak-labeled online SQL threat corpus.")
    parser.add_argument("--max-malicious-rows", type=int, default=int(os.getenv("SQL_WEAKLABEL_MAX_MALICIOUS_ROWS", "1200")))
    parser.add_argument("--max-benign-rows", type=int, default=int(os.getenv("SQL_WEAKLABEL_MAX_BENIGN_ROWS", "700")))
    parser.add_argument("--feedback-limit", type=int, default=int(os.getenv("SQL_WEAKLABEL_FEEDBACK_LIMIT", "500")))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    report = refresh_sql_threat_corpus(
        max_malicious_rows=max(100, int(args.max_malicious_rows)),
        max_benign_rows=max(100, int(args.max_benign_rows)),
        feedback_limit=max(0, int(args.feedback_limit)),
        seed=int(args.seed),
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
