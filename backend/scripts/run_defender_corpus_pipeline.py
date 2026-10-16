from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from backend.core.database import SessionLocal, create_db_tables, ensure_runtime_schema_compatibility
from backend.scripts.build_evaluation_corpus import build_domain_corpus
from backend.scripts.update_sql_threat_corpus import refresh_sql_threat_corpus
from backend.services.defender_ai_service import DefenderAIService


def _corpus_root() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "corpus"


def _corpus_domains(target: str) -> List[str]:
    if target == "all":
        return ["sql", "file", "phishing"]
    if target == "spam":
        return ["phishing"]
    if target in {"sql", "file"}:
        return [target]
    raise ValueError(f"Unsupported domain: {target}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build validated corpora and trigger Defender retraining.")
    parser.add_argument("--domain", choices=["sql", "spam", "file", "all"], default="all")
    parser.add_argument("--strict", action="store_true", help="Fail corpus build on quality gate misses.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-feedback-samples", type=int, default=5)
    parser.add_argument("--allow-corpus-only", action="store_true")
    parser.add_argument("--promote-if-better", action="store_true")
    parser.add_argument("--notes", type=str, default="corpus_pipeline")
    parser.add_argument("--refresh-sql-online", action="store_true")
    parser.add_argument(
        "--sql-max-malicious-rows",
        type=int,
        default=int(os.getenv("SQL_WEAKLABEL_MAX_MALICIOUS_ROWS", "1200")),
    )
    parser.add_argument(
        "--sql-max-benign-rows",
        type=int,
        default=int(os.getenv("SQL_WEAKLABEL_MAX_BENIGN_ROWS", "700")),
    )
    parser.add_argument(
        "--sql-feedback-limit",
        type=int,
        default=int(os.getenv("SQL_WEAKLABEL_FEEDBACK_LIMIT", "500")),
    )
    args = parser.parse_args()

    corpus_root = _corpus_root()
    sql_threat_refresh_report: Dict[str, Any] = {"status": "not_requested"}
    if bool(args.refresh_sql_online) and any(d == "sql" for d in _corpus_domains(args.domain)):
        try:
            sql_threat_refresh_report = refresh_sql_threat_corpus(
                max_malicious_rows=max(100, int(args.sql_max_malicious_rows)),
                max_benign_rows=max(100, int(args.sql_max_benign_rows)),
                feedback_limit=max(0, int(args.sql_feedback_limit)),
                seed=int(args.seed),
            )
        except Exception as exc:
            sql_threat_refresh_report = {"status": "error", "error": str(exc)}

    corpus_reports: Dict[str, Any] = {}
    for d in _corpus_domains(args.domain):
        corpus_reports[d] = build_domain_corpus(
            domain=d,
            corpus_root=corpus_root,
            strict=bool(args.strict),
            seed=int(args.seed),
        )

    create_db_tables()
    ensure_runtime_schema_compatibility()
    service = DefenderAIService.get_instance() if DefenderAIService._instance is not None else DefenderAIService()

    with SessionLocal() as db:
        retrain_results = service.retrain_and_register_candidates(
            db=db,
            domain=args.domain,
            min_feedback_samples=max(0, int(args.min_feedback_samples)),
            promote_if_better=bool(args.promote_if_better),
            notes=f"{args.notes} @{datetime.now(timezone.utc).isoformat()}",
            allow_corpus_only=bool(args.allow_corpus_only),
        )

    output = {
        "status": "ok",
        "domain": args.domain,
        "allow_corpus_only": bool(args.allow_corpus_only),
        "min_feedback_samples": int(args.min_feedback_samples),
        "sql_threat_refresh_report": sql_threat_refresh_report,
        "corpus_reports": corpus_reports,
        "retrain_results": retrain_results,
    }
    print(json.dumps(output, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
