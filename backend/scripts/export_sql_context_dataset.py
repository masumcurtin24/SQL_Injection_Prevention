from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.database import SessionLocal, create_db_tables, ensure_runtime_schema_compatibility
from backend.core.models import SQLAnalysisLog
from backend.security.sql_normalizer import canonicalize


DEFAULT_OUTPUT = (
    PROJECT_ROOT / "backend" / "data" / "corpus" / "sql" / "raw" / "sql_request_response_context_latest.csv"
)
DEFAULT_REPORT = (
    PROJECT_ROOT / "backend" / "data" / "corpus" / "sql" / "raw" / "sql_request_response_context_report_latest.json"
)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _join_hits(hits: Any) -> str:
    if isinstance(hits, list):
        return "|".join(str(x) for x in hits if str(x).strip())
    if isinstance(hits, str):
        return hits.strip()
    return ""


def _iter_rows(limit: int) -> Iterable[SQLAnalysisLog]:
    with SessionLocal() as db:
        q = db.query(SQLAnalysisLog).order_by(SQLAnalysisLog.timestamp.desc())
        if limit > 0:
            q = q.limit(limit)
        yield from q.all()


def build_rows(limit: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in _iter_rows(limit=limit):
        query_text = str(item.query_received or "").strip()
        normalized, _meta = canonicalize(query_text)

        anomaly = item.anomaly_detection_result or {}
        validation = item.query_validation_result or {}
        combined = item.combined_assessment or {}
        risk_level = str(item.risk_level or combined.get("overall_risk_level") or "").strip() or "Low"
        action = str(item.suggested_action or combined.get("suggested_action") or "").strip() or "ALLOW"
        category = str(item.category or "").strip() or "safe"
        is_malicious = int(bool(item.is_malicious))
        calibrated_risk = _safe_float(combined.get("calibrated_risk_score"), default=0.0)
        heuristic_hits = _join_hits((combined.get("heuristics_detection") or {}).get("hits"))

        request_payload_text = " ".join(
            token for token in [f"tenant:{item.tenant_id}", query_text, f"category:{category}"] if token
        ).strip()
        response_context_text = " ".join(
            token
            for token in [
                f"risk:{risk_level}",
                f"action:{action}",
                f"malicious:{is_malicious}",
                f"anomaly:{anomaly.get('prediction_label')}",
                f"nlp:{validation.get('classification_label')}",
                f"hits:{heuristic_hits}",
            ]
            if token
        ).strip()

        rows.append(
            {
                "sample_id": str(item.id or ""),
                "timestamp": (item.timestamp or datetime.now(timezone.utc)).isoformat(),
                "tenant_id": str(item.tenant_id or ""),
                "service_context": "unknown",
                "request_query": query_text,
                "request_query_normalized": normalized,
                "response_risk_level": risk_level,
                "response_action": action,
                "response_category": category,
                "response_is_malicious": is_malicious,
                "response_calibrated_risk_score": calibrated_risk,
                "anomaly_label": str(anomaly.get("prediction_label") or ""),
                "anomaly_score": _safe_float(anomaly.get("score"), default=0.0),
                "nlp_label": str(validation.get("classification_label") or ""),
                "nlp_score": _safe_float(validation.get("classification_score"), default=0.0),
                "heuristic_hits": heuristic_hits,
                "label": is_malicious,
                "request_payload_text": request_payload_text,
                "response_context_text": response_context_text,
                "source_type": "runtime_sql_analysis_log",
            }
        )
    return rows


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "sample_id",
        "timestamp",
        "tenant_id",
        "service_context",
        "request_query",
        "request_query_normalized",
        "response_risk_level",
        "response_action",
        "response_category",
        "response_is_malicious",
        "response_calibrated_risk_score",
        "anomaly_label",
        "anomaly_score",
        "nlp_label",
        "nlp_score",
        "heuristic_hits",
        "label",
        "request_payload_text",
        "response_context_text",
        "source_type",
    ]
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_report(path: Path, rows: List[Dict[str, Any]], output_csv: Path) -> None:
    labels = {0: 0, 1: 0}
    risk_counts: Dict[str, int] = {}
    action_counts: Dict[str, int] = {}
    for row in rows:
        labels[int(row.get("label", 0))] = labels.get(int(row.get("label", 0)), 0) + 1
        risk = str(row.get("response_risk_level") or "unknown")
        action = str(row.get("response_action") or "unknown")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        action_counts[action] = action_counts.get(action, 0) + 1

    report = {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output_csv": str(output_csv),
        "rows": len(rows),
        "label_distribution": {str(k): int(v) for k, v in labels.items()},
        "risk_distribution": risk_counts,
        "action_distribution": action_counts,
        "notes": [
            "service_context is currently exported as 'unknown' because runtime logs do not persist request header service name.",
            "This artifact is intended as a context-enriched training input for roadmap experiments.",
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Roadmap step: export SQL request-response context dataset.")
    p.add_argument("--output-csv", type=str, default=str(DEFAULT_OUTPUT))
    p.add_argument("--report-json", type=str, default=str(DEFAULT_REPORT))
    p.add_argument("--limit", type=int, default=10000, help="Max rows to export; <=0 exports all.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    output_csv = Path(args.output_csv).resolve()
    report_json = Path(args.report_json).resolve()
    limit = int(args.limit)

    create_db_tables()
    ensure_runtime_schema_compatibility()
    rows = build_rows(limit=limit)
    write_csv(output_csv, rows)
    write_report(report_json, rows, output_csv)

    payload = {
        "status": "ok",
        "output_csv": str(output_csv),
        "report_json": str(report_json),
        "rows": len(rows),
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
