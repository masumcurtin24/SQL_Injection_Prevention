from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_RUNS = PROJECT_ROOT / "backend" / "data" / "benchmarks" / "runs"
ROADMAP_ROOT = PROJECT_ROOT / "backend" / "data" / "benchmarks" / "roadmap"
DEFAULT_REPORT_JSON = ROADMAP_ROOT / "sql_rule_suggestions_latest.json"
DEFAULT_REPORT_MD = ROADMAP_ROOT / "sql_rule_suggestions_latest.md"
DEFAULT_SUGGESTIONS_YAML = PROJECT_ROOT / "backend" / "security" / "prevention_rules_roadmap_suggestions.yml"


PATTERN_LIBRARY: Dict[str, str] = {
    "union_select": r"(?i)\bunion\s+select\b",
    "stacked_query": r"(?i);\s*(drop|delete|insert|update|alter|exec|execute|call)\b",
    "time_delay": r"(?i)\b(sleep\s*\(|pg_sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b",
    "blind_exfil": r"(?i)\b(substring|substr|ascii|ord)\s*\(\s*\(\s*select\b",
    "metadata_probe": r"(?i)\b(@@version|version\s*\(|database\s*\(|current_database\s*\(|information_schema)\b",
    "proc_abuse": r"(?i)\b(xp_cmdshell|xp_dirtree|xp_regread|sp_oacreate|openrowset)\b",
    "copy_program": r"(?i)\bcopy\b[\s\S]{0,120}\bto\s+program\b",
    "comment_tamper": r"(?i)(--|/\*|\*/|#)",
}


def _norm_space(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _load_predictions(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Prediction file not found: {path}")
    df = pd.read_csv(path, dtype=str, keep_default_na=False).copy()
    required = {"label", "query"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"Missing required columns in predictions CSV: {missing}")
    # enforcement prediction key differs by domain scripts; support common names.
    if "pred_enforcement" in df.columns:
        pred_col = "pred_enforcement"
    elif "predicted_positive" in df.columns:
        pred_col = "predicted_positive"
    else:
        raise ValueError("Prediction CSV must include 'pred_enforcement' or 'predicted_positive'.")
    df["pred_col"] = df[pred_col]
    df["label"] = df["label"].apply(lambda v: int(str(v).strip() or "0"))
    df["pred"] = df["pred_col"].apply(lambda v: int(str(v).strip() or "0"))
    return df


def _latest_sql_predictions() -> Path:
    if not BENCHMARK_RUNS.exists():
        raise FileNotFoundError(f"Missing benchmark runs directory: {BENCHMARK_RUNS}")
    candidates: List[Path] = []
    for run_dir in BENCHMARK_RUNS.iterdir():
        if not run_dir.is_dir():
            continue
        p = run_dir / "sql_predictions.csv"
        if p.exists():
            candidates.append(p)
    if not candidates:
        raise FileNotFoundError("No sql_predictions.csv found in benchmark runs.")
    candidates.sort(key=lambda p: p.parent.name, reverse=True)
    return candidates[0]


def _extract_fn_fp(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    false_neg = df[(df["label"] == 1) & (df["pred"] == 0)].copy()
    false_pos = df[(df["label"] == 0) & (df["pred"] == 1)].copy()
    return false_neg.reset_index(drop=True), false_pos.reset_index(drop=True)


def _pattern_frequencies(rows: pd.DataFrame) -> Dict[str, int]:
    out: Dict[str, int] = {k: 0 for k in PATTERN_LIBRARY.keys()}
    for query in rows["query"].astype(str).tolist():
        text = str(query or "")
        for key, patt in PATTERN_LIBRARY.items():
            if re.search(patt, text):
                out[key] += 1
    return out


def _templateize_query(query: str) -> str:
    s = _norm_space(query).lower()
    s = re.sub(r"'(?:''|[^'])*'", "?", s)
    s = re.sub(r"\b0x[0-9a-f]+\b", "?", s, flags=re.IGNORECASE)
    s = re.sub(r"\b\d+(?:\.\d+)?\b", "?", s)
    s = _norm_space(s)
    return s[:240]


def _candidate_allowlist_from_fp(false_pos: pd.DataFrame, max_items: int = 15) -> List[str]:
    templates: Dict[str, int] = {}
    for query in false_pos["query"].astype(str).tolist():
        q = str(query or "")
        # Conservative: only consider obviously parameterized queries as candidates.
        if not re.search(r"(\?|\$\d+|@[a-z_][a-z0-9_]*)", q, flags=re.IGNORECASE):
            continue
        if re.search(r"(union\s+select|xp_cmdshell|waitfor\s+delay|sleep\s*\()", q, flags=re.IGNORECASE):
            continue
        t = _templateize_query(q)
        if not t:
            continue
        templates[t] = templates.get(t, 0) + 1
    ranked = sorted(templates.items(), key=lambda item: (-item[1], item[0]))
    return [tpl for tpl, _count in ranked[: max(1, int(max_items))]]


def _to_yaml(report: Dict[str, Any]) -> str:
    def _sq(value: Any) -> str:
        text = str(value or "")
        return "'" + text.replace("'", "''") + "'"

    critical_patterns = report.get("recommended_critical_patterns", [])
    allow_templates = report.get("recommended_allowlist_templates", [])
    fn_freq = report.get("false_negative_pattern_frequency", {})
    lines = [
        "# Roadmap suggestion file (non-authoritative).",
        "# Review manually before merging into backend/security/prevention_rules.yml.",
        "sql_roadmap_suggestions:",
        f"  generated_at: {_sq(report.get('generated_at'))}",
        f"  source_predictions: {_sq(report.get('source_predictions'))}",
        "  observed_error_counts:",
        f"    false_negatives: {report.get('false_negative_count', 0)}",
        f"    false_positives: {report.get('false_positive_count', 0)}",
        "  pattern_frequency_false_negatives:",
    ]
    for key in sorted(fn_freq.keys()):
        lines.append(f"    {key}: {int(fn_freq.get(key, 0))}")
    lines.append("  recommended_updates:")
    lines.append("    critical_patterns:")
    if critical_patterns:
        for patt in critical_patterns:
            lines.append(f"      - {_sq(patt)}")
    else:
        lines.append("      - 're:(?i)union\\s+select'")
    lines.append("    allowlist_templates:")
    if allow_templates:
        for tpl in allow_templates:
            lines.append(f"      - {_sq(tpl)}")
    else:
        lines.append("      - '# no safe template candidates found'")
    lines.append("  notes:")
    lines.append("    - 'This file is advisory; do not auto-apply in production without review.'")
    lines.append("    - 'Validate updates with run_benchmark_harness.py --domain sql --sql-scope combined --strict-gate.'")
    lines.append("")
    return "\n".join(lines)


def _to_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# SQL Rule Suggestion Report",
        "",
        f"- Recorded at: `{report.get('generated_at')}`",
        f"- Source predictions: `{report.get('source_predictions')}`",
        f"- Total rows: `{report.get('total_rows')}`",
        f"- False negatives: `{report.get('false_negative_count')}`",
        f"- False positives: `{report.get('false_positive_count')}`",
        "",
        "## False-negative pattern frequency",
    ]
    freq = report.get("false_negative_pattern_frequency", {})
    for key in sorted(freq.keys()):
        lines.append(f"- {key}: {freq[key]}")
    lines.append("")
    lines.append("## Recommended critical patterns")
    for patt in report.get("recommended_critical_patterns", []):
        lines.append(f"- {patt}")
    lines.append("")
    lines.append("## Recommended allowlist templates (review required)")
    for tpl in report.get("recommended_allowlist_templates", []):
        lines.append(f"- {tpl}")
    lines.append("")
    return "\n".join(lines)


def run(predictions_csv: Path, report_json: Path, report_md: Path, out_yaml: Path) -> Dict[str, Any]:
    ROADMAP_ROOT.mkdir(parents=True, exist_ok=True)
    df = _load_predictions(predictions_csv)
    fn_df, fp_df = _extract_fn_fp(df)
    fn_freq = _pattern_frequencies(fn_df)

    # Recommend top missed malicious signatures.
    recommended_critical_patterns: List[str] = []
    for key, count in sorted(fn_freq.items(), key=lambda item: (-item[1], item[0])):
        if count <= 0:
            continue
        recommended_critical_patterns.append(f"re:{PATTERN_LIBRARY[key]}")
        if len(recommended_critical_patterns) >= 6:
            break

    allow_templates = _candidate_allowlist_from_fp(fp_df, max_items=15)
    report = {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_predictions": str(predictions_csv),
        "total_rows": int(len(df)),
        "false_negative_count": int(len(fn_df)),
        "false_positive_count": int(len(fp_df)),
        "false_negative_pattern_frequency": fn_freq,
        "recommended_critical_patterns": recommended_critical_patterns,
        "recommended_allowlist_templates": allow_templates,
        "notes": [
            "Suggestions are intentionally conservative and should be reviewed manually.",
            "Derived from benchmark prediction errors; not from production telemetry.",
        ],
    }

    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report_md.write_text(_to_markdown(report), encoding="utf-8")
    out_yaml.parent.mkdir(parents=True, exist_ok=True)
    out_yaml.write_text(_to_yaml(report), encoding="utf-8")
    return report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Roadmap step: generate SQL prevention rule suggestions from benchmark errors."
    )
    p.add_argument(
        "--predictions-csv",
        type=str,
        default="",
        help="Path to sql_predictions.csv. Default: latest available benchmark run.",
    )
    p.add_argument("--report-json", type=str, default=str(DEFAULT_REPORT_JSON))
    p.add_argument("--report-md", type=str, default=str(DEFAULT_REPORT_MD))
    p.add_argument("--suggestions-yaml", type=str, default=str(DEFAULT_SUGGESTIONS_YAML))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    predictions = Path(args.predictions_csv).resolve() if str(args.predictions_csv).strip() else _latest_sql_predictions()
    report = run(
        predictions_csv=predictions,
        report_json=Path(args.report_json).resolve(),
        report_md=Path(args.report_md).resolve(),
        out_yaml=Path(args.suggestions_yaml).resolve(),
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
