from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import pandas as pd


def _norm(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _slug(value: Any) -> str:
    raw = _norm(value).lower().replace(" ", "_").replace("-", "_")
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _safe_json(v: Dict[str, Any]) -> str:
    try:
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    except Exception:
        return "{}"


def _label_to_int(label: Any, label_map: Dict[str, int]) -> Optional[int]:
    key = _slug(label)
    if not key:
        return None
    if key in label_map:
        return int(label_map[key])
    if key in {"1", "true", "malicious", "spam", "phishing", "suspicious"}:
        return 1
    if key in {"0", "false", "benign", "safe", "ham", "legitimate"}:
        return 0
    return None


def _compose_sql_text(row: Dict[str, Any]) -> str:
    query = _norm(row.get("query") or row.get("text"))
    dialect = _slug(row.get("dialect"))
    orm = _slug(row.get("orm_name") or row.get("orm"))
    service = _slug(row.get("service_context") or row.get("service"))
    parts = []
    if dialect:
        parts.append(f"dialect:{dialect}")
    if orm:
        parts.append(f"orm:{orm}")
    if service:
        parts.append(f"service:{service}")
    if query:
        parts.append(query)
    return _norm(" ".join(parts))


def _derive_sql_benchmark_group(record: Dict[str, Any], source_file: str) -> str:
    explicit = _slug(record.get("benchmark_group") or record.get("corpus_group") or record.get("evaluation_group"))
    if explicit:
        return explicit
    source = str(source_file or "").lower().strip()
    if "heldout" in source or "held_out" in source or "adversarial" in source:
        return "held_out_adversarial"
    if "template" in source:
        return "tuning"
    if "seed" in source or "weaklabel" in source:
        return "regression"
    split = _slug(record.get("split"))
    if split == "train":
        return "tuning"
    if split in {"validation", "test"}:
        return "regression"
    return "regression"


def _derive_sql_source_kind(record: Dict[str, Any], source_file: str) -> str:
    explicit = _slug(record.get("source_kind") or record.get("source_type"))
    if explicit:
        return explicit
    source = str(source_file or "").lower().strip()
    if "weaklabel" in source:
        return "weaklabel"
    if "template" in source or "seed" in source:
        return "synthetic"
    if "heldout" in source or "held_out" in source or "adversarial" in source:
        return "curated"
    return "curated"


def _derive_sql_source_confidence(record: Dict[str, Any], source_kind: str) -> str:
    explicit = _slug(record.get("source_confidence") or record.get("confidence"))
    if explicit:
        return explicit
    if source_kind == "weaklabel":
        return "weak"
    if source_kind == "synthetic":
        return "medium"
    return "high"


def _derive_sql_severity(label: int, scenario: str, record: Dict[str, Any]) -> str:
    explicit = _slug(record.get("severity") or record.get("severity_slice"))
    if explicit:
        return explicit
    if int(label) == 0:
        return "none"
    scen = _slug(scenario)
    if scen in {"stored_procedure_abuse", "file_os_interaction", "stacked_delayed_sqli", "stacked_delay_sqli"}:
        return "critical"
    if scen in {
        "obfuscated_sqli",
        "service_context_trace",
        "service_context_bypass",
        "schema_enumeration",
        "whitespace_comment_tampering",
        "encoding_concatenation_evasion",
        "cross_dialect_evasion",
    }:
        return "high"
    return "high"


def _derive_sql_benign_type(label: int, scenario: str, record: Dict[str, Any]) -> str:
    explicit = _slug(record.get("benign_scenario_type") or record.get("benign_type"))
    if explicit:
        return explicit
    if int(label) != 0:
        return "non_benign"
    scen = _slug(scenario)
    mapping = {
        "benign_enterprise_query": "enterprise_runtime",
        "orm_generated_query": "orm_generated",
        "cross_dialect_query": "cross_dialect",
        "reporting_analytics_query": "reporting_analytics",
        "parameterized_raw_sql_query": "parameterized_raw_sql",
        "metadata_introspection_query": "metadata_introspection",
        "migration_admin_query": "migration_admin",
    }
    return mapping.get(scen, "general_benign")


def _derive_sql_tuned_flag(record: Dict[str, Any], benchmark_group: str, source_kind: str) -> str:
    explicit = _slug(record.get("tuned_during_phase2_1"))
    if explicit in {"true", "false"}:
        return explicit
    if benchmark_group == "held_out_adversarial":
        return "false"
    if source_kind in {"synthetic", "weaklabel"}:
        return "true"
    return "false"


def _compose_file_text(row: Dict[str, Any]) -> str:
    filename = _norm(row.get("filename"))
    mime = _slug(row.get("mime_type"))
    ext = _slug(row.get("extension"))
    file_type = _slug(row.get("file_type"))
    macro = _slug(row.get("macro_enabled"))
    nested = _slug(row.get("nested_archive"))
    excerpt = _norm(row.get("content_excerpt") or row.get("text"))
    parts = []
    if filename:
        parts.append(f"filename:{filename}")
    if file_type:
        parts.append(f"type:{file_type}")
    if mime:
        parts.append(f"mime:{mime}")
    if ext:
        parts.append(f"ext:{ext}")
    if macro:
        parts.append(f"macro:{macro}")
    if nested:
        parts.append(f"nested_archive:{nested}")
    if excerpt:
        parts.append(excerpt)
    return _norm(" ".join(parts))


def _compose_phishing_text(row: Dict[str, Any]) -> str:
    subject = _norm(row.get("subject"))
    body = _norm(row.get("body_text") or row.get("text"))
    sender = _norm(row.get("sender_email") or row.get("sender_domain"))
    urls = _norm(row.get("urls") or row.get("url_features"))
    attachment = _norm(row.get("attachment_features") or row.get("attachment_names"))
    language = _slug(row.get("language"))
    style = _slug(row.get("style_shift") or row.get("style"))
    parts = []
    if subject:
        parts.append(f"subject:{subject}")
    if sender:
        parts.append(f"sender:{sender}")
    if language:
        parts.append(f"language:{language}")
    if style:
        parts.append(f"style:{style}")
    if urls:
        parts.append(f"urls:{urls}")
    if attachment:
        parts.append(f"attachment:{attachment}")
    if body:
        parts.append(body)
    return _norm(" ".join(parts))


@dataclass(frozen=True)
class DomainSpec:
    key: str
    required_scenarios: Tuple[str, ...]
    label_map: Dict[str, int]
    text_builder: Callable[[Dict[str, Any]], str]
    output_name: str


SQL_REQUIRED_SCENARIOS = (
    "benign_enterprise_query",
    "orm_generated_query",
    "cross_dialect_query",
    "obfuscated_sqli",
    "stored_procedure_abuse",
    "service_context_trace",
)

FILE_REQUIRED_SCENARIOS = (
    "benign_complex_pdf_ooxml",
    "benign_macro_enabled_office",
    "malicious_pdf_ooxml",
    "nested_archive_abuse",
    "mime_extension_mismatch",
)

PHISH_REQUIRED_SCENARIOS = (
    "modern_phishing",
    "legitimate_transactional",
    "sender_domain_metadata",
    "url_feature_rich",
    "attachment_feature_rich",
    "multilingual_style_shift",
)

DOMAIN_SPECS: Dict[str, DomainSpec] = {
    "sql": DomainSpec(
        key="sql",
        required_scenarios=SQL_REQUIRED_SCENARIOS,
        label_map={"benign": 0, "safe": 0, "malicious": 1, "sqli": 1, "suspicious": 1},
        text_builder=_compose_sql_text,
        output_name="sql_corpus_latest.csv",
    ),
    "file": DomainSpec(
        key="file",
        required_scenarios=FILE_REQUIRED_SCENARIOS,
        label_map={"benign": 0, "safe": 0, "malicious": 1, "suspicious": 1, "blocked": 1},
        text_builder=_compose_file_text,
        output_name="file_corpus_latest.csv",
    ),
    "phishing": DomainSpec(
        key="phishing",
        required_scenarios=PHISH_REQUIRED_SCENARIOS,
        label_map={"ham": 0, "legitimate": 0, "benign": 0, "spam": 1, "phishing": 1, "malicious": 1, "suspicious": 1},
        text_builder=_compose_phishing_text,
        output_name="phishing_corpus_latest.csv",
    ),
}


def _iter_raw_files(raw_dir: Path) -> Iterable[Path]:
    if not raw_dir.exists():
        return []
    return sorted([p for p in raw_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".csv", ".jsonl"}])


def _records_from_file(path: Path) -> List[Dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        return df.to_dict(orient="records")
    if suffix == ".jsonl":
        rows: List[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            row = line.strip()
            if not row:
                continue
            try:
                parsed = json.loads(row)
            except Exception:
                continue
            if isinstance(parsed, dict):
                rows.append(parsed)
        return rows
    return []


def _hash_id(domain: str, text: str, label: int, scenario: str) -> str:
    payload = f"{domain}|{label}|{scenario}|{text[:2000]}"
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _apply_split(df: pd.DataFrame, seed: int, val_ratio: float = 0.15, test_ratio: float = 0.15) -> pd.DataFrame:
    # Normalize index so downstream loc/set operations are stable after de-dup/filter.
    out = df.copy().reset_index(drop=True)
    if "split" in out.columns:
        existing = out["split"].astype(str).str.lower().str.strip()
        if existing.isin({"train", "validation", "test"}).all():
            return out

    out["split"] = "train"
    # Keep sampled rows' original index values so we can write back to `out` safely.
    shuffled = out.sample(frac=1.0, random_state=seed)
    for label, group in shuffled.groupby("label", sort=False):
        idx = list(group.index)
        n = len(idx)
        if n <= 2:
            continue
        n_test = max(1, int(round(n * test_ratio)))
        n_val = max(1, int(round(n * val_ratio)))
        if (n_test + n_val) >= n:
            n_test = 1
            n_val = 1
        test_idx = idx[:n_test]
        val_idx = idx[n_test : n_test + n_val]
        out.loc[test_idx, "split"] = "test"
        out.loc[val_idx, "split"] = "validation"
    return out


def build_domain_corpus(
    *,
    domain: str,
    corpus_root: Path,
    strict: bool = False,
    seed: int = 42,
) -> Dict[str, Any]:
    if domain not in DOMAIN_SPECS:
        raise ValueError(f"Unsupported domain: {domain}")
    spec = DOMAIN_SPECS[domain]
    domain_root = corpus_root / domain
    raw_dir = domain_root / "raw"
    processed_dir = domain_root / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, Any]] = []
    skipped = 0
    files = list(_iter_raw_files(raw_dir))
    for file_path in files:
        for record in _records_from_file(file_path):
            label = _label_to_int(record.get("label"), spec.label_map)
            if label is None:
                skipped += 1
                continue
            scenario = _slug(record.get("scenario"))
            if not scenario:
                skipped += 1
                continue
            text = spec.text_builder(record)
            if not text:
                skipped += 1
                continue
            metadata = dict(record)
            metadata.pop("text", None)
            metadata.pop("body_text", None)
            benchmark_group = _slug(record.get("benchmark_group"))
            source_kind = _slug(record.get("source_kind"))
            source_confidence = _slug(record.get("source_confidence"))
            severity = _slug(record.get("severity"))
            benign_scenario_type = _slug(record.get("benign_scenario_type"))
            tuned_during_phase2_1 = _slug(record.get("tuned_during_phase2_1"))
            if domain == "sql":
                benchmark_group = _derive_sql_benchmark_group(record, file_path.name)
                source_kind = _derive_sql_source_kind(record, file_path.name)
                source_confidence = _derive_sql_source_confidence(record, source_kind)
                severity = _derive_sql_severity(int(label), scenario, record)
                benign_scenario_type = _derive_sql_benign_type(int(label), scenario, record)
                tuned_during_phase2_1 = _derive_sql_tuned_flag(record, benchmark_group, source_kind)

            metadata.setdefault("benchmark_group", benchmark_group or "unknown")
            metadata.setdefault("source_kind", source_kind or "unknown")
            metadata.setdefault("source_confidence", source_confidence or "unknown")
            metadata.setdefault("severity", severity or "unknown")
            metadata.setdefault("benign_scenario_type", benign_scenario_type or "unknown")
            metadata.setdefault("tuned_during_phase2_1", tuned_during_phase2_1 or "unknown")
            rows.append(
                {
                    "sample_id": _hash_id(domain, text, label, scenario),
                    "domain": domain,
                    "label": int(label),
                    "scenario": scenario,
                    "text": text,
                    "source_file": file_path.name,
                    "benchmark_group": benchmark_group or "unknown",
                    "source_kind": source_kind or "unknown",
                    "source_confidence": source_confidence or "unknown",
                    "severity": severity or "unknown",
                    "benign_scenario_type": benign_scenario_type or "unknown",
                    "tuned_during_phase2_1": tuned_during_phase2_1 or "unknown",
                    "metadata_json": _safe_json(metadata),
                    "split": _slug(record.get("split")) if record.get("split") else None,
                }
            )

    if not rows:
        raise ValueError(f"No valid rows found for domain '{domain}' under {raw_dir}")

    df = pd.DataFrame(rows).drop_duplicates(subset=["label", "scenario", "text"], keep="first")
    df = _apply_split(df, seed=seed)

    scenarios_present = sorted(set(df["scenario"].astype(str).tolist()))
    missing_scenarios = sorted(set(spec.required_scenarios) - set(scenarios_present))
    labels_present = sorted(set(int(v) for v in df["label"].tolist()))
    quality_passed = (labels_present == [0, 1]) and (len(missing_scenarios) == 0)
    if strict and not quality_passed:
        raise ValueError(
            f"Quality gate failed for {domain}: labels_present={labels_present}, missing_scenarios={missing_scenarios}"
        )

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    out_file = processed_dir / f"{domain}_corpus_{ts}.csv"
    latest_file = processed_dir / spec.output_name
    report_file = processed_dir / f"{domain}_corpus_report_{ts}.json"
    latest_report = processed_dir / f"{domain}_corpus_report_latest.json"

    df.to_csv(out_file, index=False)
    df.to_csv(latest_file, index=False)

    report = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_file_count": len(files),
        "total_rows": int(len(df)),
        "skipped_rows": int(skipped),
        "label_distribution": {str(k): int(v) for k, v in df["label"].value_counts().to_dict().items()},
        "split_distribution": {str(k): int(v) for k, v in df["split"].value_counts().to_dict().items()},
        "scenario_distribution": {str(k): int(v) for k, v in df["scenario"].value_counts().to_dict().items()},
        "benchmark_group_distribution": {
            str(k): int(v) for k, v in df["benchmark_group"].value_counts().to_dict().items()
        },
        "source_confidence_distribution": {
            str(k): int(v) for k, v in df["source_confidence"].value_counts().to_dict().items()
        },
        "source_kind_distribution": {
            str(k): int(v) for k, v in df["source_kind"].value_counts().to_dict().items()
        },
        "severity_distribution": {str(k): int(v) for k, v in df["severity"].value_counts().to_dict().items()},
        "tuned_during_phase2_1_distribution": {
            str(k): int(v) for k, v in df["tuned_during_phase2_1"].value_counts().to_dict().items()
        },
        "required_scenarios": list(spec.required_scenarios),
        "missing_scenarios": missing_scenarios,
        "quality_gate_passed": quality_passed,
        "artifacts": {
            "versioned_csv": str(out_file),
            "latest_csv": str(latest_file),
            "versioned_report": str(report_file),
            "latest_report": str(latest_report),
        },
    }
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    latest_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _default_corpus_root() -> Path:
    backend_root = Path(__file__).resolve().parents[1]
    return backend_root / "data" / "corpus"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build validated evaluation corpora for SQL, file, and phishing domains.")
    parser.add_argument("--domain", choices=["sql", "file", "phishing", "all"], default="all")
    parser.add_argument("--strict", action="store_true", help="Fail when quality gates are not satisfied.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--corpus-root", type=str, default=str(_default_corpus_root()))
    args = parser.parse_args()

    root = Path(args.corpus_root).resolve()
    domains = ["sql", "file", "phishing"] if args.domain == "all" else [args.domain]
    failed = False
    for domain in domains:
        try:
            report = build_domain_corpus(domain=domain, corpus_root=root, strict=args.strict, seed=args.seed)
            print(json.dumps({"domain": domain, "status": "ok", "quality_gate_passed": report["quality_gate_passed"], "total_rows": report["total_rows"]}))
        except Exception as exc:
            failed = True
            print(json.dumps({"domain": domain, "status": "error", "error": str(exc)}))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
