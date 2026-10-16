from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional import fallback
    yaml = None

import yara


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_policy() -> Dict[str, Any]:
    return {
        "sources": [],
        "vetting": {
            "max_file_bytes": 600_000,
            "max_rules_per_file": 1_500,
        },
        "regression": {
            "benign_paths": [
                "backend/data/raw/files_for_analysis_training/benign_samples",
            ],
            "max_benign_files": 300,
            "max_bytes_per_file": 1_000_000,
            "staging": {
                "max_fp_files": 10,
                "max_total_matches": 50,
            },
            "canary": {
                "max_fp_files": 7,
                "max_total_matches": 30,
            },
            "promotion": {
                "max_fp_files": 5,
                "max_total_matches": 20,
            },
        },
        "promotion": {
            "active_prefix": "upstream_",
            "canary_max_files": 3,
        },
    }


def merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge_dict(out[k], v)
        else:
            out[k] = v
    return out


def load_policy(path: Path) -> Dict[str, Any]:
    policy = default_policy()
    if not path.exists():
        return policy
    if yaml is None:
        raise RuntimeError("PyYAML is required to load yara updater policy.")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"Invalid policy format in {path}")
    return merge_dict(policy, raw)


def resolve_paths(base: Path, values: Sequence[str]) -> List[Path]:
    out: List[Path] = []
    for item in values:
        p = Path(item)
        if not p.is_absolute():
            p = (base / p).resolve()
        out.append(p)
    return out


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sanitize_source_id(source_id: str) -> str:
    safe = []
    for ch in (source_id or "source"):
        if ch.isalnum() or ch in {"_", "-"}:
            safe.append(ch)
        else:
            safe.append("_")
    return "".join(safe)[:80] or "source"


def extract_rule_names(text: str) -> List[str]:
    import re

    names: List[str] = []
    patt = re.compile(r"^\s*(?:private\s+)?rule\s+([A-Za-z0-9_]+)\b", re.MULTILINE)
    for m in patt.finditer(text or ""):
        names.append(m.group(1))
    return names


def compile_rule_source(source: str) -> None:
    yara.compile(source=source)


def compile_rule_files(paths: Iterable[Path]) -> yara.Rules:
    filepaths: Dict[str, str] = {}
    for idx, p in enumerate(paths):
        filepaths[f"r{idx}_{p.name}"] = str(p)
    if not filepaths:
        raise ValueError("No YARA files provided for compilation.")
    return yara.compile(filepaths=filepaths)


def collect_benign_files(paths: Sequence[Path], *, max_files: int, max_bytes_per_file: int) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        if len(out) >= max_files:
            break
        if p.is_file():
            if p.stat().st_size <= max_bytes_per_file:
                out.append(p)
            continue
        if not p.exists() or not p.is_dir():
            continue
        for child in sorted(p.rglob("*")):
            if len(out) >= max_files:
                break
            if child.is_file() and child.stat().st_size <= max_bytes_per_file:
                out.append(child)
    return out


@dataclass
class FPRegressionResult:
    files_scanned: int
    fp_files: int
    total_matches: int
    top_rules: Dict[str, int]
    sample_hits: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "fp_files": self.fp_files,
            "total_matches": self.total_matches,
            "top_rules": self.top_rules,
            "sample_hits": self.sample_hits,
        }


def run_fp_regression(
    rules: yara.Rules,
    benign_files: Sequence[Path],
    *,
    max_bytes_per_file: int,
    sample_hit_limit: int = 20,
) -> FPRegressionResult:
    rule_counts: Dict[str, int] = {}
    sample_hits: List[Dict[str, Any]] = []
    fp_files = 0
    total_matches = 0

    for path in benign_files:
        try:
            data = path.read_bytes()[:max_bytes_per_file]
        except Exception:
            continue
        try:
            matches = rules.match(data=data)
        except Exception:
            continue
        if not matches:
            continue
        fp_files += 1
        total_matches += len(matches)
        names = [m.rule for m in matches]
        for name in names:
            rule_counts[name] = rule_counts.get(name, 0) + 1
        if len(sample_hits) < sample_hit_limit:
            sample_hits.append({"path": str(path), "rules": names[:10]})

    top_rules = dict(sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True)[:30])
    return FPRegressionResult(
        files_scanned=len(benign_files),
        fp_files=fp_files,
        total_matches=total_matches,
        top_rules=top_rules,
        sample_hits=sample_hits,
    )


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
