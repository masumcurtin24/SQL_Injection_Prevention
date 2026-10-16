from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
BENCHMARK_ROOT = BACKEND_ROOT / "data" / "benchmarks"
ROADMAP_ROOT = BENCHMARK_ROOT / "roadmap"
BASELINE_FILE = BENCHMARK_ROOT / "baselines" / "phase2_baseline_latest.json"
RUN_LATEST_SUMMARY = BENCHMARK_ROOT / "runs" / "latest" / "summary.json"


def _run_step(args: list[str], *, cwd: Path) -> Tuple[int, str, str]:
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _safe_load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _extract_last_json_blob(raw: str) -> Optional[Dict[str, Any]]:
    text = (raw or "").strip()
    if not text:
        return None
    # Harness currently emits one final JSON payload; parse line-wise fallback.
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for candidate in reversed(lines):
        if not candidate.startswith("{"):
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return None


def _metric_delta(current: Dict[str, Any], baseline: Dict[str, Any], key: str) -> Optional[float]:
    cur = current.get(key)
    base = baseline.get(key)
    if isinstance(cur, (int, float)) and isinstance(base, (int, float)):
        return float(cur) - float(base)
    return None


def _build_markdown(payload: Dict[str, Any]) -> str:
    run_id = payload.get("run_id")
    gate_passed = payload.get("gate_passed")
    sql_scope = payload.get("sql_scope")
    metrics = payload.get("metrics", {})
    analysis = metrics.get("analysis", {})
    enforcement = metrics.get("enforcement", {})
    deltas = payload.get("baseline_delta", {}).get("enforcement", {})
    lines = [
        f"# SQL Adversarial Regression Report ({run_id})",
        "",
        f"- Recorded at: `{payload.get('generated_at')}`",
        f"- SQL scope: `{sql_scope}`",
        f"- Gate passed: `{gate_passed}`",
        f"- Run dir: `{payload.get('run_dir')}`",
        "",
        "## Current Metrics",
        f"- analysis: precision={analysis.get('precision')} recall={analysis.get('recall')} f1={analysis.get('f1')} fpr={analysis.get('false_positive_rate')}",
        f"- enforcement: precision={enforcement.get('precision')} recall={enforcement.get('recall')} f1={enforcement.get('f1')} fpr={enforcement.get('false_positive_rate')}",
        "",
        "## Enforcement Delta vs Baseline",
        f"- delta_precision={deltas.get('precision')}",
        f"- delta_recall={deltas.get('recall')}",
        f"- delta_f1={deltas.get('f1')}",
        f"- delta_fpr={deltas.get('false_positive_rate')}",
        f"- delta_false_negative_count={deltas.get('false_negative_count')}",
        "",
    ]
    reasons = payload.get("gate_reasons") or []
    lines.append("## Gate Reasons")
    if reasons:
        lines.extend(f"- {str(r)}" for r in reasons)
    else:
        lines.append("- No gate failures.")
    lines.append("")
    return "\n".join(lines)


def run(sql_scope: str, strict_gate: bool) -> int:
    ROADMAP_ROOT.mkdir(parents=True, exist_ok=True)
    out_json = ROADMAP_ROOT / "sql_adversarial_regression_latest.json"
    out_md = ROADMAP_ROOT / "sql_adversarial_regression_latest.md"

    py = sys.executable
    build_cmd = [
        py,
        "backend/scripts/build_evaluation_corpus.py",
        "--domain",
        "sql",
        "--strict",
    ]
    bench_cmd = [
        py,
        "backend/scripts/run_benchmark_harness.py",
        "--domain",
        "sql",
        "--sql-scope",
        sql_scope,
        "--disable-transformer",
    ]
    if strict_gate:
        bench_cmd.append("--strict-gate")

    rc_build, out_build, err_build = _run_step(build_cmd, cwd=PROJECT_ROOT)
    if rc_build != 0:
        payload = {
            "status": "error",
            "stage": "build_evaluation_corpus",
            "return_code": rc_build,
            "stdout": out_build[-4000:],
            "stderr": err_build[-4000:],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        out_md.write_text("# SQL Adversarial Regression Report\n\n- Build step failed.\n", encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return rc_build

    rc_bench, out_bench, err_bench = _run_step(bench_cmd, cwd=PROJECT_ROOT)
    bench_meta = _extract_last_json_blob(out_bench) or {}
    latest_summary = _safe_load_json(RUN_LATEST_SUMMARY)
    baseline_summary = _safe_load_json(BASELINE_FILE)

    results = latest_summary.get("results", {}).get("sql", {})
    metrics = results.get("metrics", {})
    analysis = metrics.get("analysis", {}) if isinstance(metrics, dict) else {}
    enforcement = metrics.get("enforcement", {}) if isinstance(metrics, dict) else {}
    baseline_enforcement = (
        baseline_summary.get("results", {}).get("sql", {}).get("metrics", {}).get("enforcement", {})
    )

    delta_enforcement = {
        "precision": _metric_delta(enforcement, baseline_enforcement, "precision"),
        "recall": _metric_delta(enforcement, baseline_enforcement, "recall"),
        "f1": _metric_delta(enforcement, baseline_enforcement, "f1"),
        "false_positive_rate": _metric_delta(enforcement, baseline_enforcement, "false_positive_rate"),
        "false_negative_count": _metric_delta(enforcement, baseline_enforcement, "false_negative_count"),
    }

    payload = {
        "status": "ok" if rc_bench == 0 else "error",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sql_scope": sql_scope,
        "strict_gate": bool(strict_gate),
        "run_id": latest_summary.get("run_id") or bench_meta.get("run_id"),
        "run_dir": bench_meta.get("run_dir"),
        "gate_passed": bool(bench_meta.get("gate_passed", rc_bench == 0)),
        "gate_reasons": latest_summary.get("gate", {}).get("reasons", []),
        "metrics": {
            "analysis": analysis,
            "enforcement": enforcement,
        },
        "baseline_delta": {
            "enforcement": delta_enforcement,
        },
        "commands": {
            "build_corpus": " ".join(build_cmd),
            "benchmark": " ".join(bench_cmd),
        },
        "stderr_tail": err_bench[-4000:],
    }

    out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    out_md.write_text(_build_markdown(payload), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return rc_bench


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Roadmap step: run SQL adversarial regression and emit delta report.")
    p.add_argument(
        "--sql-scope",
        choices=["combined", "original", "held_out", "tuning", "regression"],
        default="combined",
        help="SQL benchmark scope to execute.",
    )
    p.add_argument(
        "--strict-gate",
        action="store_true",
        help="Enable strict quality gate failure behavior in benchmark harness.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    return run(sql_scope=str(args.sql_scope), strict_gate=bool(args.strict_gate))


if __name__ == "__main__":
    raise SystemExit(main())
