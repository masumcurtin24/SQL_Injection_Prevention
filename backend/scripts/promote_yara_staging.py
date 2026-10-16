#!/usr/bin/env python3
"""
Promote staged YARA rules into active rules directory after regression checks.

Default mode is dry-run (no file changes). Use --execute to perform promotion.
When executing, a canary subset is promoted first and verified. Any gate failure
triggers automatic rollback of touched files.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.scripts.yara_updater_lib import (
    collect_benign_files,
    compile_rule_files,
    load_policy,
    resolve_paths,
    run_fp_regression,
    sanitize_source_id,
    sha256_file,
    utc_now_iso,
    write_json,
)


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _collect_staged_from_manifest(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    sources = manifest.get("sources") if isinstance(manifest, dict) else {}
    if not isinstance(sources, dict):
        return out
    for source_id, payload in sources.items():
        if not isinstance(payload, dict):
            continue
        files = payload.get("files")
        if not isinstance(files, dict):
            continue
        for name, meta in files.items():
            if not isinstance(meta, dict):
                continue
            staged_path = str(meta.get("staged_path") or "")
            if not staged_path:
                continue
            out.append(
                {
                    "source_id": sanitize_source_id(str(source_id)),
                    "name": str(name),
                    "sha256": meta.get("sha256"),
                    "staged_path": staged_path,
                }
            )
    out.sort(key=lambda x: (str(x.get("source_id") or ""), str(x.get("name") or "")))
    return out


def _resolve_canary_count(total_staged: int, promotion_cfg: Dict[str, Any], arg_canary_count: Optional[int]) -> int:
    if total_staged <= 0:
        return 0
    if arg_canary_count is not None:
        return max(0, min(total_staged, int(arg_canary_count)))
    cfg_count = promotion_cfg.get("canary_max_files")
    if cfg_count is None:
        return min(3, total_staged)
    try:
        return max(0, min(total_staged, int(cfg_count)))
    except Exception:
        return min(3, total_staged)


def _run_regression(
    *,
    rule_files: List[Path],
    benign_files: List[Path],
    max_bytes_per_file: int,
    thresholds: Dict[str, Any],
) -> Dict[str, Any]:
    compile_error = None
    result = None
    gate_pass = False
    try:
        rules = compile_rule_files(rule_files)
        fp_result = run_fp_regression(
            rules,
            benign_files,
            max_bytes_per_file=max_bytes_per_file,
        )
        result = fp_result.to_dict()
        max_fp_files = int(thresholds.get("max_fp_files") or 0)
        max_total_matches = int(thresholds.get("max_total_matches") or 0)
        gate_pass = (
            fp_result.fp_files <= max_fp_files
            and fp_result.total_matches <= max_total_matches
        )
    except Exception as exc:
        compile_error = str(exc)
    return {
        "pass": gate_pass,
        "compile_error": compile_error,
        "result": result,
        "thresholds": thresholds,
        "candidate_rule_files": len(rule_files),
    }


def _ensure_backup(dest: Path, backup_dir: Path, backup_map: Dict[str, Optional[str]]) -> None:
    key = str(dest.resolve())
    if key in backup_map:
        return
    if dest.exists():
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"{len(backup_map):04d}__{dest.name}"
        shutil.copy2(dest, backup_path)
        backup_map[key] = str(backup_path.resolve())
    else:
        backup_map[key] = None


def _apply_entries(
    *,
    entries: List[Dict[str, Any]],
    rules_dir: Path,
    active_prefix: str,
    backup_dir: Path,
    backup_map: Dict[str, Optional[str]],
) -> List[Dict[str, Any]]:
    promoted: List[Dict[str, Any]] = []
    for entry in entries:
        src = Path(str(entry["staged_path"])).resolve()
        source_id = sanitize_source_id(str(entry["source_id"]))
        filename = str(entry["name"])
        dest_name = f"{active_prefix}{source_id}__{filename}"
        dest = rules_dir / dest_name

        _ensure_backup(dest, backup_dir, backup_map)

        changed = True
        if dest.exists():
            try:
                changed = sha256_file(dest) != sha256_file(src)
            except Exception:
                changed = True
        if changed:
            shutil.copy2(src, dest)

        promoted.append(
            {
                "dest": str(dest),
                "source": str(src),
                "sha256": sha256_file(dest),
                "changed": changed,
            }
        )
    return promoted


def _apply_remove_missing(
    *,
    prior_map: Dict[str, Any],
    keep_dest_paths: List[str],
    backup_dir: Path,
    backup_map: Dict[str, Optional[str]],
) -> List[str]:
    removed: List[str] = []
    keep = set(str(Path(p).resolve()) for p in keep_dest_paths)
    for dest_path in prior_map.keys():
        dp = Path(dest_path)
        if str(dp.resolve()) in keep:
            continue
        if not dp.exists():
            continue
        _ensure_backup(dp, backup_dir, backup_map)
        try:
            dp.unlink()
            removed.append(str(dp))
        except Exception:
            continue
    return removed


def _rollback_from_backups(backup_map: Dict[str, Optional[str]]) -> Dict[str, int]:
    restored = 0
    deleted = 0
    for dest_str, backup_str in backup_map.items():
        dest = Path(dest_str)
        if backup_str:
            backup = Path(backup_str)
            if backup.exists():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup, dest)
                restored += 1
        else:
            if dest.exists():
                try:
                    dest.unlink()
                    deleted += 1
                except Exception:
                    pass
    return {"restored_files": restored, "deleted_new_files": deleted}


def _active_rule_files(rules_dir: Path) -> List[Path]:
    return sorted([p for p in rules_dir.glob("*.yar") if p.is_file()])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=str(ROOT / "backend" / "security" / "yara_updater_policy.yml"),
        help="Path to updater policy YAML.",
    )
    parser.add_argument(
        "--staging-root",
        default=str(ROOT / "backend" / "yara_rules" / "staging"),
        help="Staging root path.",
    )
    parser.add_argument(
        "--rules-dir",
        default=str(ROOT / "backend" / "yara_rules"),
        help="Active YARA rules directory.",
    )
    parser.add_argument("--execute", action="store_true", help="Apply promotion changes.")
    parser.add_argument(
        "--remove-missing",
        action="store_true",
        help="Remove previously promoted upstream files that are no longer in staging.",
    )
    parser.add_argument(
        "--canary-count",
        type=int,
        default=None,
        help="Number of staged files to promote in canary phase before full promotion.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON summary.")
    args = parser.parse_args()

    policy = load_policy(Path(args.policy).resolve())
    staging_root = Path(args.staging_root).resolve()
    rules_dir = Path(args.rules_dir).resolve()
    manifest_path = staging_root / "manifest.json"
    promotion_report_path = staging_root / "promotion_report.json"
    promoted_manifest_path = rules_dir / "upstream_promoted_manifest.json"
    rollback_dir = staging_root / "rollback"

    staging_manifest = _load_json(manifest_path)
    staged_entries = _collect_staged_from_manifest(staging_manifest)
    if not staged_entries:
        summary = {"error": "no_staged_entries", "manifest": str(manifest_path)}
        print(json.dumps(summary, indent=2))
        return 2

    regression_cfg = policy.get("regression") or {}
    benign_paths = resolve_paths(ROOT, [str(x) for x in (regression_cfg.get("benign_paths") or [])])
    max_benign_files = int(regression_cfg.get("max_benign_files") or 300)
    max_bytes_per_file = int(regression_cfg.get("max_bytes_per_file") or 1_000_000)
    benign_files = collect_benign_files(
        benign_paths,
        max_files=max_benign_files,
        max_bytes_per_file=max_bytes_per_file,
    )

    promotion_cfg = policy.get("promotion") or {}
    active_prefix = str(promotion_cfg.get("active_prefix") or "upstream_")
    canary_thresholds = regression_cfg.get("canary") or regression_cfg.get("promotion") or {}
    promotion_thresholds = regression_cfg.get("promotion") or {}

    # Pre-check gate: compile active + all staged before any write operation.
    precheck_files = _active_rule_files(rules_dir) + [Path(e["staged_path"]).resolve() for e in staged_entries]
    precheck = _run_regression(
        rule_files=precheck_files,
        benign_files=benign_files,
        max_bytes_per_file=max_bytes_per_file,
        thresholds=promotion_thresholds,
    )
    promotion_pass = bool(precheck["pass"])

    promoted_files: List[Dict[str, Any]] = []
    removed_files: List[str] = []
    canary_report: Optional[Dict[str, Any]] = None
    post_apply_report: Optional[Dict[str, Any]] = None
    rollback_summary: Optional[Dict[str, int]] = None
    rollback_backup_dir: Optional[str] = None
    rolled_back = False

    prior_promoted = _load_json(promoted_manifest_path)
    prior_map = prior_promoted.get("files") if isinstance(prior_promoted, dict) else {}
    if not isinstance(prior_map, dict):
        prior_map = {}

    if promotion_pass and args.execute:
        backup_map: Dict[str, Optional[str]] = {}
        run_id = f"rollback_{datetime_safe_token()}"
        run_backup_dir = rollback_dir / run_id
        rollback_backup_dir = str(run_backup_dir)

        canary_count = _resolve_canary_count(len(staged_entries), promotion_cfg, args.canary_count)
        canary_entries = staged_entries[:canary_count]
        remaining_entries = staged_entries[canary_count:]

        # 1) Apply canary subset
        canary_promoted = _apply_entries(
            entries=canary_entries,
            rules_dir=rules_dir,
            active_prefix=active_prefix,
            backup_dir=run_backup_dir,
            backup_map=backup_map,
        )
        promoted_files.extend(canary_promoted)

        active_after_canary = _active_rule_files(rules_dir)
        canary_report = _run_regression(
            rule_files=active_after_canary,
            benign_files=benign_files,
            max_bytes_per_file=max_bytes_per_file,
            thresholds=canary_thresholds,
        )
        if not canary_report["pass"]:
            rollback_summary = _rollback_from_backups(backup_map)
            rolled_back = True
            promotion_pass = False
        else:
            # 2) Apply remaining entries
            remaining_promoted = _apply_entries(
                entries=remaining_entries,
                rules_dir=rules_dir,
                active_prefix=active_prefix,
                backup_dir=run_backup_dir,
                backup_map=backup_map,
            )
            promoted_files.extend(remaining_promoted)

            # Optional prune of no-longer-staged files after canary passes.
            if args.remove_missing:
                keep_dest_paths = [row["dest"] for row in promoted_files]
                removed_files = _apply_remove_missing(
                    prior_map=prior_map,
                    keep_dest_paths=keep_dest_paths,
                    backup_dir=run_backup_dir,
                    backup_map=backup_map,
                )

            # 3) Final verify gate
            active_after_full = _active_rule_files(rules_dir)
            post_apply_report = _run_regression(
                rule_files=active_after_full,
                benign_files=benign_files,
                max_bytes_per_file=max_bytes_per_file,
                thresholds=promotion_thresholds,
            )
            if not post_apply_report["pass"]:
                rollback_summary = _rollback_from_backups(backup_map)
                rolled_back = True
                promotion_pass = False
            else:
                promoted_manifest = {
                    "generated_at": utc_now_iso(),
                    "staging_manifest": str(manifest_path),
                    "files": {row["dest"]: row for row in promoted_files},
                }
                write_json(promoted_manifest_path, promoted_manifest)

    report = {
        "generated_at": utc_now_iso(),
        "execute": bool(args.execute),
        "precheck_pass": bool(precheck["pass"]),
        "promotion_pass": bool(promotion_pass),
        "compile_error": precheck["compile_error"],
        "candidate_rule_files": precheck["candidate_rule_files"],
        "staged_files": len(staged_entries),
        "result": precheck["result"],
        "thresholds": promotion_thresholds,
        "canary": canary_report,
        "post_apply": post_apply_report,
        "rolled_back": rolled_back,
        "rollback_summary": rollback_summary,
        "rollback_backup_dir": rollback_backup_dir,
        "promoted_files": promoted_files,
        "removed_files": removed_files,
        "promoted_manifest": str(promoted_manifest_path),
    }
    write_json(promotion_report_path, report)

    print(json.dumps(report, indent=2))

    if not promotion_pass:
        return 2
    return 0


def datetime_safe_token() -> str:
    return utc_now_iso().replace(":", "").replace("-", "").replace(".", "").replace("+", "_")


if __name__ == "__main__":
    raise SystemExit(main())
