#!/usr/bin/env python3
"""
Stage upstream YARA updates with vetting and false-positive regression.

Outputs under backend/yara_rules/staging:
  - manifest.json
  - last_diff.json
  - regression_report.json
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.scripts.yara_updater_lib import (
    collect_benign_files,
    compile_rule_files,
    compile_rule_source,
    extract_rule_names,
    load_policy,
    resolve_paths,
    run_fp_regression,
    sanitize_source_id,
    sha256_bytes,
    utc_now_iso,
    write_json,
)


@dataclass
class CandidateFile:
    source_id: str
    name: str
    url: str
    upstream_sha: Optional[str] = None


def _http_get(url: str, *, token: Optional[str] = None, timeout: int = 30) -> bytes:
    headers = {
        "User-Agent": "defender-yara-updater/1.0",
        "Accept": "application/vnd.github+json,application/json,text/plain,*/*",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, headers=headers, method="GET")
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _github_repo_listing(source: Dict[str, Any], token: Optional[str]) -> List[CandidateFile]:
    repo = str(source.get("repo") or "").strip()
    directory = str(source.get("path") or "").strip()
    branch = str(source.get("branch") or "master").strip()
    if not repo or not directory:
        return []

    listing_url = f"https://api.github.com/repos/{repo}/contents/{directory}?ref={branch}"
    raw = _http_get(listing_url, token=token)
    payload = json.loads(raw.decode("utf-8", errors="replace"))
    if not isinstance(payload, list):
        return []

    include_patterns = [re.compile(p) for p in (source.get("include") or [])]
    exclude_patterns = [re.compile(p) for p in (source.get("exclude") or [])]
    max_files = int(source.get("max_files") or 50)
    source_id = sanitize_source_id(str(source.get("id") or repo.replace("/", "_")))
    out: List[CandidateFile] = []

    for item in payload:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "file":
            continue
        name = str(item.get("name") or "")
        if not name.endswith(".yar"):
            continue
        if include_patterns and not any(p.search(name) for p in include_patterns):
            continue
        if exclude_patterns and any(p.search(name) for p in exclude_patterns):
            continue
        download = str(item.get("download_url") or "")
        if not download:
            continue
        out.append(CandidateFile(source_id=source_id, name=name, url=download, upstream_sha=str(item.get("sha") or "")))
        if len(out) >= max_files:
            break
    return out


def _curated_files(source: Dict[str, Any]) -> List[CandidateFile]:
    source_id = sanitize_source_id(str(source.get("id") or "curated_source"))
    out: List[CandidateFile] = []
    for entry in (source.get("files") or []):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        url = str(entry.get("url") or "").strip()
        if not name or not url:
            continue
        out.append(
            CandidateFile(
                source_id=source_id,
                name=name,
                url=url,
                upstream_sha=str(entry.get("sha") or ""),
            )
        )
    return out


def list_candidates(source: Dict[str, Any], token: Optional[str]) -> List[CandidateFile]:
    if source.get("repo") and source.get("path"):
        return _github_repo_listing(source, token)
    return _curated_files(source)


def vet_candidate(content: bytes, *, max_file_bytes: int, max_rules_per_file: int) -> Dict[str, Any]:
    text = content.decode("utf-8", errors="replace")
    result: Dict[str, Any] = {"accepted": False, "reasons": [], "rule_count": 0}

    if len(content) > max_file_bytes:
        result["reasons"].append(f"file_too_large>{max_file_bytes}")
        return result

    names = extract_rule_names(text)
    result["rule_count"] = len(names)
    if not names:
        result["reasons"].append("no_rule_blocks")
        return result
    if len(names) > max_rules_per_file:
        result["reasons"].append(f"too_many_rules>{max_rules_per_file}")
        return result

    try:
        compile_rule_source(text)
    except Exception as exc:
        msg = str(exc)
        result["reasons"].append(f"compile_failed:{msg[:200]}")
        return result

    result["accepted"] = True
    return result


def flatten_manifest_entries(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    sources = manifest.get("sources") if isinstance(manifest, dict) else {}
    if not isinstance(sources, dict):
        return out
    for source_id, source_payload in sources.items():
        if not isinstance(source_payload, dict):
            continue
        files = source_payload.get("files")
        if not isinstance(files, dict):
            continue
        for filename, meta in files.items():
            out[f"{source_id}/{filename}"] = meta
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=str(ROOT / "backend" / "security" / "yara_updater_policy.yml"),
        help="Path to upstream policy YAML.",
    )
    parser.add_argument(
        "--staging-root",
        default=str(ROOT / "backend" / "yara_rules" / "staging"),
        help="Staging root path.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON summary only.")
    args = parser.parse_args()

    policy_path = Path(args.policy).resolve()
    staging_root = Path(args.staging_root).resolve()
    upstream_root = staging_root / "upstream"
    manifest_path = staging_root / "manifest.json"
    diff_path = staging_root / "last_diff.json"
    regression_path = staging_root / "regression_report.json"

    policy = load_policy(policy_path)
    token = os.getenv("GITHUB_TOKEN", "").strip() or None
    vetting = policy.get("vetting") or {}
    max_file_bytes = int(vetting.get("max_file_bytes") or 600_000)
    max_rules_per_file = int(vetting.get("max_rules_per_file") or 1_500)

    prev_manifest: Dict[str, Any] = {}
    if manifest_path.exists():
        try:
            prev_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            prev_manifest = {}

    new_manifest: Dict[str, Any] = {
        "generated_at": utc_now_iso(),
        "policy_path": str(policy_path),
        "sources": {},
        "summary": {"accepted_files": 0, "rejected_files": 0, "download_errors": 0},
    }

    sources = policy.get("sources") or []
    for source in sources:
        if not isinstance(source, dict):
            continue
        source_id = sanitize_source_id(str(source.get("id") or "source"))
        source_dir = upstream_root / source_id
        source_dir.mkdir(parents=True, exist_ok=True)
        source_manifest = {
            "description": source.get("description"),
            "files": {},
            "rejected": [],
            "errors": [],
        }
        candidates = list_candidates(source, token)

        for candidate in candidates:
            try:
                raw = _http_get(candidate.url, token=token)
            except (HTTPError, URLError, TimeoutError, ValueError) as exc:
                source_manifest["errors"].append({"name": candidate.name, "url": candidate.url, "error": str(exc)})
                new_manifest["summary"]["download_errors"] += 1
                continue

            vetted = vet_candidate(
                raw,
                max_file_bytes=max_file_bytes,
                max_rules_per_file=max_rules_per_file,
            )
            if not vetted.get("accepted"):
                source_manifest["rejected"].append(
                    {
                        "name": candidate.name,
                        "url": candidate.url,
                        "reasons": vetted.get("reasons") or [],
                    }
                )
                new_manifest["summary"]["rejected_files"] += 1
                continue

            out_path = source_dir / candidate.name
            out_path.write_text(raw.decode("utf-8", errors="replace"), encoding="utf-8")
            source_manifest["files"][candidate.name] = {
                "url": candidate.url,
                "upstream_sha": candidate.upstream_sha,
                "sha256": sha256_bytes(raw),
                "rule_count": int(vetted.get("rule_count") or 0),
                "staged_path": str(out_path),
                "staged_at": utc_now_iso(),
            }
            new_manifest["summary"]["accepted_files"] += 1

        new_manifest["sources"][source_id] = source_manifest

    # Remove orphaned staged files absent from the new manifest.
    keep_paths = set()
    for src_payload in new_manifest["sources"].values():
        files = src_payload.get("files") if isinstance(src_payload, dict) else {}
        if not isinstance(files, dict):
            continue
        for meta in files.values():
            if isinstance(meta, dict) and meta.get("staged_path"):
                keep_paths.add(str(meta["staged_path"]))
    if upstream_root.exists():
        for old in upstream_root.rglob("*.yar"):
            if str(old) not in keep_paths:
                try:
                    old.unlink()
                except Exception:
                    pass

    prev_flat = flatten_manifest_entries(prev_manifest)
    new_flat = flatten_manifest_entries(new_manifest)
    prev_keys = set(prev_flat.keys())
    new_keys = set(new_flat.keys())
    added = sorted(list(new_keys - prev_keys))
    removed = sorted(list(prev_keys - new_keys))
    updated = sorted(
        [
            key
            for key in (new_keys & prev_keys)
            if str(new_flat[key].get("sha256")) != str(prev_flat[key].get("sha256"))
        ]
    )
    unchanged = sorted([key for key in (new_keys & prev_keys) if key not in set(updated)])

    diff_payload = {
        "generated_at": utc_now_iso(),
        "added": added,
        "updated": updated,
        "removed": removed,
        "unchanged_count": len(unchanged),
    }

    # Compile staged rules + run benign regression.
    staged_files = sorted(upstream_root.rglob("*.yar")) if upstream_root.exists() else []
    regression_cfg = policy.get("regression") or {}
    benign_paths = resolve_paths(ROOT, [str(x) for x in (regression_cfg.get("benign_paths") or [])])
    max_benign_files = int(regression_cfg.get("max_benign_files") or 300)
    max_bytes_per_file = int(regression_cfg.get("max_bytes_per_file") or 1_000_000)
    benign_files = collect_benign_files(
        benign_paths,
        max_files=max_benign_files,
        max_bytes_per_file=max_bytes_per_file,
    )

    compile_error = None
    fp_result = None
    regression_pass = False
    if staged_files:
        try:
            rules = compile_rule_files(staged_files)
            fp_result = run_fp_regression(
                rules,
                benign_files,
                max_bytes_per_file=max_bytes_per_file,
            )
            stage_limits = (regression_cfg.get("staging") or {})
            max_fp_files = int(stage_limits.get("max_fp_files") or 10)
            max_total_matches = int(stage_limits.get("max_total_matches") or 50)
            regression_pass = (
                fp_result.fp_files <= max_fp_files
                and fp_result.total_matches <= max_total_matches
            )
        except Exception as exc:
            compile_error = str(exc)
    else:
        regression_pass = False
        compile_error = "no_staged_rules"

    regression_payload = {
        "generated_at": utc_now_iso(),
        "staged_rule_files": len(staged_files),
        "compile_error": compile_error,
        "regression_pass": regression_pass,
        "result": fp_result.to_dict() if fp_result else None,
        "thresholds": (regression_cfg.get("staging") or {}),
    }

    write_json(manifest_path, new_manifest)
    write_json(diff_path, diff_payload)
    write_json(regression_path, regression_payload)

    summary = {
        "manifest": str(manifest_path),
        "diff": str(diff_path),
        "regression": str(regression_path),
        "summary": new_manifest["summary"],
        "diff_counts": {
            "added": len(added),
            "updated": len(updated),
            "removed": len(removed),
        },
        "regression_pass": regression_pass,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(json.dumps(summary, indent=2))

    if not regression_pass:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
