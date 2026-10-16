from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.file_analysis_service import (
    DEFAULT_DYNAMIC_PROVIDER_VALIDATION_ARTIFACT,
    DYNAMIC_PROVIDER_DISABLED_NAMES,
    DYNAMIC_PROVIDER_READINESS_STATES,
)
from backend.services.file_dynamic.providers import create_dynamic_analysis_provider


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _build_provider_config(args: argparse.Namespace) -> Dict[str, Any]:
    provider = str(args.provider or "").strip().lower() or "none"
    if provider == "http":
        return {
            "base_url": str(args.http_base_url or "").strip(),
            "api_key": str(args.http_api_key or "").strip() or None,
            "submit_path": str(args.http_submit_path or "/v1/dynamic/submit").strip(),
            "status_path_template": str(
                args.http_status_path_template or "/v1/dynamic/status/{submission_id}"
            ).strip(),
            "result_path_template": str(
                args.http_result_path_template or "/v1/dynamic/result/{submission_id}"
            ).strip(),
            "timeout_seconds": _safe_float(args.http_timeout_seconds, 10.0),
            "verify_tls": not bool(args.http_insecure),
        }
    if provider == "fake":
        return {
            "completion_polls": max(0, int(args.fake_completion_polls)),
            "fail": bool(args.fake_fail),
            "failure_reason": str(args.fake_failure_reason or "provider_failed"),
        }
    return {}


def _readiness_state(*, provider_name: str, configured: bool, validated: bool) -> str:
    name = str(provider_name or "").strip().lower() or "none"
    if name in DYNAMIC_PROVIDER_DISABLED_NAMES:
        return "disabled"
    if name == "fake":
        return "fake"
    if not configured:
        return "misconfigured"
    return "live_validated" if validated else "live_not_validated"


async def _validate(provider_name: str, provider_config: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    provider = create_dynamic_analysis_provider(provider_name, provider_config)
    diagnostics = {}
    try:
        diagnostics = provider.diagnostics() if callable(getattr(provider, "diagnostics", None)) else {}
    except Exception as exc:
        diagnostics = {"configured": False, "available": False, "reason": f"diagnostics_error:{str(exc)[:120]}"}

    configured = bool(diagnostics.get("configured")) if "configured" in diagnostics else provider_name not in DYNAMIC_PROVIDER_DISABLED_NAMES
    available = bool(diagnostics.get("available")) if "available" in diagnostics else configured

    validation_payload: Dict[str, Any] = {
        "artifact_version": "file_dynamic_provider_validation_v1",
        "checked_at": _utcnow_iso(),
        "provider": str(provider_name or "none"),
        "provider_base_url": (
            (diagnostics.get("details") or {}).get("base_url")
            if isinstance(diagnostics.get("details"), dict)
            else None
        ),
        "diagnostics": diagnostics,
        "configured": configured,
        "available": available,
        "validated": False,
        "validation_state": "live_not_validated",
        "reason": None,
        "submit_probe": None,
        "status_probe": None,
        "result_probe": None,
    }

    if provider_name in DYNAMIC_PROVIDER_DISABLED_NAMES:
        validation_payload["validation_state"] = "disabled"
        validation_payload["reason"] = "provider_disabled"
        return validation_payload

    if provider_name == "fake":
        validation_payload["validation_state"] = "fake"
        validation_payload["reason"] = "fake_provider_is_not_live_validated"
        return validation_payload

    if not configured:
        validation_payload["validation_state"] = "misconfigured"
        validation_payload["reason"] = str(diagnostics.get("reason") or "provider_misconfigured")
        return validation_payload

    try:
        handle = await provider.submit(
            sample_ref=f"dynamic-provider-validation-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            sample_bytes=b"provider-validation-safe-sample",
            metadata={"filename": "provider-validation.txt", "purpose": "connectivity_validation_only"},
        )
        validation_payload["submit_probe"] = {
            "status": str(getattr(handle, "status", "") or "").strip().lower() or None,
            "submission_id": str(getattr(handle, "submission_id", "") or "").strip() or None,
            "message": str(getattr(handle, "message", "") or "").strip() or None,
            "submitted_at": (
                getattr(handle, "submitted_at", None).isoformat()
                if getattr(handle, "submitted_at", None) is not None
                else None
            ),
        }
    except Exception as exc:
        validation_payload["reason"] = f"submit_probe_failed:{str(exc)[:180]}"
        validation_payload["validation_state"] = "live_not_validated"
        return validation_payload

    submit_status = str((validation_payload["submit_probe"] or {}).get("status") or "").strip().lower()
    submission_id = str((validation_payload["submit_probe"] or {}).get("submission_id") or "").strip()
    if submit_status in {"failed", "unavailable"} or not submission_id:
        validation_payload["reason"] = (
            str((validation_payload["submit_probe"] or {}).get("message") or "") or "submit_probe_not_actionable"
        )
        validation_payload["validation_state"] = "live_not_validated"
        return validation_payload

    try:
        snap = await provider.get_status(submission_id)
        status_value = str(getattr(snap, "status", "") or "").strip().lower() or None
        validation_payload["status_probe"] = {
            "status": status_value,
            "updated_at": (
                getattr(snap, "updated_at", None).isoformat()
                if getattr(snap, "updated_at", None) is not None
                else None
            ),
            "failure_reason": str(getattr(snap, "failure_reason", "") or "").strip() or None,
        }
    except Exception as exc:
        validation_payload["reason"] = f"status_probe_failed:{str(exc)[:180]}"
        validation_payload["validation_state"] = "live_not_validated"
        return validation_payload

    status_value = str((validation_payload["status_probe"] or {}).get("status") or "").strip().lower()
    if status_value in {"failed", "unavailable"}:
        validation_payload["reason"] = (
            str((validation_payload["status_probe"] or {}).get("failure_reason") or "") or "status_probe_not_actionable"
        )
        validation_payload["validation_state"] = "live_not_validated"
        return validation_payload

    if status_value == "completed":
        try:
            result = await provider.fetch_result(submission_id)
            validation_payload["result_probe"] = {
                "status": str(getattr(result, "status", "") or "").strip().lower() or None,
                "summary": str(getattr(result, "summary", "") or "").strip() or None,
                "failure_reason": str(getattr(result, "failure_reason", "") or "").strip() or None,
                "ioc_count": len(list(getattr(result, "iocs", []) or [])),
                "evidence_count": len(list(getattr(result, "evidence_items", []) or [])),
            }
        except Exception as exc:
            validation_payload["reason"] = f"result_probe_failed:{str(exc)[:180]}"
            validation_payload["validation_state"] = "live_not_validated"
            return validation_payload

    validation_payload["validated"] = True
    validation_payload["validation_state"] = "live_validated"
    validation_payload["reason"] = "submit_and_status_probe_successful"
    validation_payload["validation_state"] = _readiness_state(
        provider_name=provider_name,
        configured=configured,
        validated=bool(validation_payload["validated"]),
    )
    return validation_payload


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate dynamic file-analysis provider readiness without local detonation.",
    )
    parser.add_argument("--provider", type=str, default=os.getenv("FILE_DYNAMIC_PROVIDER", "none"))
    parser.add_argument(
        "--artifact-path",
        type=str,
        default=str(DEFAULT_DYNAMIC_PROVIDER_VALIDATION_ARTIFACT),
        help="Path for latest provider validation artifact JSON.",
    )
    parser.add_argument("--strict", action="store_true", help="Exit non-zero unless validation_state=live_validated.")

    parser.add_argument("--fake-completion-polls", type=int, default=1)
    parser.add_argument("--fake-fail", action="store_true")
    parser.add_argument("--fake-failure-reason", type=str, default="provider_failed")

    parser.add_argument("--http-base-url", type=str, default=os.getenv("FILE_DYNAMIC_HTTP_BASE_URL", ""))
    parser.add_argument("--http-api-key", type=str, default=os.getenv("FILE_DYNAMIC_HTTP_API_KEY", ""))
    parser.add_argument("--http-submit-path", type=str, default=os.getenv("FILE_DYNAMIC_HTTP_SUBMIT_PATH", "/v1/dynamic/submit"))
    parser.add_argument(
        "--http-status-path-template",
        type=str,
        default=os.getenv("FILE_DYNAMIC_HTTP_STATUS_PATH_TEMPLATE", "/v1/dynamic/status/{submission_id}"),
    )
    parser.add_argument(
        "--http-result-path-template",
        type=str,
        default=os.getenv("FILE_DYNAMIC_HTTP_RESULT_PATH_TEMPLATE", "/v1/dynamic/result/{submission_id}"),
    )
    parser.add_argument(
        "--http-timeout-seconds",
        type=float,
        default=_safe_float(os.getenv("FILE_DYNAMIC_HTTP_TIMEOUT_SECONDS", "10"), 10.0),
    )
    parser.add_argument("--http-insecure", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    provider_name = str(args.provider or "none").strip().lower() or "none"
    provider_config = _build_provider_config(args)
    result = asyncio.run(_validate(provider_name, provider_config, args))

    validation_state = str(result.get("validation_state") or "").strip().lower()
    if validation_state not in DYNAMIC_PROVIDER_READINESS_STATES:
        result["validation_state"] = "live_not_validated"

    artifact_path = Path(args.artifact_path).resolve()
    _write_json(artifact_path, result)
    history_dir = artifact_path.parent / "history"
    history_name = f"file_dynamic_provider_validation_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.json"
    _write_json(history_dir / history_name, result)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.strict and str(result.get("validation_state") or "") != "live_validated":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
