from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import DefenderFeedback, User
from backend.server.deps.policy import require_policy
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.utils.telemetry import telemetry

router = APIRouter()


def _is_false_positive(domain: str, predicted_label: str, true_label: str) -> bool:
    d = str(domain or "").strip().lower()
    pred = str(predicted_label or "").strip().lower()
    true = str(true_label or "").strip().lower()
    if not pred or not true:
        return False

    if d == "sql":
        predicted_positive = any(token in pred for token in ["mal", "susp", "high", "critical"])
        true_positive = true.startswith("mal")
    elif d == "spam":
        predicted_positive = any(token in pred for token in ["spam", "phish", "junk"])
        true_positive = true == "spam"
    elif d == "file":
        predicted_positive = not any(token in pred for token in ["safe", "benign", "allow"])
        true_positive = not any(token in true for token in ["safe", "benign"])
    else:
        return False

    return bool(predicted_positive and not true_positive)


@router.get("/overview", summary="Telemetry overview (HTTP + websocket)")
def telemetry_overview(
    top: int = Query(20, ge=1, le=200),
    _user: User = Depends(require_policy("monitoring.read")),
):
    return telemetry.snapshot_overview(top=top)


@router.get("/http/endpoints", summary="Per-endpoint latency and error metrics")
def endpoint_metrics(
    top: int = Query(100, ge=1, le=500),
    _user: User = Depends(require_policy("monitoring.read")),
):
    return telemetry.snapshot_http(top=top)


@router.get("/websocket/health", summary="Websocket health and counters")
def websocket_health(_user: User = Depends(require_policy("monitoring.read"))):
    return telemetry.snapshot_ws()


@router.get("/false-positive-trends", summary="False-positive trends from analyst feedback")
def false_positive_trends(
    days: int = Query(30, ge=1, le=365),
    analyst_only: bool = Query(True, description="When true, include only human analyst feedback."),
    db: Session = Depends(get_db),
    _user: User = Depends(require_policy("monitoring.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
):
    today = datetime.now(timezone.utc).date()
    start_day = today - timedelta(days=days - 1)
    start_dt = datetime(start_day.year, start_day.month, start_day.day, tzinfo=timezone.utc)

    q = db.query(
        DefenderFeedback.domain,
        DefenderFeedback.timestamp,
        DefenderFeedback.predicted_label,
        DefenderFeedback.true_label,
        DefenderFeedback.source,
    ).filter(DefenderFeedback.tenant_id == tenant_ctx.tenant_id, DefenderFeedback.timestamp >= start_dt)
    if analyst_only:
        q = q.filter(DefenderFeedback.source == "human")
    rows = q.all()

    series_map: Dict[str, Dict[str, int]] = {}
    summary: Dict[str, Dict[str, int]] = {
        "sql": {"labeled": 0, "false_positives": 0},
        "spam": {"labeled": 0, "false_positives": 0},
        "file": {"labeled": 0, "false_positives": 0},
    }
    for i in range(days):
        day = start_day + timedelta(days=i)
        key = day.isoformat()
        series_map[key] = {"date": key, "sql": 0, "spam": 0, "file": 0, "total": 0}  # type: ignore[assignment]

    for domain, ts, predicted_label, true_label, _source in rows:
        domain_key = str(domain or "").strip().lower()
        if domain_key not in {"sql", "spam", "file"}:
            continue
        if not ts:
            continue
        day_key = ts.date().isoformat()
        if day_key not in series_map:
            continue

        summary[domain_key]["labeled"] += 1
        if _is_false_positive(domain_key, str(predicted_label or ""), str(true_label or "")):
            summary[domain_key]["false_positives"] += 1
            series_map[day_key][domain_key] += 1
            series_map[day_key]["total"] += 1

    by_domain = {}
    for key, vals in summary.items():
        labeled = int(vals.get("labeled") or 0)
        fp = int(vals.get("false_positives") or 0)
        by_domain[key] = {
            "labeled": labeled,
            "false_positives": fp,
            "false_positive_rate": (float(fp) / float(labeled)) if labeled else 0.0,
        }

    return {
        "time_period": f"last_{days}_days",
        "analyst_only": analyst_only,
        "series": [series_map[k] for k in sorted(series_map.keys())],
        "summary": by_domain,
    }
