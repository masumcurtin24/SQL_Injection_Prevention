import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import AuditLog, User
from backend.server.deps.tenant import TenantContext, get_tenant_context
from backend.server.deps.policy import require_policy
from backend.server.schemas.configuration import (
    ConfigGetResponse,
    ConfigPatchResponse,
    GovernanceChangeEntry,
    GovernanceDomainSection,
    GovernanceOverviewResponse,
    SqlEnforcementPatch,
    SqlEnforcementRules,
)
from backend.services.file_analysis_service import FileAnalysisService
from backend.services.spam_detection_service import SpamDetectionService
from backend.utils.audit import write_audit
from backend.utils.logging_utils import setup_logger
from backend.utils.user_summary import build_user_summary_map

logger = setup_logger(__name__)
router = APIRouter()


def _rules_path() -> Path:
    return Path(__file__).resolve().parents[2] / "security" / "prevention_rules.yml"


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_rules_dict_and_raw(path: Path) -> tuple[Dict[str, Any], bytes]:
    if not path.exists():
        raise HTTPException(status_code=500, detail="prevention_rules.yml not found")
    raw = path.read_bytes()
    try:
        parsed = yaml.safe_load(raw.decode("utf-8")) or {}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Invalid YAML in prevention_rules.yml: {exc}")
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=500, detail="prevention_rules.yml must parse to a mapping")
    return parsed, raw


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)  # type: ignore[arg-type]
        else:
            out[key] = value
    return out


def _collect_changed_paths(before: Any, after: Any, prefix: str = "") -> List[str]:
    if isinstance(before, dict) and isinstance(after, dict):
        paths: List[str] = []
        keys = sorted(set(before.keys()) | set(after.keys()))
        for key in keys:
            child_prefix = f"{prefix}.{key}" if prefix else key
            if key not in before or key not in after:
                paths.append(child_prefix)
                continue
            paths.extend(_collect_changed_paths(before[key], after[key], child_prefix))
        return paths
    if isinstance(before, list) and isinstance(after, list):
        if before != after:
            return [prefix or "root"]
        return []
    if before != after:
        return [prefix or "root"]
    return []


def _env_overrides() -> Dict[str, str]:
    keys = [
        "SQL_ENFORCEMENT_MODE",
        "SQL_REQUIRE_PARAMETERIZATION",
        "SQL_DDL_EXEC_POLICY",
        "SQL_DDL_EXEC_ALLOWED_SERVICES",
        "SQL_DDL_EXEC_ALLOWLIST_PATTERNS",
        "SQL_ALLOWLIST_MODE",
        "SQL_ALLOWLIST_LAST_REVIEWED_AT",
        "ALLOWLIST_MAX_AGE_DAYS",
        "SQL_MONITOR_BACKOFF_N",
        "SQL_REQUIRE_SERVICE_CONTEXT",
        "SQL_TELEMETRY_FILE",
        "HEURISTICS_HIGH_THRESHOLD",
        "HEURISTICS_CRITICAL_CODES",
        "SQL_SECURE_CONSTRUCTION_MODE",
        "SQL_REQUIRE_APPROVED_RAW_SQL",
        "SQL_RAW_SQL_UNKNOWN_ACTION",
        "SQL_RAW_SQL_MIGRATION_SERVICE_PATTERN",
        "SQL_RAW_SQL_ALLOW_CONSTANT_SELECT",
    ]
    return {k: os.environ[k] for k in keys if k in os.environ}


def _safe_parse_details(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        return {"value": parsed}
    except Exception:
        return {"raw": raw}


def _section(data: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = data.get(key)
    if isinstance(value, dict):
        return value
    return {}


def _parse_optional_datetime(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _sql_construction_expiry_summary(sql_controls: Dict[str, Any], *, horizon_days: int = 30) -> Dict[str, Any]:
    sc = sql_controls.get("sql_construction")
    if not isinstance(sc, dict):
        return {
            "horizon_days": horizon_days,
            "approved_raw_sql": {"total": 0, "expired": [], "near_expiry": []},
            "raw_sql_exceptions": {"total": 0, "expired": [], "near_expiry": []},
        }
    now = datetime.now(timezone.utc)
    horizon = now + timedelta(days=max(1, int(horizon_days)))

    def _inspect(entries: Any) -> Dict[str, Any]:
        expired: List[str] = []
        near_expiry: List[str] = []
        total = 0
        if not isinstance(entries, list):
            return {"total": 0, "expired": expired, "near_expiry": near_expiry}
        for item in entries:
            if not isinstance(item, dict):
                continue
            total += 1
            expires_at = _parse_optional_datetime(item.get("expires_at"))
            if expires_at is None:
                continue
            item_id = str(item.get("id") or f"entry-{total}").strip()
            if expires_at < now:
                expired.append(item_id)
            elif expires_at <= horizon:
                near_expiry.append(item_id)
        return {"total": total, "expired": expired, "near_expiry": near_expiry}

    return {
        "horizon_days": horizon_days,
        "approved_raw_sql": _inspect(sc.get("approved_raw_sql")),
        "raw_sql_exceptions": _inspect(sc.get("raw_sql_exceptions")),
    }


def _yara_rules_metadata() -> Dict[str, Any]:
    rules_dir = Path(__file__).resolve().parents[2] / "yara_rules"
    files = sorted([f for f in rules_dir.glob("*.yar") if f.is_file()], key=lambda item: item.name.lower())
    latest_modified_at = None
    if files:
        latest_modified_at = datetime.fromtimestamp(
            max(item.stat().st_mtime for item in files),
            tz=timezone.utc,
        )
    return {
        "rules_dir": str(rules_dir),
        "rule_file_count": len(files),
        "rule_files": [item.name for item in files],
        "latest_modified_at": latest_modified_at,
    }


def _governance_changes(
    db: Session,
    tenant_id: str,
    limit: int = 20,
) -> List[GovernanceChangeEntry]:
    filters = [
        AuditLog.action.like("config.%"),
        AuditLog.action.like("spam.settings.%"),
        AuditLog.action.like("spam.blocklist.%"),
        AuditLog.action.like("spam.reputation.%"),
        AuditLog.action.like("spam.fraud_patterns.%"),
        AuditLog.action.like("defender.model.%"),
        AuditLog.action.like("defender.train.%"),
    ]
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.tenant_id == tenant_id)
        .filter(or_(*filters))
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )

    actor_map = build_user_summary_map(
        db=db,
        user_ids=[str(row.actor_user_id or "").strip() for row in rows],
        include_unknown=False,
    )
    changes: List[GovernanceChangeEntry] = []
    for row in rows:
        actor_user_id = str(row.actor_user_id or "").strip() or None
        changes.append(
            GovernanceChangeEntry(
                id=row.id,
                timestamp=row.timestamp,
                tenant_id=row.tenant_id,
                actor_user_id=actor_user_id,
                actor=actor_map.get(actor_user_id) if actor_user_id else None,
                action=row.action,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                success=bool(row.success),
                details=_safe_parse_details(row.details_json),
            )
        )
    return changes


@router.get(
    "/governance-overview",
    response_model=GovernanceOverviewResponse,
    summary="Unified governance view for SQL, file, email, and suppressions",
)
def get_governance_overview(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_policy("dashboard.access.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> GovernanceOverviewResponse:
    rules_path = _rules_path()
    rules, _ = _load_rules_dict_and_raw(rules_path)

    sql_controls = {
        "critical_patterns": rules.get("critical_patterns") or [],
        "ddl_exec": _section(rules, "ddl_exec"),
        "allowlist": _section(rules, "allowlist"),
        "monitor": _section(rules, "monitor"),
        "parameterization": _section(rules, "parameterization"),
        "service_context": _section(rules, "service_context"),
        "telemetry": _section(rules, "telemetry"),
        "sql_construction": _section(rules, "sql_construction"),
    }
    sql_expiry = _sql_construction_expiry_summary(sql_controls, horizon_days=30)
    file_controls = _section(rules, "file_detection")
    email_policy_defaults = _section(rules, "spam_detection")

    file_runtime_ready = False
    file_runtime_note = None
    try:
        file_service = FileAnalysisService.get_instance()
        file_runtime_ready = bool(file_service.are_resources_loaded())
    except Exception as exc:
        file_runtime_note = str(exc)
    file_metadata = _yara_rules_metadata()
    file_metadata["runtime_ready"] = file_runtime_ready

    email_runtime_settings: Dict[str, Any] = {}
    email_runtime_note = None
    try:
        spam_service = SpamDetectionService.get_instance()
        email_runtime_settings = spam_service.get_settings()
    except Exception as exc:
        email_runtime_note = str(exc)

    suppressions_controls = {
        "sql_allowlist": sql_controls.get("allowlist") or {},
        "sql_ddl_allowlist_patterns": (
            (sql_controls.get("ddl_exec") or {}).get("allowlist_patterns") or []
        ),
        "file_allow_domains": (file_controls.get("allow_domains") if isinstance(file_controls, dict) else {}) or {},
        "email_allowlist": {
            "path": email_runtime_settings.get("allowlist_path"),
            "count": email_runtime_settings.get("allowlist_count"),
        },
        "email_blocklist": {
            "path": email_runtime_settings.get("blocklist_path"),
            "count": email_runtime_settings.get("blocklist_count"),
        },
    }

    domains = {
        "sql": GovernanceDomainSection(
            support="editable",
            writable_actions=["config.sql_enforcement.patch"],
            controls=sql_controls,
            metadata={
                "policy_path": str(rules_path),
                "env_overrides": _env_overrides(),
                "restart_required": True,
                "scope": "global",
                "sql_construction_expiry": sql_expiry,
            },
            notes=[
                "SQL governance is editable through PATCH /config/sql-enforcement with step-up authentication.",
                "Approved raw SQL templates/exceptions include expiry visibility for governance review.",
            ],
        ),
        "file": GovernanceDomainSection(
            support="read_only",
            writable_actions=[],
            controls=file_controls,
            metadata=file_metadata,
            notes=[
                "File governance currently exposes active policy and signature metadata only.",
                "File rule promotion/write controls are not exposed as public config APIs yet.",
            ]
            + ([f"Runtime note: {file_runtime_note}"] if file_runtime_note else []),
        ),
        "email": GovernanceDomainSection(
            support="partially_supported",
            writable_actions=["spam.settings.update", "spam.blocklist.upload"],
            controls={
                "policy_defaults": email_policy_defaults,
                "runtime_settings": email_runtime_settings,
            },
            metadata={
                "settings_backed_by_runtime_service": bool(email_runtime_settings),
                "reputation_reload_supported": True,
                "reputation_update_supported": True,
                "fraud_pattern_reload_supported": True,
            },
            notes=[
                "Email settings, blocklist upload, and reputation reload/update are writable via spam governance APIs.",
                "Not all email governance values persist to YAML; some are runtime overrides.",
            ]
            + ([f"Runtime note: {email_runtime_note}"] if email_runtime_note else []),
        ),
        "suppressions": GovernanceDomainSection(
            support="partially_supported",
            writable_actions=[],
            controls=suppressions_controls,
            metadata={
                "exception_registry": "not_implemented",
                "suppression_policy_scope": "mixed",
            },
            notes=[
                "SQL allowlist patterns and email allow/block lists are available.",
                "Dedicated suppression/exception lifecycle APIs are not implemented yet.",
            ],
        ),
    }

    return GovernanceOverviewResponse(
        as_of=datetime.now(timezone.utc),
        scope="tenant",
        tenant_id=tenant_ctx.tenant_id,
        domains=domains,
        recent_changes=_governance_changes(db=db, tenant_id=tenant_ctx.tenant_id),
    )


@router.get("/sql-enforcement", response_model=ConfigGetResponse, summary="Read SQL enforcement YAML config")
def get_sql_enforcement_config(
    _current_user: User = Depends(require_policy("monitoring.read")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> ConfigGetResponse:
    path = _rules_path()
    rules, _ = _load_rules_dict_and_raw(path)
    return ConfigGetResponse(
        rules=rules,
        env_overrides=_env_overrides(),
        scope="global",
        tenant_id=tenant_ctx.tenant_id,
        restart_required=True,
    )


@router.patch("/sql-enforcement", response_model=ConfigPatchResponse, summary="Patch SQL enforcement YAML config")
def patch_sql_enforcement_config(
    payload: SqlEnforcementPatch,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_policy("config.sql_enforcement.patch")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> ConfigPatchResponse:
    path = _rules_path()
    before_rules, before_raw = _load_rules_dict_and_raw(path)
    before_hash = _sha256_bytes(before_raw)

    patch_dict = payload.model_dump(exclude_none=True)
    merged = _deep_merge(before_rules, patch_dict)

    # Strictly validate final config against known schema/keys only.
    validated = SqlEnforcementRules(**merged)
    merged_validated = validated.model_dump()
    changed_paths = _collect_changed_paths(before_rules, merged_validated)

    serialized = yaml.safe_dump(merged_validated, sort_keys=False, allow_unicode=False).encode("utf-8")
    after_hash = _sha256_bytes(serialized)

    tmp_path: Optional[str] = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="prevention_rules.", suffix=".yml", dir=str(path.parent))
        with os.fdopen(fd, "wb") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception as exc:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=f"Failed to persist config atomically: {exc}")

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="config.sql_enforcement.patch",
        resource_type="config",
        resource_id="sql-enforcement",
        details={
            "before_sha256": before_hash,
            "after_sha256": after_hash,
            "changed_paths": changed_paths,
            "scope": "global",
            "note": "Service restart required for changes to take effect.",
        },
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )

    logger.info("SQL enforcement config updated by user=%s; restart required.", current_user.id)
    return ConfigPatchResponse(
        rules=merged_validated,
        scope="global",
        tenant_id=tenant_ctx.tenant_id,
        before_sha256=before_hash,
        after_sha256=after_hash,
        changed_paths=changed_paths,
        restart_required=True,
    )
