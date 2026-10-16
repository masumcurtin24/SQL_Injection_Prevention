from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from sqlalchemy.orm import Session

from backend.core.models import User as UserModel


def _normalize_user_id(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def _masked_email_hint(email: str) -> str:
    raw = str(email or "").strip()
    if not raw:
        return ""
    if "@" not in raw:
        return raw
    local, domain = raw.split("@", 1)
    if not local:
        return f"***@{domain}"
    if len(local) <= 2:
        masked_local = f"{local[0]}***"
    else:
        masked_local = f"{local[:2]}***"
    return f"{masked_local}@{domain}"


def to_user_summary_payload(user: UserModel) -> Dict[str, Any]:
    full_name = str(user.full_name or "").strip() or None
    email_hint = _masked_email_hint(str(user.email or ""))
    display_name = full_name or email_hint or f"user-{str(user.id)[:8]}"
    return {
        "id": str(user.id),
        "display_name": display_name,
        "full_name": full_name,
        "role": str(user.role or "").strip() or None,
    }


def unknown_user_summary(user_id: str) -> Dict[str, Any]:
    normalized = _normalize_user_id(user_id) or "unknown"
    return {
        "id": normalized,
        "display_name": f"user-{normalized[:8]}",
        "full_name": None,
        "role": None,
    }


def build_user_summary_map(
    db: Session,
    user_ids: Iterable[Any],
    *,
    include_unknown: bool = False,
) -> Dict[str, Dict[str, Any]]:
    normalized_ids: list[str] = []
    seen: set[str] = set()
    for raw in user_ids:
        uid = _normalize_user_id(raw)
        if not uid or uid in seen:
            continue
        seen.add(uid)
        normalized_ids.append(uid)

    if not normalized_ids:
        return {}

    rows = db.query(UserModel).filter(UserModel.id.in_(normalized_ids)).all()
    mapping: Dict[str, Dict[str, Any]] = {str(row.id): to_user_summary_payload(row) for row in rows}

    if include_unknown:
        for uid in normalized_ids:
            mapping.setdefault(uid, unknown_user_summary(uid))

    return mapping
