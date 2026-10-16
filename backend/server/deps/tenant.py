from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from fastapi import Depends, HTTPException, Query, Request
from sqlalchemy.orm import Query as SAQuery
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import DEFAULT_TENANT_ID, Tenant, User
from backend.server.deps.auth import get_current_user


def normalize_tenant_id(value: Optional[str]) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def get_default_tenant_id() -> str:
    return DEFAULT_TENANT_ID


def resolve_user_tenant_id(user: User) -> str:
    return normalize_tenant_id(getattr(user, "tenant_id", None)) or get_default_tenant_id()


def ensure_tenant_exists(db: Session, tenant_id: str) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id, Tenant.is_active.is_(True)).first()
    if tenant is None:
        raise HTTPException(status_code=404, detail=f"Tenant not found or inactive: {tenant_id}")
    return tenant


@dataclass
class TenantContext:
    tenant_id: str
    requested_tenant_id: Optional[str]
    user_tenant_id: str
    user_role: str
    is_admin_scope: bool


def get_tenant_context(
    request: Request,
    tenant_id: Optional[str] = Query(None, description="Optional active tenant scope."),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TenantContext:
    header_tenant = normalize_tenant_id(request.headers.get("X-Tenant-ID"))
    query_tenant = normalize_tenant_id(tenant_id)
    requested = header_tenant or query_tenant

    role = str(getattr(current_user, "role", "") or "").strip().lower()
    user_tenant_id = resolve_user_tenant_id(current_user)

    if role == "admin":
        effective_tenant_id = requested or user_tenant_id
        ensure_tenant_exists(db, effective_tenant_id)
        return TenantContext(
            tenant_id=effective_tenant_id,
            requested_tenant_id=requested,
            user_tenant_id=user_tenant_id,
            user_role=role,
            is_admin_scope=True,
        )

    if requested and requested != user_tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden tenant scope")
    ensure_tenant_exists(db, user_tenant_id)
    return TenantContext(
        tenant_id=user_tenant_id,
        requested_tenant_id=requested,
        user_tenant_id=user_tenant_id,
        user_role=role,
        is_admin_scope=False,
    )


def list_accessible_tenants(db: Session, current_user: User) -> list[Tenant]:
    role = str(getattr(current_user, "role", "") or "").strip().lower()
    if role == "admin":
        return db.query(Tenant).filter(Tenant.is_active.is_(True)).order_by(Tenant.slug.asc()).all()
    tenant_id = resolve_user_tenant_id(current_user)
    row = db.query(Tenant).filter(Tenant.id == tenant_id, Tenant.is_active.is_(True)).first()
    return [row] if row is not None else []


def apply_tenant_filter(query: SAQuery, model: Any, tenant_id: Optional[str]) -> SAQuery:
    if not tenant_id:
        return query
    if hasattr(model, "tenant_id"):
        return query.filter(getattr(model, "tenant_id") == tenant_id)
    return query


def unique_non_empty(values: Iterable[Optional[str]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in values:
        value = normalize_tenant_id(raw)
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out

