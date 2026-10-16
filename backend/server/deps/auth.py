from __future__ import annotations

import os
import secrets
from typing import Callable, Dict

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import DEFAULT_TENANT_ID, User
from backend.security.auth import decode_access_token, hash_password
from backend.security.request_context import set_current_role, set_current_tenant_id, sql_service_context

_bearer = HTTPBearer(auto_error=False)

_ROLE_ORDER: Dict[str, int] = {"viewer": 1, "reviewer": 2, "analyst": 3, "admin": 4}


def _oidc_auto_provision_enabled() -> bool:
    return str(os.getenv("AUTH_OIDC_AUTO_PROVISION", "false")).strip().lower() in {"1", "true", "yes", "on"}


def _extract_email_claim(payload: dict) -> str | None:
    for key in ("email", "upn", "preferred_username"):
        value = str(payload.get(key) or "").strip().lower()
        if value and "@" in value:
            return value
    return None


def _extract_full_name_claim(payload: dict) -> str | None:
    direct = str(payload.get("name") or "").strip()
    if direct:
        return direct

    given = str(payload.get("given_name") or "").strip()
    family = str(payload.get("family_name") or "").strip()
    composed = " ".join(part for part in [given, family] if part).strip()
    if composed:
        return composed

    nickname = str(payload.get("nickname") or "").strip()
    return nickname or None


def _extract_role_claim(payload: dict) -> str:
    # Highest role wins if multiple claims are present.
    candidates: list[str] = []
    role_direct = str(payload.get("role") or "").strip().lower()
    if role_direct:
        candidates.append(role_direct)

    roles_list = payload.get("roles")
    if isinstance(roles_list, str):
        candidates.append(roles_list.strip().lower())
    elif isinstance(roles_list, list):
        candidates.extend(str(item or "").strip().lower() for item in roles_list)

    realm_access = payload.get("realm_access")
    if isinstance(realm_access, dict):
        realm_roles = realm_access.get("roles")
        if isinstance(realm_roles, list):
            candidates.extend(str(item or "").strip().lower() for item in realm_roles)

    valid = [role for role in candidates if role in _ROLE_ORDER]
    if not valid:
        return "viewer"
    return sorted(valid, key=lambda r: _ROLE_ORDER.get(r, 0), reverse=True)[0]


def _extract_tenant_claim(payload: dict) -> str:
    value = str(payload.get("tenant_id") or "").strip()
    return value or DEFAULT_TENANT_ID


def resolve_user_from_token_payload(db: Session, payload: dict) -> User | None:
    # Token validation and WebSocket authentication can resolve users outside
    # HTTP middleware. This trusted context gives the SQL enforcer a service
    # identity while still requiring normal ORM parameterisation checks.
    with sql_service_context(
        "user_lookup_service",
        tenant_id=_extract_tenant_claim(payload),
        role=_extract_role_claim(payload),
    ):
        user: User | None = None
        subject = str(payload.get("sub") or "").strip()
        email = _extract_email_claim(payload)

        if subject:
            user = db.query(User).filter(User.id == subject).first()
        if user is None and email:
            user = db.query(User).filter(User.email == email).first()

        if user is None and email and _oidc_auto_provision_enabled():
            user = User(
                email=email,
                tenant_id=_extract_tenant_claim(payload),
                full_name=_extract_full_name_claim(payload),
                password_hash=hash_password(secrets.token_urlsafe(48)),
                role=_extract_role_claim(payload),
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        elif user is not None:
            tenant_id = str(getattr(user, "tenant_id", "") or "").strip()
            if not tenant_id:
                user.tenant_id = DEFAULT_TENANT_ID
                db.add(user)
                db.commit()
                db.refresh(user)

        return user


def get_current_user(
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> User:
    if credentials is None or (credentials.scheme or "").lower() != "bearer":
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid token")

    user = resolve_user_from_token_payload(db=db, payload=payload)
    if user is None or not bool(user.is_active):
        raise HTTPException(status_code=401, detail="User disabled or not found")

    role = (user.role or "").strip().lower()
    if role not in _ROLE_ORDER:
        raise HTTPException(status_code=401, detail="User role invalid")

    # Make role/tenant available to lower-level policy controls (e.g., SQL enforcer).
    try:
        set_current_role(role)
        set_current_tenant_id(str(getattr(user, "tenant_id", "") or DEFAULT_TENANT_ID))
    except Exception:
        pass

    return user


def require_role(min_role: str) -> Callable[[User], User]:
    required = (min_role or "").strip().lower()
    if required not in _ROLE_ORDER:
        raise ValueError(f"Unknown role: {min_role}")

    def _dep(current_user: User = Depends(get_current_user)) -> User:
        current = (current_user.role or "").strip().lower()
        if _ROLE_ORDER.get(current, 0) < _ROLE_ORDER[required]:
            raise HTTPException(status_code=403, detail="Forbidden")
        return current_user

    return _dep
