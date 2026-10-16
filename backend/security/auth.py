import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import hmac
import hashlib
import secrets

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from backend.security.oidc import is_oidc_enabled, verify_oidc_access_token
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)

_password_hasher = PasswordHasher()
_MIN_JWT_SECRET_LENGTH = 32


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def _get_jwt_secret_key() -> str:
    secret = os.getenv("JWT_SECRET_KEY", "").strip()
    if not secret:
        raise RuntimeError("JWT_SECRET_KEY must be set in the environment.")
    if len(secret) < _MIN_JWT_SECRET_LENGTH:
        raise RuntimeError(
            f"JWT_SECRET_KEY must be at least {_MIN_JWT_SECRET_LENGTH} characters."
        )
    return secret


def _get_jwt_algorithm() -> str:
    return os.getenv("JWT_ALGORITHM", "HS256").strip() or "HS256"


def _get_access_token_exp_minutes() -> int:
    try:
        return int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60").strip() or "60")
    except Exception:
        return 60


def _get_refresh_token_exp_days() -> int:
    try:
        value = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "14").strip() or "14")
        if value < 1:
            return 1
        if value > 90:
            return 90
        return value
    except Exception:
        return 14


def _get_step_up_token_exp_minutes() -> int:
    try:
        value = int(os.getenv("JWT_STEP_UP_TOKEN_EXPIRE_MINUTES", "10").strip() or "10")
        if value < 1:
            return 1
        if value > 60:
            return 60
        return value
    except Exception:
        return 10


def create_access_token(
    user_id: str,
    role: str,
    email: str,
    tenant_id: Optional[str] = None,
    exp: Optional[datetime] = None,
) -> Tuple[str, int]:
    exp_dt = exp or (datetime.now(timezone.utc) + timedelta(minutes=_get_access_token_exp_minutes()))
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "email": email,
        "tenant_id": str(tenant_id or "").strip() or None,
        "iat": int(now.timestamp()),
        "exp": int(exp_dt.timestamp()),
        "type": "access",
    }
    token = jwt.encode(payload, _get_jwt_secret_key(), algorithm=_get_jwt_algorithm())
    expires_in = max(int(exp_dt.timestamp() - now.timestamp()), 0)
    return token, expires_in


def decode_access_token(token: str) -> Dict[str, Any]:
    if is_oidc_enabled():
        return verify_oidc_access_token(token)
    payload = jwt.decode(token, _get_jwt_secret_key(), algorithms=[_get_jwt_algorithm()])
    if str(payload.get("type") or "").strip().lower() != "access":
        raise jwt.InvalidTokenError("Invalid token type")
    return payload


def create_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    secret = _get_jwt_secret_key().encode("utf-8")
    digest = hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest


def get_refresh_token_expiry(now: Optional[datetime] = None) -> datetime:
    base = now or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return base + timedelta(days=_get_refresh_token_exp_days())


def create_step_up_token(
    user_id: str,
    role: str,
    email: str,
    tenant_id: Optional[str] = None,
    actions: Optional[List[str]] = None,
    exp: Optional[datetime] = None,
) -> Tuple[str, int]:
    normalized_actions: List[str] = []
    for action in actions or []:
        value = str(action or "").strip()
        if not value:
            continue
        if value not in normalized_actions:
            normalized_actions.append(value)
    if not normalized_actions:
        normalized_actions = ["*"]

    exp_dt = exp or (datetime.now(timezone.utc) + timedelta(minutes=_get_step_up_token_exp_minutes()))
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "email": email,
        "tenant_id": str(tenant_id or "").strip() or None,
        "actions": normalized_actions,
        "auth_time": int(now.timestamp()),
        "iat": int(now.timestamp()),
        "exp": int(exp_dt.timestamp()),
        "type": "step_up",
    }
    token = jwt.encode(payload, _get_jwt_secret_key(), algorithm=_get_jwt_algorithm())
    expires_in = max(int(exp_dt.timestamp() - now.timestamp()), 0)
    return token, expires_in


def decode_step_up_token(token: str) -> Dict[str, Any]:
    payload = jwt.decode(token, _get_jwt_secret_key(), algorithms=[_get_jwt_algorithm()])
    if str(payload.get("type") or "").strip().lower() != "step_up":
        raise jwt.InvalidTokenError("Invalid token type")
    return payload
