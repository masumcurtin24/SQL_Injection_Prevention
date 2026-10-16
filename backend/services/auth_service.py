from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import uuid
from typing import Any, Dict, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from backend.core.models import DEFAULT_TENANT_ID, AuthSession, User
from backend.security.auth import (
    create_access_token,
    create_refresh_token,
    get_refresh_token_expiry,
    hash_refresh_token,
)
from backend.security.request_context import sql_service_context
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


@dataclass
class AuthRefreshError(Exception):
    detail: str
    reason: str = "invalid_refresh_token"


class AuthService:
    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _to_utc(value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _client_ip(request: Optional[Request]) -> Optional[str]:
        if request is None:
            return None
        try:
            return str(request.client.host) if request.client and request.client.host else None
        except Exception:
            return None

    @staticmethod
    def _user_agent(request: Optional[Request]) -> Optional[str]:
        if request is None:
            return None
        try:
            value = str(request.headers.get("user-agent") or "").strip()
            return value or None
        except Exception:
            return None

    @classmethod
    def _new_session(
        cls,
        user_id: str,
        family_id: str,
        refresh_token_hash: str,
        expires_at: datetime,
        request: Optional[Request],
    ) -> AuthSession:
        now = cls._now()
        return AuthSession(
            id=str(uuid.uuid4()),
            family_id=family_id,
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            status="active",
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            last_used_at=now,
            ip=cls._client_ip(request),
            user_agent=cls._user_agent(request),
        )

    @classmethod
    def _issue_access_refresh_bundle(
        cls,
        db: Session,
        user: User,
        request: Optional[Request],
        family_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = cls._now()
        refresh_token = create_refresh_token()
        refresh_hash = hash_refresh_token(refresh_token)
        expires_at = get_refresh_token_expiry(now)

        session_id = str(uuid.uuid4())
        effective_family_id = family_id or session_id
        session = AuthSession(
            id=session_id,
            family_id=effective_family_id,
            user_id=user.id,
            tenant_id=str(getattr(user, "tenant_id", "") or DEFAULT_TENANT_ID),
            refresh_token_hash=refresh_hash,
            status="active",
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            last_used_at=now,
            ip=cls._client_ip(request),
            user_agent=cls._user_agent(request),
        )
        db.add(session)

        access_token, expires_in = create_access_token(
            user_id=user.id,
            role=user.role,
            email=user.email,
            tenant_id=getattr(user, "tenant_id", None),
            exp=None,
        )
        refresh_expires_in = max(int(expires_at.timestamp() - now.timestamp()), 0)
        return {
            "access_token": access_token,
            "access_expires_in": expires_in,
            "refresh_token": refresh_token,
            "refresh_expires_in": refresh_expires_in,
            "session_id": session.id,
            "family_id": session.family_id,
        }

    @classmethod
    def issue_login_tokens(cls, db: Session, user: User, request: Optional[Request]) -> Dict[str, Any]:
        with sql_service_context(
            "auth_service",
            tenant_id=str(getattr(user, "tenant_id", "") or DEFAULT_TENANT_ID),
            role=str(getattr(user, "role", "") or ""),
        ):
            try:
                bundle = cls._issue_access_refresh_bundle(db=db, user=user, request=request, family_id=None)
                db.commit()
                return bundle
            except Exception:
                db.rollback()
                logger.exception("Failed issuing login tokens")
                raise

    @classmethod
    def _revoke_family(
        cls,
        db: Session,
        family_id: str,
        reason: str,
    ) -> int:
        if not family_id:
            return 0
        now = cls._now()
        sessions = db.query(AuthSession).filter(AuthSession.family_id == family_id).all()
        updated = 0
        for session in sessions:
            if session.status != "revoked" or session.revoked_at is None:
                session.status = "revoked"
                session.revoked_at = now
                session.revoke_reason = reason
                session.updated_at = now
                db.add(session)
                updated += 1
        return updated

    @classmethod
    def refresh_tokens(cls, db: Session, refresh_token: str, request: Optional[Request]) -> Dict[str, Any]:
        with sql_service_context("auth_service"):
            token_value = str(refresh_token or "").strip()
            if not token_value:
                raise AuthRefreshError(detail="Refresh token is required.", reason="missing_refresh_token")

            try:
                token_hash = hash_refresh_token(token_value)
            except Exception:
                raise AuthRefreshError(detail="Invalid refresh token.", reason="invalid_refresh_token")

            session = db.query(AuthSession).filter(AuthSession.refresh_token_hash == token_hash).first()
            if session is None:
                raise AuthRefreshError(detail="Invalid refresh token.", reason="invalid_refresh_token")

            now = cls._now()
            expires_at_utc = cls._to_utc(session.expires_at)
            if expires_at_utc is not None and expires_at_utc <= now:
                if session.status == "active":
                    session.status = "revoked"
                    session.revoked_at = now
                    session.revoke_reason = "expired"
                    session.updated_at = now
                    db.add(session)
                    db.commit()
                raise AuthRefreshError(detail="Refresh token expired.", reason="expired_refresh_token")

            if session.status != "active" or session.revoked_at is not None:
                try:
                    cls._revoke_family(db=db, family_id=session.family_id, reason="reuse_detected")
                    db.commit()
                except Exception:
                    db.rollback()
                raise AuthRefreshError(
                    detail="Refresh token reuse detected. Please login again.",
                    reason="refresh_token_reuse_detected",
                )

            user = db.query(User).filter(User.id == str(session.user_id)).first()
            if user is None or not bool(user.is_active):
                session.status = "revoked"
                session.revoked_at = now
                session.revoke_reason = "user_disabled_or_not_found"
                session.updated_at = now
                db.add(session)
                db.commit()
                raise AuthRefreshError(detail="User disabled or not found.", reason="user_invalid")

            new_bundle = cls._issue_access_refresh_bundle(
                db=db,
                user=user,
                request=request,
                family_id=session.family_id or session.id,
            )

            session.status = "rotated"
            session.revoked_at = now
            session.revoke_reason = "rotated"
            session.replaced_by_session_id = str(new_bundle.get("session_id") or "")
            session.last_used_at = now
            session.updated_at = now
            db.add(session)

            try:
                db.commit()
                return {**new_bundle, "user": user}
            except Exception:
                db.rollback()
                logger.exception("Failed rotating refresh token")
                raise

    @classmethod
    def logout(cls, db: Session, user: User, refresh_token: str) -> bool:
        with sql_service_context(
            "auth_service",
            tenant_id=str(getattr(user, "tenant_id", "") or DEFAULT_TENANT_ID),
            role=str(getattr(user, "role", "") or ""),
        ):
            token_value = str(refresh_token or "").strip()
            if not token_value:
                return False

            token_hash = hash_refresh_token(token_value)
            session = (
                db.query(AuthSession)
                .filter(
                    AuthSession.refresh_token_hash == token_hash,
                    AuthSession.user_id == user.id,
                )
                .first()
            )
            if session is None:
                return False

            if session.status != "revoked" or session.revoked_at is None:
                now = cls._now()
                session.status = "revoked"
                session.revoked_at = now
                session.revoke_reason = "logout"
                session.updated_at = now
                db.add(session)
                db.commit()
            return True

    @classmethod
    def logout_all(cls, db: Session, user: User) -> int:
        with sql_service_context(
            "auth_service",
            tenant_id=str(getattr(user, "tenant_id", "") or DEFAULT_TENANT_ID),
            role=str(getattr(user, "role", "") or ""),
        ):
            now = cls._now()
            sessions = (
                db.query(AuthSession)
                .filter(
                    AuthSession.user_id == user.id,
                    AuthSession.status == "active",
                )
                .all()
            )
            count = 0
            for session in sessions:
                session.status = "revoked"
                session.revoked_at = now
                session.revoke_reason = "logout_all"
                session.updated_at = now
                db.add(session)
                count += 1
            if count > 0:
                db.commit()
            return count
