from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

import jwt

from backend.core.database import SessionLocal
from backend.core.models import User
from backend.security.auth import hash_password

_OIDC_TEST_SECRET = "oidc-shared-secret-for-tests-32bytes"


def _set_oidc_hs256_env(monkeypatch, *, auto_provision: bool):
    monkeypatch.setenv("AUTH_IDENTITY_MODE", "oidc")
    monkeypatch.setenv("AUTH_OIDC_AUTO_PROVISION", "true" if auto_provision else "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example.com")
    monkeypatch.setenv("OIDC_AUDIENCE", "sql-injection-prevention-api")
    monkeypatch.setenv("OIDC_JWKS_URL", "")
    monkeypatch.setenv("OIDC_JWT_ALGORITHMS", "HS256")
    monkeypatch.setenv("OIDC_JWT_SHARED_SECRET", _OIDC_TEST_SECRET)
    monkeypatch.setenv("OIDC_CLOCK_SKEW_SECONDS", "60")


def _oidc_token(*, subject: str, email: str, role: str = "viewer") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "email": email,
        "role": role,
        "iss": "https://issuer.example.com",
        "aud": "sql-injection-prevention-api",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    return jwt.encode(payload, _OIDC_TEST_SECRET, algorithm="HS256")


def test_oidc_auto_provision_creates_user_and_authenticates(client, monkeypatch):
    _set_oidc_hs256_env(monkeypatch, auto_provision=True)
    email = f"oidc-auto-{uuid.uuid4()}@example.com"
    token = _oidc_token(subject=f"oidc-sub-{uuid.uuid4()}", email=email, role="analyst")

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    payload = me.json()
    assert payload["email"] == email
    assert payload["role"] == "analyst"

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
    assert user is not None
    assert user.role == "analyst"


def test_oidc_without_auto_provision_rejects_unknown_user(client, monkeypatch):
    _set_oidc_hs256_env(monkeypatch, auto_provision=False)
    token = _oidc_token(
        subject=f"oidc-sub-{uuid.uuid4()}",
        email=f"oidc-no-provision-{uuid.uuid4()}@example.com",
        role="viewer",
    )
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 401, me.text


def test_oidc_maps_existing_user_by_email(client, monkeypatch):
    _set_oidc_hs256_env(monkeypatch, auto_provision=False)
    email = f"oidc-existing-{uuid.uuid4()}@example.com"

    with SessionLocal() as db:
        user = User(
            email=email,
            password_hash=hash_password("local-password-not-used"),
            role="viewer",
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = _oidc_token(subject=f"external-subject-{uuid.uuid4()}", email=email, role="admin")
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    payload = me.json()
    assert payload["email"] == email
    # Existing local role remains authoritative unless explicitly changed by policy.
    assert payload["role"] == "viewer"
