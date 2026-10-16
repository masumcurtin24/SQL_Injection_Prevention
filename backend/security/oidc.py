from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

import jwt


@dataclass(frozen=True)
class OIDCSettings:
    mode: str
    issuer: Optional[str]
    audience: Optional[str]
    jwks_url: Optional[str]
    shared_secret: Optional[str]
    algorithms: Tuple[str, ...]
    leeway_seconds: int


def is_oidc_enabled() -> bool:
    return str(os.getenv("AUTH_IDENTITY_MODE", "local")).strip().lower() == "oidc"


def _parse_algorithms(raw: Optional[str]) -> Tuple[str, ...]:
    values = [token.strip() for token in str(raw or "RS256").split(",") if token and token.strip()]
    return tuple(values or ["RS256"])


def _derive_jwks_url(issuer: Optional[str], explicit_jwks_url: Optional[str]) -> Optional[str]:
    explicit = str(explicit_jwks_url or "").strip()
    if explicit:
        return explicit
    iss = str(issuer or "").strip()
    if not iss:
        return None
    return f"{iss.rstrip('/')}/.well-known/jwks.json"


def get_oidc_settings() -> OIDCSettings:
    issuer = str(os.getenv("OIDC_ISSUER_URL", "") or "").strip() or None
    audience = str(os.getenv("OIDC_AUDIENCE", "") or "").strip() or None
    shared_secret = str(os.getenv("OIDC_JWT_SHARED_SECRET", "") or "").strip() or None
    raw_jwks_url = str(os.getenv("OIDC_JWKS_URL", "") or "").strip() or None
    mode = str(os.getenv("AUTH_IDENTITY_MODE", "local")).strip().lower()
    try:
        leeway = int(str(os.getenv("OIDC_CLOCK_SKEW_SECONDS", "60") or "60").strip())
        if leeway < 0:
            leeway = 0
        if leeway > 300:
            leeway = 300
    except Exception:
        leeway = 60

    return OIDCSettings(
        mode=mode,
        issuer=issuer,
        audience=audience,
        jwks_url=_derive_jwks_url(issuer=issuer, explicit_jwks_url=raw_jwks_url),
        shared_secret=shared_secret,
        algorithms=_parse_algorithms(os.getenv("OIDC_JWT_ALGORITHMS", "RS256")),
        leeway_seconds=leeway,
    )


@lru_cache(maxsize=8)
def _jwks_client(jwks_url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(jwks_url)


def verify_oidc_access_token(token: str) -> Dict[str, Any]:
    settings = get_oidc_settings()
    if settings.mode != "oidc":
        raise jwt.InvalidTokenError("OIDC mode is not enabled.")

    options = {"require": ["exp", "iat", "sub"]}
    verify_aud = bool(settings.audience)

    if settings.shared_secret:
        return jwt.decode(
            token,
            key=settings.shared_secret,
            algorithms=list(settings.algorithms),
            audience=settings.audience if verify_aud else None,
            issuer=settings.issuer,
            options=options | {"verify_aud": verify_aud},
            leeway=settings.leeway_seconds,
        )

    if not settings.jwks_url:
        raise jwt.InvalidTokenError("OIDC_JWKS_URL or OIDC_ISSUER_URL is required for OIDC validation.")

    signing_key = _jwks_client(settings.jwks_url).get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key=signing_key,
        algorithms=list(settings.algorithms),
        audience=settings.audience if verify_aud else None,
        issuer=settings.issuer,
        options=options | {"verify_aud": verify_aud},
        leeway=settings.leeway_seconds,
    )
