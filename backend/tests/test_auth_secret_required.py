import pytest

from backend.security.auth import create_access_token


def test_create_access_token_requires_secret(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        create_access_token(user_id="u1", role="admin", email="admin@example.com")


def test_create_access_token_rejects_short_secret(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "too-short")
    with pytest.raises(RuntimeError, match="at least"):
        create_access_token(user_id="u1", role="admin", email="admin@example.com")
