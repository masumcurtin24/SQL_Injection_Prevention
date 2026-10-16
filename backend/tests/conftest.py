import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _configure_test_env() -> None:
    tmp_dir = Path(tempfile.mkdtemp(prefix="sqliprev-test-")).resolve()
    db_path = tmp_dir / "test.db"

    os.environ.setdefault("ENV", "test")
    os.environ.setdefault("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173")
    os.environ.setdefault("MAX_BODY_BYTES", "1024")

    os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-should-be-at-least-32-bytes")
    os.environ.setdefault("JWT_ALGORITHM", "HS256")
    os.environ.setdefault("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60")
    os.environ.setdefault("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "14")
    os.environ.setdefault("JWT_STEP_UP_TOKEN_EXPIRE_MINUTES", "10")
    os.environ.setdefault("AUTH_STEP_UP_MAX_AGE_SECONDS", "900")
    os.environ.setdefault("AUTH_IDENTITY_MODE", "local")
    os.environ.setdefault("AUTH_OIDC_AUTO_PROVISION", "false")
    os.environ.setdefault("OIDC_ISSUER_URL", "")
    os.environ.setdefault("OIDC_AUDIENCE", "")
    os.environ.setdefault("OIDC_JWKS_URL", "")
    os.environ.setdefault("OIDC_JWT_ALGORITHMS", "RS256")
    os.environ.setdefault("OIDC_JWT_SHARED_SECRET", "")
    os.environ.setdefault("OIDC_CLOCK_SKEW_SECONDS", "60")

    os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
    os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "admin-password-123")

    os.environ.setdefault("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")


_configure_test_env()


@pytest.fixture()
def client():
    from backend.server.main import app

    with TestClient(app) as c:
        yield c
