"""Baseline smoke test for real FastAPI startup/lifespan.

This boots the app via TestClient, verifies liveness/readiness endpoints,
and checks a minimal auth route behavior. Exits non-zero on regression.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _prepare_env() -> None:
    os.environ.setdefault("ENV", "test")
    os.environ.setdefault("JWT_SECRET_KEY", "smoke-secret-key-should-be-at-least-32-bytes")
    os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
    os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "admin-password-123")
    os.environ.setdefault("BOOTSTRAP_ADMIN_FULL_NAME", "Bootstrap Admin")
    os.environ.setdefault("AUTH_IDENTITY_MODE", "local")


def main() -> None:
    _prepare_env()
    from backend.server.main import app

    with TestClient(app) as client:
        live = client.get("/health/live")
        if live.status_code != 200 or (live.json() or {}).get("status") != "alive":
            raise SystemExit(f"Startup smoke failed: /health/live unexpected response: {live.status_code} {live.text}")

        health = client.get("/health")
        if health.status_code != 200:
            raise SystemExit(f"Startup smoke failed: /health returned {health.status_code}")
        payload = health.json() or {}
        if payload.get("ready") is not True:
            raise SystemExit(f"Startup smoke failed: /health ready flag is not true: {payload}")

        ready = client.get("/health/ready")
        if ready.status_code != 200 or (ready.json() or {}).get("status") != "ready":
            raise SystemExit(f"Startup smoke failed: /health/ready unexpected response: {ready.status_code} {ready.text}")

        auth_me = client.get("/api/v1/auth/me")
        if auth_me.status_code != 401:
            raise SystemExit(f"Startup smoke failed: /api/v1/auth/me expected 401, got {auth_me.status_code}")

        invalid_login = client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "invalid-password"},
        )
        if invalid_login.status_code != 401:
            raise SystemExit(
                f"Startup smoke failed: /api/v1/auth/login invalid creds expected 401, got {invalid_login.status_code}"
            )

    print("App startup smoke passed.")


if __name__ == "__main__":
    main()
