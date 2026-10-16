from __future__ import annotations

import time
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, Request

from backend.core.models import User
from backend.security.auth import decode_step_up_token
from backend.security.authorization_policy import get_policy, role_meets_minimum
from backend.server.deps.auth import get_current_user


def require_policy(action: str) -> Callable[[Request, User], User]:
    policy = get_policy(action)

    def _dep(
        request: Request,
        current_user: User = Depends(get_current_user),
    ) -> User:
        role = str(getattr(current_user, "role", "") or "").strip().lower()
        if not role_meets_minimum(role, policy.min_role):
            raise HTTPException(status_code=403, detail="Forbidden")

        if not policy.require_step_up:
            return current_user

        step_up_token = str(request.headers.get("X-Step-Up-Token") or "").strip()
        if not step_up_token:
            raise HTTPException(status_code=401, detail="Step-up authentication required.")

        try:
            payload = decode_step_up_token(step_up_token)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Step-up token expired.")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid step-up token.")

        token_user = str(payload.get("sub") or "").strip()
        token_role = str(payload.get("role") or "").strip().lower()
        if token_user != str(current_user.id):
            raise HTTPException(status_code=403, detail="Step-up token user mismatch.")
        if token_role != role:
            raise HTTPException(status_code=403, detail="Step-up token role mismatch.")

        token_actions = payload.get("actions")
        if isinstance(token_actions, str):
            allowed_actions = [token_actions]
        elif isinstance(token_actions, list):
            allowed_actions = [str(item).strip() for item in token_actions if str(item).strip()]
        else:
            allowed_actions = []

        if "*" not in allowed_actions and policy.action not in allowed_actions:
            raise HTTPException(status_code=403, detail="Step-up token not valid for this action.")

        issued_at = int(payload.get("iat") or 0)
        if issued_at <= 0:
            raise HTTPException(status_code=401, detail="Invalid step-up token.")
        age_seconds = int(time.time()) - issued_at
        if age_seconds > int(policy.step_up_max_age_seconds):
            raise HTTPException(status_code=401, detail="Step-up authentication is stale.")

        return current_user

    return _dep
