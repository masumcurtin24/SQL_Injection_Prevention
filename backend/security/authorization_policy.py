from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Dict


_ROLE_ORDER: Dict[str, int] = {"viewer": 1, "reviewer": 2, "analyst": 3, "admin": 4}


def _default_step_up_max_age_seconds() -> int:
    try:
        value = int(os.getenv("AUTH_STEP_UP_MAX_AGE_SECONDS", "900").strip() or "900")
        if value < 30:
            return 30
        if value > 3600:
            return 3600
        return value
    except Exception:
        return 900


@dataclass(frozen=True)
class AuthorizationPolicy:
    action: str
    min_role: str = "viewer"
    require_step_up: bool = False
    step_up_max_age_seconds: int = _default_step_up_max_age_seconds()


POLICY_REGISTRY: Dict[str, AuthorizationPolicy] = {
    "config.sql_enforcement.patch": AuthorizationPolicy(
        action="config.sql_enforcement.patch",
        min_role="admin",
        require_step_up=True,
    ),
    "defender.train.run": AuthorizationPolicy(
        action="defender.train.run",
        min_role="admin",
        require_step_up=True,
    ),
    "defender.model.promote": AuthorizationPolicy(
        action="defender.model.promote",
        min_role="admin",
        require_step_up=True,
    ),
    "defender.model.rollback": AuthorizationPolicy(
        action="defender.model.rollback",
        min_role="admin",
        require_step_up=True,
    ),
    "defender.spam.autopipeline.run": AuthorizationPolicy(
        action="defender.spam.autopipeline.run",
        min_role="admin",
        require_step_up=True,
    ),
    "spam.settings.update": AuthorizationPolicy(
        action="spam.settings.update",
        min_role="admin",
        require_step_up=True,
    ),
    "spam.blocklist.upload": AuthorizationPolicy(
        action="spam.blocklist.upload",
        min_role="admin",
        require_step_up=True,
    ),
    "dashboard.metrics.read": AuthorizationPolicy(
        action="dashboard.metrics.read",
        min_role="viewer",
        require_step_up=False,
    ),
    "dashboard.events.read": AuthorizationPolicy(
        action="dashboard.events.read",
        min_role="viewer",
        require_step_up=False,
    ),
    "dashboard.detail.read": AuthorizationPolicy(
        action="dashboard.detail.read",
        min_role="analyst",
        require_step_up=False,
    ),
    "dashboard.access.read": AuthorizationPolicy(
        action="dashboard.access.read",
        min_role="admin",
        require_step_up=False,
    ),
    "cases.read": AuthorizationPolicy(
        action="cases.read",
        min_role="analyst",
        require_step_up=False,
    ),
    "cases.create": AuthorizationPolicy(
        action="cases.create",
        min_role="analyst",
        require_step_up=False,
    ),
    "cases.update": AuthorizationPolicy(
        action="cases.update",
        min_role="analyst",
        require_step_up=False,
    ),
    "cases.assign": AuthorizationPolicy(
        action="cases.assign",
        min_role="analyst",
        require_step_up=False,
    ),
    "investigation.read": AuthorizationPolicy(
        action="investigation.read",
        min_role="analyst",
        require_step_up=False,
    ),
    "monitoring.read": AuthorizationPolicy(
        action="monitoring.read",
        min_role="reviewer",
        require_step_up=False,
    ),
    "ws.alert.subscribe": AuthorizationPolicy(
        action="ws.alert.subscribe",
        min_role="analyst",
        require_step_up=True,
    ),
}


def role_meets_minimum(user_role: str, min_role: str) -> bool:
    current = str(user_role or "").strip().lower()
    required = str(min_role or "").strip().lower()
    if required not in _ROLE_ORDER:
        return False
    return _ROLE_ORDER.get(current, 0) >= _ROLE_ORDER[required]


def get_policy(action: str) -> AuthorizationPolicy:
    key = str(action or "").strip()
    if key in POLICY_REGISTRY:
        return POLICY_REGISTRY[key]
    return AuthorizationPolicy(action=key, min_role="viewer", require_step_up=False)
