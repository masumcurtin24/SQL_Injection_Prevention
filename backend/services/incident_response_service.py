from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.services.alerts_service import AlertsService
from backend.server.schemas.responses import Alert as AlertSchema
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


class IncidentResponseService:
    _instance: Optional["IncidentResponseService"] = None
    _initialized_flag: bool = False
    _alerts_service_instance: Optional[AlertsService] = None

    _BASE_ACTION_MATRIX: Dict[str, List[str]] = {
        "ALLOW": ["log_only"],
        "ALLOW_UPLOAD": ["log_only"],
        "FLAG_AS_SPAM": ["mark_spam", "queue_review"],
        "FLAG_FOR_REVIEW": ["queue_review"],
        "FLAG_FOR_REVIEW_BLOCK": ["block_request", "queue_review", "notify_soc"],
        "BLOCK_EMAIL": ["block_request", "notify_soc", "preserve_evidence", "user_warning", "search_similar_messages"],
        "QUARANTINE_EMAIL": ["block_request", "notify_soc", "preserve_evidence", "search_similar_messages"],
        "BLOCK_UPLOAD": ["block_request", "notify_soc"],
        "BLOCK_REQUEST": ["block_request", "notify_soc", "preserve_evidence"],
        "QUARANTINE_REQUEST": ["quarantine_request", "notify_soc", "preserve_evidence"],
        "BLOCK_IMMEDIATE": ["block_request", "notify_soc", "rate_limit_source"],
        "BLOCK_AND_QUARANTINE": ["block_request", "quarantine_request", "notify_soc", "preserve_evidence"],
    }

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(IncidentResponseService, cls).__new__(cls)
        return cls._instance

    def __init__(self, alerts_service: Optional[AlertsService] = None):
        if self._initialized_flag:
            if alerts_service is not None:
                self._alerts_service_instance = alerts_service
            return
        logger.info("Initializing IncidentResponseService...")
        self._alerts_service_instance = alerts_service
        self._initialized_flag = True
        logger.info("IncidentResponseService initialized successfully.")

    @classmethod
    def get_instance(cls) -> "IncidentResponseService":
        if not cls._initialized_flag or cls._instance is None:
            raise RuntimeError("IncidentResponseService has not been initialized.")
        return cls._instance

    def get_action_matrix(self) -> Dict[str, List[str]]:
        return {k: list(v) for k, v in self._BASE_ACTION_MATRIX.items()}

    def plan_actions(
        self,
        *,
        domain: str,
        suggested_action: Optional[str],
        risk_level: Optional[str] = None,
    ) -> List[str]:
        action_key = (suggested_action or "ALLOW").strip().upper()
        actions = list(self._BASE_ACTION_MATRIX.get(action_key, ["queue_review"]))
        risk = (risk_level or "").strip().lower()
        domain_normalized = (domain or "unknown").strip().lower()

        # Escalate SOC notifications for high/critical outcomes even if action key is custom.
        if risk in {"high", "critical"} and "notify_soc" not in actions:
            actions.append("notify_soc")

        # Domain-specific refinements.
        if domain_normalized == "spam" and action_key == "FLAG_AS_SPAM":
            if "mark_spam" not in actions:
                actions.insert(0, "mark_spam")
        if domain_normalized == "spam" and action_key == "BLOCK_EMAIL":
            for request_action in ("domain_block_request", "url_block_request"):
                if request_action not in actions:
                    actions.append(request_action)
        if domain_normalized == "file" and action_key.startswith("BLOCK"):
            if "quarantine_request" not in actions and "BLOCK_AND_QUARANTINE" in action_key:
                actions.append("quarantine_request")
        return actions

    def execute_actions(
        self,
        *,
        db: Session,
        domain: str,
        entity_id: str,
        suggested_action: Optional[str],
        risk_level: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        create_alert_if_missing: bool = False,
    ) -> Dict[str, Any]:
        actions = self.plan_actions(domain=domain, suggested_action=suggested_action, risk_level=risk_level)
        details_payload = details if isinstance(details, dict) else {}

        alert_created = False
        if (
            create_alert_if_missing
            and "notify_soc" in actions
            and self._alerts_service_instance is not None
        ):
            severity = "High" if (risk_level or "").strip().lower() in {"high", "critical"} else "Medium"
            title = f"Defender Action: {domain.upper()} {suggested_action or 'REVIEW'}"
            message = details_payload.get("message") or "Defender policy triggered additional SOC notification."
            try:
                alert = AlertSchema(
                    id=f"alert-defender-{entity_id}",
                    timestamp=datetime.now(timezone.utc),
                    severity=severity,
                    title=title,
                    message=message,
                    target=f"defender:{domain}",
                    acknowledged=False,
                    tags=["defender_v1", f"domain:{domain}", f"decision:{(suggested_action or 'UNKNOWN').upper()}"],
                )
                self._alerts_service_instance.create_alert(db=db, alert_data=alert)
                alert_created = True
            except Exception as exc:
                logger.error(f"Defender alert creation failed for {domain}:{entity_id}: {exc}", exc_info=True)

        strict_mode = os.getenv("DEFENDER_STRICT_MODE", "false").strip().lower() in {"1", "true", "yes", "y"}
        if strict_mode and "queue_review" in actions and "block_request" not in actions and (risk_level or "").lower() == "high":
            actions.append("block_request")

        return {
            "domain": (domain or "unknown").lower(),
            "entity_id": entity_id,
            "decision": (suggested_action or "ALLOW").upper(),
            "risk_level": (risk_level or "low").capitalize(),
            "actions": actions,
            "alert_created": alert_created,
        }
