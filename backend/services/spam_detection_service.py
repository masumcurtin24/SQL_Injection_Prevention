"""
Enhanced spam detection service with optional transformer model, URL/domain heuristics,
basic reputation/blocklist support, and richer response metadata.
"""
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from collections import Counter
from difflib import SequenceMatcher
from email import policy
from email.parser import Parser
import html as html_lib
import os
import re
import math
import sys
import unicodedata
import joblib
import uuid
from sqlalchemy.orm import Session
import json
import asyncio
from urllib.parse import urlparse
from pathlib import Path
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

from backend.utils.logging_utils import setup_logger
from backend.server.schemas.requests import EmailAnalysisRequest
from backend.server.schemas.responses import (
    SpamClassificationResult,
    SpamDecisionDisplay,
    Alert as AlertSchema,
    XAIExplanation,
    XAIExplanationEvidence,
    XAIExplanationTraceStep,
)
from backend.core.models import DEFAULT_TENANT_ID, SpamAnalysisLog as SpamAnalysisLogModel
from backend.services.alerts_service import AlertsService
from backend.services.ai_reliability_service import assess_ai_reliability
from backend.services.explainability_contract import complete_explainability_contract
from backend.services.incident_response_service import IncidentResponseService
from backend.server.websockets import manager

logger = setup_logger(__name__)


class SpamDetectionService:
    _instance: Optional['SpamDetectionService'] = None
    _spam_detection_pipeline: Optional[Any] = None
    _transformer_pipeline: Optional[Any] = None
    _transformer_model_name: Optional[str] = None
    _blocklist_domains: Optional[set] = None
    _allowlist_domains: Optional[set] = None
    _domain_reputation: Optional[Dict[str, float]] = None
    _fraud_pattern_pack: Optional[Dict[str, Any]] = None
    _alerts_service_instance: Optional[AlertsService] = None
    _incident_response_service_instance: Optional[IncidentResponseService] = None
    _initialized_flag: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(SpamDetectionService, cls).__new__(cls)
        return cls._instance

    def __init__(self, model_path: str, alerts_service: AlertsService):
        if self._initialized_flag:
            return
        logger.info("Initializing SpamDetectionService...")
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Spam detection model not found at {model_path}")
            self._spam_detection_pipeline = joblib.load(model_path)
            self._alerts_service_instance = alerts_service
            try:
                self._incident_response_service_instance = IncidentResponseService.get_instance()
            except Exception:
                self._incident_response_service_instance = IncidentResponseService(alerts_service=alerts_service)
            logger.info("Spam Detection pipeline loaded successfully.")
        except Exception as e:
            logger.critical(f"FATAL: Failed to load spam detection model: {e}", exc_info=True)

        # Optional transformer-based classifier
        model_name = os.getenv("SPAM_TRANSFORMER_MODEL", "").strip()
        self._transformer_model_name = model_name or None
        if model_name:
            try:
                from transformers import pipeline  # type: ignore
                self._transformer_pipeline = pipeline("text-classification", model=model_name, truncation=True)
                logger.info(f"Transformer spam model ready: {model_name}")
            except Exception as e:
                logger.error(
                    "Transformer model unavailable for SPAM_TRANSFORMER_MODEL='%s' (python=%s): %s. "
                    "Install in this runtime with: %s -m pip install transformers torch",
                    model_name,
                    sys.executable,
                    e,
                    sys.executable,
                )

        # Reputation assets
        self._blocklist_domains = set()
        self._allowlist_domains = set()
        self._domain_reputation = {}
        self._fraud_pattern_pack = None
        self.reload_blocklist()
        self.reload_allowlist()
        self.reload_reputation_scores()
        self.reload_fraud_pattern_pack()

        self._apply_yaml_policy_overrides()

        self._initialized_flag = True

    @staticmethod
    def _clamp01(value: float) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return 0.0
        if numeric < 0.0:
            return 0.0
        if numeric > 1.0:
            return 1.0
        return numeric

    @staticmethod
    def _compute_decision_confidence(
        spam_score: float,
        category: str,
        uncertainty_score: float = 0.0,
        ood_score: float = 0.0,
    ) -> float:
        """Return confidence in the selected class, not the malicious-email risk.

        spam_score is the calibrated risk of spam/phishing behaviour.
        decision_confidence is confidence in the selected final class.
        For benign classifications, low spam_score means high decision confidence.
        """
        risk = SpamDetectionService._clamp01(spam_score)
        label = str(category or "").strip().lower()
        safe_labels = {
            "safe",
            "ham",
            "clean",
            "benign",
            "not_spam",
            "not spam",
            "legitimate",
            "normal",
            "allow",
            "allowed",
        }
        base_confidence = 1.0 - risk if label in safe_labels else risk
        # Keep threat risk, decision confidence, and uncertainty separate.
        # Review policy consumes uncertainty/OOD; they do not rewrite the
        # confidence assigned to the selected final class.
        _ = uncertainty_score, ood_score
        return SpamDetectionService._clamp01(base_confidence)

    @staticmethod
    def _default_handling_for_category(category: str) -> str:
        normalized = str(category or "").strip().lower()
        if normalized == "blocked":
            return "block"
        if normalized == "suspicious":
            return "review"
        return "allow"

    @staticmethod
    def _spam_suggested_actions(
        *,
        recommended_handling: str,
        review_required: bool,
        fraud_category: Optional[str] = None,
    ) -> List[str]:
        handling = str(recommended_handling or "").strip().lower()
        category = str(fraud_category or "").strip().lower()
        if category == "gift_card_fraud":
            return [
                "Do not purchase gift cards.",
                "Do not send card numbers, PINs, codes, or photos.",
                "Verify the request through a trusted channel.",
                "Report to SOC or a manager.",
                "Create a block request or quarantine according to configured policy after review or policy approval.",
            ]
        if category == "payroll_direct_deposit_change":
            return [
                "Do not change payroll details from email alone.",
                "Verify through the HR/payroll system or a known phone number.",
                "Report the suspicious sender/domain to SOC.",
                "Preserve the message and headers for investigation.",
            ]
        if category == "credential_harvesting":
            return [
                "Do not click login links.",
                "Verify the domain manually through the official portal.",
                "Reset passwords only through the official identity system.",
                "Report the message to SOC.",
            ]
        if category in {"invoice_payment_redirection", "wire_transfer_fraud", "supplier_bank_change"}:
            return [
                "Do not change payment instructions from email alone.",
                "Verify bank or wire changes with a known supplier contact.",
                "Preserve evidence and notify finance security/SOC.",
                "Create a block request according to configured mail policy if approved.",
            ]
        if category in {
            "courier_customs_fee_phishing",
            "delivery_redelivery_fee_phishing",
            "package_hold_phishing",
            "courier_brand_impersonation",
            "payment_link_impersonation",
            "tracking_link_phishing",
        }:
            return [
                "Do not click the payment or tracking link.",
                "Do not enter card, banking, or personal details.",
                "Verify delivery status through the official courier website or app.",
                "Check sender and link domains independently.",
                "Report the message to SOC/security team.",
                "Use block-request or quarantine-request wording only as an action plan.",
            ]
        if review_required or handling == "review":
            return [
                "Route to analyst review before blocking.",
                "Do not click links or download attachments.",
                "Verify sender/domain independently.",
                "Check headers, URL reputation, and business context.",
                "Do not automatically block sender/domain from this single grey-zone result.",
            ]
        if handling == "block":
            return [
                "Block or quarantine according to policy.",
                "Preserve evidence.",
                "Investigate recipients and similar messages.",
            ]
        if handling == "quarantine":
            return [
                "Quarantine according to configured mail/file policy.",
                "Preserve evidence.",
                "Escalate if related campaign indicators exist.",
            ]
        if handling == "monitor":
            return [
                "Allow but log and monitor.",
                "Review if repeated pattern emerges.",
            ]
        return [
            "No strong indicators found.",
            "Continue normal handling.",
            "Monitor if similar reports appear.",
        ]

    @classmethod
    def _compute_spam_uncertainty(
        cls,
        *,
        spam_score: float,
        suspicious_threshold: float,
        ood_score: float,
        component_scores: Dict[str, Optional[float]],
        component_weights: Optional[Dict[str, float]] = None,
        transformer_available: bool,
        reputation_available: bool,
        headers_available: bool,
        fidelity_score: Optional[float] = None,
    ) -> Tuple[float, Dict[str, float], List[str]]:
        risk = cls._clamp01(spam_score)
        threshold = cls._clamp01(suspicious_threshold)
        ood = cls._clamp01(ood_score)
        threshold_margin_uncertainty = cls._clamp01(
            1.0 - min(abs(risk - threshold) / 0.20, 1.0)
        )

        weights = component_weights if isinstance(component_weights, dict) else {}
        active_components: List[Tuple[str, float, float]] = []
        for name, value in component_scores.items():
            if not isinstance(value, (int, float)):
                continue
            try:
                weight = float(weights.get(name, 1.0))
            except (TypeError, ValueError):
                weight = 1.0
            if weight <= 0.0:
                continue
            active_components.append((name, cls._clamp01(float(value)), weight))

        # Disagreement should reflect material, weighted conflict with the
        # selected risk side, not raw max-min spread. A missing header score,
        # for example, is handled by missing_component_uncertainty instead of
        # being treated as a benign vote against phishing.
        neutral_margin = 0.05
        lower_band = max(0.0, threshold - neutral_margin)
        upper_band = min(1.0, threshold + neutral_margin)
        decision_is_restrictive = risk >= threshold
        conflict_mass = 0.0
        total_weight = sum(weight for _name, _score, weight in active_components)
        for _name, score, weight in active_components:
            conflict_strength = 0.0
            if decision_is_restrictive and score < lower_band:
                conflict_strength = (lower_band - score) / max(lower_band, 1e-9)
            elif not decision_is_restrictive and score > upper_band:
                conflict_strength = (score - upper_band) / max(1.0 - upper_band, 1e-9)
            conflict_mass += weight * cls._clamp01(conflict_strength)
        component_disagreement_uncertainty = (
            cls._clamp01(conflict_mass / total_weight)
            if total_weight > 0.0
            else 0.0
        )

        missing_important_components: List[str] = []
        if not transformer_available:
            missing_important_components.append("transformer")
        if not reputation_available:
            missing_important_components.append("reputation")
        if not headers_available:
            missing_important_components.append("headers")
        missing_component_uncertainty = min(0.30, 0.10 * len(missing_important_components))
        low_fidelity_uncertainty = (
            cls._clamp01(1.0 - float(fidelity_score))
            if isinstance(fidelity_score, (int, float))
            else 0.0
        )

        components = {
            "threshold_margin_uncertainty": round(threshold_margin_uncertainty, 4),
            "component_disagreement_uncertainty": round(component_disagreement_uncertainty, 4),
            "missing_component_uncertainty": round(missing_component_uncertainty, 4),
            "ood_score": round(ood, 4),
            "low_fidelity_uncertainty": round(low_fidelity_uncertainty, 4),
        }
        uncertainty_score = round(
            cls._clamp01(max(components.values())),
            4,
        )
        return uncertainty_score, components, missing_important_components

    @classmethod
    def _classify_spam_decision_display(
        cls,
        *,
        spam_score: float,
        decision_confidence: float,
        uncertainty_score: float,
        ood_score: float,
        ai_reliability: Optional[Any],
        category: str,
        suspicious_threshold: float,
        fraud_category: Optional[str] = None,
    ) -> SpamDecisionDisplay:
        risk = cls._clamp01(spam_score)
        confidence = cls._clamp01(decision_confidence)
        uncertainty = cls._clamp01(uncertainty_score)
        ood = cls._clamp01(ood_score)
        handling = cls._default_handling_for_category(category)
        review_required = False
        reliability_status = None
        adversarial_suspicion = False

        if ai_reliability is not None:
            handling = str(getattr(ai_reliability, "recommended_handling", handling) or handling).strip().lower()
            review_required = bool(getattr(ai_reliability, "review_required", False))
            reliability_status = str(getattr(ai_reliability, "reliability_status", "") or "") or None
            adversarial_suspicion = bool(getattr(ai_reliability, "adversarial_suspicion", False))

        review_gate = bool(
            review_required
            or confidence < 0.70
            or 0.45 <= risk <= 0.65
            or uncertainty > 0.40
            or ood > 0.35
            or adversarial_suspicion
        )
        category_lc = str(fraud_category or "").strip().lower()
        courier_categories = {
            "courier_customs_fee_phishing",
            "delivery_redelivery_fee_phishing",
            "package_hold_phishing",
            "courier_brand_impersonation",
            "payment_link_impersonation",
            "tracking_link_phishing",
        }
        if review_gate and category_lc in courier_categories and risk >= 0.75 and confidence >= 0.70:
            if category_lc == "courier_customs_fee_phishing":
                status_label = "High-Risk Courier/Customs Fee Phishing - Review Required"
            elif category_lc in {"delivery_redelivery_fee_phishing", "package_hold_phishing"}:
                status_label = "High-Risk Delivery Fee Phishing - Review Required"
            else:
                status_label = "High-Risk Courier/Delivery Phishing - Review Required"
            return SpamDecisionDisplay(
                status_label=status_label,
                status_color="amber",
                hard_detection=False,
                review_required=True,
                recommended_handling=handling if handling in {"block", "quarantine", "review"} else "review",
                reliability_status=reliability_status,
                detail="High-risk courier phishing evidence is present, but reliability guardrails require analyst review before final handling.",
            )
        if review_gate:
            return SpamDecisionDisplay(
                status_label="Needs Review — Possible Spam/Phishing",
                status_color="amber",
                hard_detection=False,
                review_required=True,
                recommended_handling=handling if handling in {"allow", "monitor", "review", "block", "quarantine"} else "review",
                reliability_status=reliability_status,
                detail="Grey-zone or reliability guardrail conditions require analyst review before treating the result as final.",
            )
        if handling == "block" or str(category or "").strip().lower() == "blocked":
            if category_lc == "courier_customs_fee_phishing":
                status_label = "High-Risk Courier/Customs Fee Phishing Detected"
            elif category_lc in {"delivery_redelivery_fee_phishing", "package_hold_phishing"}:
                status_label = "High-Risk Delivery Fee Phishing Detected"
            elif category_lc in {"payment_link_impersonation", "tracking_link_phishing", "courier_brand_impersonation"}:
                status_label = "High-Risk Courier/Delivery Phishing Detected"
            elif category_lc == "gift_card_fraud":
                status_label = "High-Risk BEC / Gift-Card Fraud Detected"
            elif category_lc in {
                "payroll_direct_deposit_change",
                "invoice_payment_redirection",
                "wire_transfer_fraud",
                "supplier_bank_change",
                "urgent_executive_request",
            }:
                status_label = "High-Risk BEC / Phishing Detected"
            elif category_lc == "credential_harvesting":
                status_label = "High-Risk Credential Phishing Detected"
            else:
                status_label = "High-Risk Phishing Detected"
            detail = (
                "High-risk BEC/phishing evidence supports a block-request action plan; this is not a claim of completed gateway enforcement."
                if category_lc
                else "High-risk evidence and handling policy support an automated phishing detection path."
            )
            return SpamDecisionDisplay(
                status_label=status_label,
                status_color="red",
                hard_detection=True,
                review_required=False,
                recommended_handling="block",
                reliability_status=reliability_status,
                detail=detail,
            )
        if risk >= cls._clamp01(suspicious_threshold):
            return SpamDecisionDisplay(
                status_label="Suspicious Message",
                status_color="amber",
                hard_detection=False,
                review_required=False,
                recommended_handling=handling if handling in {"monitor", "quarantine"} else "monitor",
                reliability_status=reliability_status,
                detail="Risk exceeds the suspicious threshold without triggering a hard detection policy.",
            )
        return SpamDecisionDisplay(
            status_label="Not Spam",
            status_color="green",
            hard_detection=False,
            review_required=False,
            recommended_handling=handling if handling in {"allow", "monitor"} else "allow",
            reliability_status=reliability_status,
            detail="No review gate or high-risk handling path was triggered.",
        )

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except Exception:
            return default

    @staticmethod
    def _sigmoid(x: float) -> float:
        try:
            return 1.0 / (1.0 + math.exp(-x))
        except OverflowError:
            return 0.0 if x < 0 else 1.0

    def _default_thresholds(self) -> Dict[str, float]:
        final_legacy = getattr(self, "_final_threshold_override", None)
        suspicious_default = self._safe_float(
            final_legacy if final_legacy is not None else os.getenv("SPAM_FINAL_THRESHOLD", "0.50"),
            0.50,
        )
        allow_default = self._safe_float(os.getenv("SPAM_ALLOW_THRESHOLD", "0.40"), 0.40)
        block_default = self._safe_float(os.getenv("SPAM_BLOCK_THRESHOLD", "0.80"), 0.80)
        ood_default = self._safe_float(os.getenv("SPAM_OOD_THRESHOLD", "0.68"), 0.68)
        thresholds = {
            "allow": self._clamp01(allow_default),
            "suspicious": self._clamp01(suspicious_default),
            "block": self._clamp01(block_default),
            "ood": self._clamp01(ood_default),
        }
        if thresholds["suspicious"] < thresholds["allow"]:
            thresholds["suspicious"] = thresholds["allow"]
        if thresholds["block"] < thresholds["suspicious"]:
            thresholds["block"] = thresholds["suspicious"]
        return thresholds

    def _resolved_thresholds(self) -> Dict[str, float]:
        defaults = self._default_thresholds()
        override = getattr(self, "_thresholds_override", None)
        if isinstance(override, dict):
            for k in ("allow", "suspicious", "block", "ood"):
                if k in override and isinstance(override.get(k), (int, float)):
                    defaults[k] = self._clamp01(float(override[k]))
        if defaults["suspicious"] < defaults["allow"]:
            defaults["suspicious"] = defaults["allow"]
        if defaults["block"] < defaults["suspicious"]:
            defaults["block"] = defaults["suspicious"]
        return defaults

    def _default_feature_weights(self) -> Dict[str, float]:
        return {
            "classical": self._safe_float(os.getenv("SPAM_W_CLASSICAL", "0.22"), 0.22),
            "transformer": self._safe_float(os.getenv("SPAM_W_TRANSFORMER", "0.36"), 0.36),
            "online": self._safe_float(os.getenv("SPAM_W_ONLINE", "0.10"), 0.10),
            "heuristic": self._safe_float(os.getenv("SPAM_W_HEURISTIC", "0.18"), 0.18),
            "reputation": self._safe_float(os.getenv("SPAM_W_REPUTATION", "0.14"), 0.14),
            "campaign": self._safe_float(os.getenv("SPAM_W_CAMPAIGN", "0.24"), 0.24),
            "header": self._safe_float(os.getenv("SPAM_W_HEADER", "0.15"), 0.15),
            "fraud_pattern": self._safe_float(os.getenv("SPAM_W_FRAUD_PATTERN", "0.22"), 0.22),
        }

    def _resolved_feature_weights(self) -> Dict[str, float]:
        defaults = self._default_feature_weights()
        override = getattr(self, "_feature_weights_override", None)
        if isinstance(override, dict):
            for k in defaults.keys():
                if k in override and isinstance(override.get(k), (int, float)):
                    defaults[k] = max(0.0, float(override[k]))
        return defaults

    def _default_calibration(self) -> Dict[str, float]:
        return {
            "a": self._safe_float(os.getenv("SPAM_CALIBRATION_A", "3.5"), 3.5),
            "b": self._safe_float(os.getenv("SPAM_CALIBRATION_B", "-1.4"), -1.4),
        }

    def _resolved_calibration(self) -> Dict[str, float]:
        defaults = self._default_calibration()
        override = getattr(self, "_calibration_override", None)
        if isinstance(override, dict):
            if isinstance(override.get("a"), (int, float)):
                defaults["a"] = float(override["a"])
            if isinstance(override.get("b"), (int, float)):
                defaults["b"] = float(override["b"])
        return defaults

    @staticmethod
    def _load_domain_list(path: str) -> set:
        out: set = set()
        if not path or not os.path.exists(path):
            return out
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                v = line.strip().lower()
                if not v or v.startswith("#"):
                    continue
                out.add(v)
        return out

    @staticmethod
    def _load_reputation_map(path: str) -> Dict[str, float]:
        data: Dict[str, float] = {}
        if not path or not os.path.exists(path):
            return data
        if path.lower().endswith(".json"):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                for k, v in raw.items():
                    try:
                        score = float(v)
                    except Exception:
                        continue
                    data[str(k).strip().lower()] = max(0.0, min(1.0, score))
            return data

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                row = line.strip()
                if not row or row.startswith("#"):
                    continue
                parts = [x.strip() for x in row.split(",")]
                if len(parts) < 2:
                    continue
                try:
                    score = float(parts[1])
                except Exception:
                    continue
                domain = parts[0].lower()
                if domain:
                    data[domain] = max(0.0, min(1.0, score))
        return data

    def _fraud_pattern_pack_path(self) -> str:
        return os.getenv("SPAM_FRAUD_PATTERN_PATH", "backend/data/reputation/spam_fraud_patterns.json")

    def _default_fraud_pattern_pack(self) -> Dict[str, Any]:
        return {
            "version": "builtin-2026-04-02",
            "patterns": [
                {
                    "id": "credential_reset_lure",
                    "label": "Credential reset / account verify lure",
                    "severity": "high",
                    "theme": "credential",
                    "weight": 0.26,
                    "requires_url": True,
                    "impact": "Likely credential-harvesting social engineering.",
                    "patterns": [
                        r"\b(?:verify|confirm|re-?authenticate|reset)\b.{0,60}\b(?:account|identity|mailbox|password|credentials?)\b",
                        r"\bpassword\s+(?:expired|expires?|reset|required)\b",
                        r"\bunusual\s+sign-?in\b.{0,60}\b(?:verify|confirm)\b",
                    ],
                },
                {
                    "id": "collab_credentials_sheet_lure",
                    "label": "Collaboration mention + credentials sheet lure",
                    "severity": "high",
                    "theme": "credential",
                    "weight": 0.28,
                    "requires_url": True,
                    "impact": "Impersonated collaboration alert requesting credential file access.",
                    "patterns": [
                        r"\byou were mentioned\b",
                        r"\btagged you\b.{0,80}\b(?:comment|project|ticket)\b",
                        r"\b(?:updated|latest|new)\s+credentials?\s+(?:sheet|file|doc(?:ument)?)\b",
                    ],
                },
                {
                    "id": "invoice_wire_reroute",
                    "label": "Invoice / wire rerouting BEC pattern",
                    "severity": "high",
                    "theme": "bec",
                    "weight": 0.24,
                    "requires_url": True,
                    "impact": "Payment diversion or business email compromise.",
                    "patterns": [
                        r"\b(?:invoice|payment)\b.{0,120}\b(?:past due|overdue|due today)\b",
                        r"\b(?:wire|ach|bank)\s+(?:instructions?|details?)\s+(?:updated|changed)\b",
                        r"\b(?:new|updated)\s+beneficiary\b",
                    ],
                },
                {
                    "id": "gift_card_exec_impersonation",
                    "label": "Executive gift-card impersonation scam",
                    "severity": "high",
                    "theme": "bec",
                    "weight": 0.24,
                    "requires_url": False,
                    "impact": "Direct financial theft via social engineering.",
                    "patterns": [
                        r"\bgift\s*card\b",
                        r"\b(?:can't|cannot)\s+talk\b",
                        r"\bsend\s+(?:the\s+)?(?:pin|code|photos?)\b",
                        r"\b(?:apple|google\s*play|amazon|target)\s+gift\s*card\b",
                    ],
                },
                {
                    "id": "delivery_redelivery_scam",
                    "label": "Delivery redelivery payment lure",
                    "severity": "medium",
                    "theme": "delivery",
                    "weight": 0.20,
                    "requires_url": True,
                    "impact": "Phishing/payment capture through fake parcel notifications.",
                    "patterns": [
                        r"\b(?:missed|failed)\s+(?:delivery|package)\b",
                        r"\b(?:redelivery|re-?delivery)\b",
                        r"\bdelivery\s+fee\b",
                    ],
                },
                {
                    "id": "mfa_push_fatigue",
                    "label": "MFA push fatigue lure",
                    "severity": "high",
                    "theme": "mfa",
                    "weight": 0.22,
                    "requires_url": False,
                    "impact": "Unauthorized access if repeated MFA prompts are approved.",
                    "patterns": [
                        r"\b(?:approve|accept)\b.{0,40}\bmfa\b",
                        r"\brepeated\s+mfa\s+prompts?\b",
                        r"\bpush\s+notification\b.{0,40}\bapprove\b",
                    ],
                },
                {
                    "id": "bank_transfer_reversal_pressure",
                    "label": "Unauthorized transfer reversal pressure",
                    "severity": "high",
                    "theme": "finance",
                    "weight": 0.30,
                    "requires_url": True,
                    "impact": "High-confidence banking fraud lure with urgency.",
                    "patterns": [
                        r"\b(?:suspicious|unauthori[sz]ed)\s+(?:transfer|transaction|payment)\b",
                        r"\bif\s+unauthori[sz]ed\b.{0,40}\b(?:cancel|reverse|stop)\b",
                        r"\b(?:transfer|transaction)\s+will\s+be\s+processed\b",
                    ],
                },
                {
                    "id": "direct_money_request_link_lure",
                    "label": "Direct money request with embedded link",
                    "severity": "high",
                    "theme": "finance",
                    "weight": 0.28,
                    "requires_url": True,
                    "impact": "Likely advance-fee or impersonation scam requesting direct transfer.",
                    "patterns": [
                        r"\b(?:send|transfer|wire|pay)\s+(?:me\s+)?(?:\$|usd|aud|eur|gbp|cad|sgd)\s*[\d,]+(?:\.\d{2})?\b",
                        r"\b(?:using|via)\s+the\s+following\s+link\b",
                        r"\b(?:send|transfer|wire)\s+funds?\s+now\b",
                    ],
                },
                {
                    "id": "tech_support_remote_access",
                    "label": "Tech-support remote access scam",
                    "severity": "high",
                    "theme": "tech_support",
                    "weight": 0.23,
                    "requires_url": True,
                    "impact": "Potential remote compromise and fraudulent support payment.",
                    "patterns": [
                        r"\b(?:microsoft|windows|apple)\s+(?:support|security)\s+alert\b",
                        r"\b(?:install|open)\s+(?:teamviewer|anydesk|remote\s+desktop)\b",
                        r"\bcall\s+support\s+now\b",
                    ],
                },
            ],
        }

    def _coerce_fraud_pattern_pack(self, raw: Any, *, source_path: str, source_type: str) -> Dict[str, Any]:
        patterns_raw = []
        version = "unknown"
        if isinstance(raw, dict):
            version = str(raw.get("version") or version)
            candidate = raw.get("patterns")
            if isinstance(candidate, list):
                patterns_raw = candidate
        elif isinstance(raw, list):
            patterns_raw = raw

        patterns: List[Dict[str, Any]] = []
        for idx, item in enumerate(patterns_raw):
            if not isinstance(item, dict):
                continue
            pid = str(item.get("id") or f"fraud_pattern_{idx+1}").strip()
            label = str(item.get("label") or pid).strip()
            severity = str(item.get("severity") or "medium").strip().lower()
            theme = str(item.get("theme") or "generic").strip().lower()
            impact = str(item.get("impact") or "Elevated phishing/spam risk indicator.").strip()
            requires_url = bool(item.get("requires_url", False))
            weight = self._clamp01(self._safe_float(item.get("weight"), 0.15))
            patterns_src = item.get("patterns")
            if isinstance(patterns_src, str):
                patterns_src = [patterns_src]
            if not isinstance(patterns_src, list):
                continue
            compiled: List[re.Pattern[str]] = []
            for pattern in patterns_src:
                token = str(pattern or "").strip()
                if not token:
                    continue
                try:
                    compiled.append(re.compile(token, flags=re.IGNORECASE | re.DOTALL))
                except Exception:
                    continue
            if not compiled:
                continue
            patterns.append(
                {
                    "id": pid,
                    "label": label,
                    "severity": severity,
                    "theme": theme,
                    "impact": impact,
                    "weight": weight,
                    "requires_url": requires_url,
                    "regex": compiled,
                }
            )

        return {
            "version": version,
            "patterns": patterns,
            "source_path": source_path,
            "source_type": source_type,
            "loaded_at": datetime.now(timezone.utc).isoformat(),
        }

    def reload_fraud_pattern_pack(self, path: Optional[str] = None) -> Dict[str, Any]:
        pack_path = path or self._fraud_pattern_pack_path()
        try:
            if pack_path and os.path.exists(pack_path):
                with open(pack_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw = json.load(f)
                pack = self._coerce_fraud_pattern_pack(raw, source_path=pack_path, source_type="file")
            else:
                pack = self._coerce_fraud_pattern_pack(
                    self._default_fraud_pattern_pack(),
                    source_path=pack_path,
                    source_type="builtin_fallback",
                )
            self._fraud_pattern_pack = pack
            return {
                "reloaded": True,
                "pattern_count": len(pack.get("patterns") or []),
                "version": pack.get("version"),
                "source_type": pack.get("source_type"),
                "path": pack_path,
            }
        except Exception as e:
            logger.error(f"Failed to reload fraud pattern pack: {e}")
            self._fraud_pattern_pack = self._coerce_fraud_pattern_pack(
                self._default_fraud_pattern_pack(),
                source_path=pack_path,
                source_type="builtin_fallback",
            )
            return {
                "reloaded": False,
                "error": str(e),
                "pattern_count": len((self._fraud_pattern_pack or {}).get("patterns") or []),
                "source_type": "builtin_fallback",
                "path": pack_path,
            }

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = float(len(value))
        return -sum((count / length) * math.log2(count / length) for count in counts.values() if count > 0)

    def _domain_lexical_risk(self, host: str) -> float:
        if not host:
            return 0.0
        normalized = host.lower().strip(".")
        entropy = self._shannon_entropy(normalized)
        digits = sum(ch.isdigit() for ch in normalized)
        alpha_num = sum(ch.isalnum() for ch in normalized)
        digit_ratio = (digits / alpha_num) if alpha_num > 0 else 0.0
        hyphen_count = normalized.count("-")
        dot_count = normalized.count(".")
        score = 0.0
        if entropy >= 3.8:
            score += 0.25
        if digit_ratio >= 0.30:
            score += 0.20
        if hyphen_count >= 2:
            score += 0.15
        if len(normalized) >= 32:
            score += 0.15
        if dot_count >= 3:
            score += 0.10
        if normalized.startswith("xn--"):
            score += 0.15
        return min(0.95, score)

    def _trusted_brand_tokens(self) -> Dict[str, str]:
        defaults = {
            "adobe.com",
            "amazon.com",
            "apple.com",
            "atlassian.com",
            "ato.gov.au",
            "docusign.com",
            "dropbox.com",
            "facebook.com",
            "github.com",
            "gitlab.com",
            "google.com",
            "linkedin.com",
            "microsoft.com",
            "netflix.com",
            "office.com",
            "office365.com",
            "paypal.com",
            "salesforce.com",
            "servicenow.com",
            "slack.com",
            "stripe.com",
            "whatsapp.com",
            "youtube.com",
            "zoom.us",
        }
        for spec in self._courier_brand_catalog().values():
            defaults.update(str(domain).lower() for domain in spec.get("domains", set()))
        domains = defaults | set(self._allowlist_domains or set())
        out: Dict[str, str] = {}
        for domain in domains:
            base = self._base_domain(str(domain or "").strip().lower())
            if not base or self._is_ip_literal(base):
                continue
            label = base.split(".", 1)[0]
            token = re.sub(r"[^a-z0-9]", "", label.lower())
            if len(token) >= 3:
                out[token] = base
        return out

    def _brand_impersonation_signal(self, host: str) -> Optional[Dict[str, Any]]:
        h = str(host or "").strip().lower()
        if not h or self._is_ip_literal(h):
            return None
        base = self._base_domain(h)
        allowlist = self._allowlist_domains or set()
        if h in allowlist or base in allowlist:
            return None
        sld = base.split(".", 1)[0] if "." in base else base
        compact = re.sub(r"[^a-z0-9]", "", sld.lower())
        if len(compact) < 4:
            return None
        leet_compact = compact.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}))
        for brand, trusted_domain in self._trusted_brand_tokens().items():
            if base == trusted_domain or brand == compact:
                continue
            if len(brand) < 4:
                continue
            exact_token = brand in compact or brand in leet_compact
            fuzzy_token = SequenceMatcher(None, leet_compact, brand).ratio() >= 0.86
            if exact_token or fuzzy_token:
                return {
                    "host": h,
                    "base_domain": base,
                    "brand": brand,
                    "trusted_domain": trusted_domain,
                    "match_type": "token" if exact_token else "fuzzy",
                }
        return None

    def _domain_reputation_score(self, host: str) -> Tuple[float, str]:
        h = str(host or "").strip().lower()
        if not h:
            return 0.0, "none"
        base = self._base_domain(h)
        allowlist = self._allowlist_domains or set()
        blocklist = self._blocklist_domains or set()
        rep = self._domain_reputation or {}

        if h in allowlist or base in allowlist:
            return 0.0, "allowlist"
        if h in blocklist or base in blocklist:
            return 1.0, "blocklist"
        if h in rep:
            return self._clamp01(float(rep[h])), "reputation_map"
        if base in rep:
            return self._clamp01(float(rep[base])), "reputation_map"
        return self._domain_lexical_risk(h), "lexical"

    def _apply_yaml_policy_overrides(self) -> None:
        if yaml is None:
            return
        try:
            policy_path = Path(__file__).resolve().parents[1] / "security" / "prevention_rules.yml"
            if not policy_path.exists():
                return
            with open(policy_path, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp) or {}
            section = (data or {}).get("spam_detection") if isinstance(data, dict) else None
            if not isinstance(section, dict):
                return
            thr = section.get("final_threshold")
            if thr is not None:
                try:
                    self._final_threshold_override = float(thr)
                except Exception:
                    pass
            tlds = section.get("suspicious_tlds")
            if isinstance(tlds, list):
                vals = [str(x).strip().lower() for x in tlds if str(x).strip()]
                if vals:
                    self._suspicious_tlds_override = vals
            thresholds = section.get("thresholds")
            if isinstance(thresholds, dict):
                parsed_thresholds: Dict[str, float] = {}
                for k in ("allow", "suspicious", "block", "ood"):
                    if isinstance(thresholds.get(k), (int, float)):
                        parsed_thresholds[k] = self._clamp01(float(thresholds[k]))
                if parsed_thresholds:
                    self._thresholds_override = parsed_thresholds
            weights = section.get("feature_weights")
            if isinstance(weights, dict):
                parsed_weights: Dict[str, float] = {}
                for k in ("classical", "transformer", "online", "heuristic", "reputation", "campaign", "header", "fraud_pattern"):
                    if isinstance(weights.get(k), (int, float)):
                        parsed_weights[k] = max(0.0, float(weights[k]))
                if parsed_weights:
                    self._feature_weights_override = parsed_weights
            calibration = section.get("calibration")
            if isinstance(calibration, dict):
                parsed_calib: Dict[str, float] = {}
                if isinstance(calibration.get("a"), (int, float)):
                    parsed_calib["a"] = float(calibration["a"])
                if isinstance(calibration.get("b"), (int, float)):
                    parsed_calib["b"] = float(calibration["b"])
                if parsed_calib:
                    self._calibration_override = parsed_calib
        except Exception as e:
            logger.warning(f"Failed to apply spam policy overrides from YAML: {e}")

    @classmethod
    def get_instance(cls) -> 'SpamDetectionService':
        if cls._instance is None:
            raise RuntimeError("SpamDetectionService has not been initialized.")
        return cls._instance

    def is_model_loaded(self) -> bool:
        return self._spam_detection_pipeline is not None or self._transformer_pipeline is not None

    # --- Online learner (HashingVectorizer + SGD) ---
    def _online_model_path(self) -> str:
        from pathlib import Path
        return str(Path(__file__).resolve().parents[1] / 'data' / 'models_store' / 'spam_online_sgd.joblib')

    def _load_online_model(self):
        try:
            return joblib.load(self._online_model_path())
        except Exception:
            return None

    def _save_online_model(self, model) -> None:
        try:
            joblib.dump(model, self._online_model_path())
        except Exception as e:
            logger.error(f"Failed to save online model: {e}")

    def submit_feedback(self, text: str, label: str) -> Dict[str, Any]:
        """Update online learner with labeled sample; persist to disk."""
        from sklearn.linear_model import SGDClassifier
        from sklearn.feature_extraction.text import HashingVectorizer
        from sklearn.pipeline import make_pipeline
        y = 1 if str(label).lower() == 'spam' else 0
        model = self._load_online_model()
        if model is None:
            model = make_pipeline(HashingVectorizer(n_features=2**18, alternate_sign=False), SGDClassifier(loss='log_loss'))
            try:
                # Initialize classes
                model.named_steps['sgdclassifier'].partial_fit(model.named_steps['hashingvectorizer'].transform([""]), [0], classes=[0,1])
            except Exception:
                pass
        try:
            X = [text]
            model.named_steps['sgdclassifier'].partial_fit(model.named_steps['hashingvectorizer'].transform(X), [y])
            self._save_online_model(model)
        except Exception as e:
            logger.error(f"Online learner update failed: {e}")
        try:
            from pathlib import Path
            fb_path = Path(__file__).resolve().parents[1] / 'data' / 'models_store' / 'spam_feedback.jsonl'
            fb_path.parent.mkdir(parents=True, exist_ok=True)
            with open(fb_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps({"text": text[:1000], "label": y}) + "\n")
        except Exception:
            pass
        return {"online_updated": True}

    def _preprocess_email_text_for_spam(self, text: str) -> str:
        normalized = self._normalize_obfuscated_text(text)
        return re.sub(r"\s+", " ", normalized.lower()).strip()

    def _normalize_obfuscated_text(self, text: Optional[str]) -> str:
        if not isinstance(text, str):
            return ""
        value = html_lib.unescape(unicodedata.normalize("NFKC", text))
        value = re.sub(r"[\u200B-\u200D\u2060\uFEFF]", "", value)  # zero-width chars
        value = re.sub(r"(?i)\bhxxps://", "https://", value)
        value = re.sub(r"(?i)\bhxxp://", "http://", value)
        value = re.sub(r"(?i)\b(https?|ftp)\s*:\s*/\s*/", r"\1://", value)
        value = re.sub(r"(?i)\bwww\s*\.\s*", "www.", value)
        value = re.sub(r"(?i)\[\s*\.\s*\]", ".", value)
        value = re.sub(r"(?i)\(\s*dot\s*\)", ".", value)
        value = re.sub(r"(?i)\{\s*dot\s*\}", ".", value)
        value = re.sub(r"(?i)\[\s*at\s*\]", "@", value)
        value = re.sub(r"(?i)\(\s*at\s*\)", "@", value)
        value = re.sub(r"(?i)\[\s*/\s*\]", "/", value)
        value = re.sub(r"(?i)\(\s*slash\s*\)", "/", value)
        value = re.sub(r"[ \t\r\f\v]+", " ", value)
        return value

    def _deobfuscate_leetspeak_tokens(self, text: Optional[str]) -> str:
        if not isinstance(text, str):
            return ""
        table = str.maketrans({
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "@": "a",
            "$": "s",
            "!": "i",
        })
        pattern = re.compile(
            r"(?i)(?<![A-Za-z0-9@!$])"
            r"(?=[A-Za-z0-9@!$]{4,})"
            r"(?=[A-Za-z0-9@!$]*[A-Za-z@!$])"
            r"(?=[A-Za-z0-9@!$]*[0-9@!$])"
            r"[A-Za-z0-9@!$]+"
            r"(?![A-Za-z0-9@!$])"
        )
        return pattern.sub(lambda m: m.group(0).translate(table), text)

    def _email_domain_from_value(self, raw_value: Optional[str]) -> str:
        raw = str(raw_value or "").strip()
        if not raw:
            return ""
        m = re.search(r"<([^>]+)>", raw)
        email = m.group(1).strip() if m else raw
        if "@" in email:
            domain = email.split("@")[-1].strip().lower()
            domain = domain.strip("[]()<> ")
            return self._base_domain(domain)
        return ""

    def _strip_html_to_text(self, value: Optional[str]) -> str:
        raw = str(value or "")
        if not raw:
            return ""
        raw = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", raw)
        raw = re.sub(r"(?i)<br\s*/?>", "\n", raw)
        raw = re.sub(r"(?i)</p\s*>", "\n", raw)
        raw = re.sub(r"(?s)<[^>]+>", " ", raw)
        return re.sub(r"[ \t\r\f\v]+", " ", html_lib.unescape(raw)).strip()

    def _looks_like_raw_rfc822_email(self, value: Optional[str]) -> bool:
        raw = str(value or "")
        if not raw or "\n" not in raw:
            return False
        head = raw.split("\n\n", 1)[0]
        if len(head) > 12000:
            return False
        header_lines = [line for line in head.splitlines() if line.strip()]
        if not header_lines:
            return False
        field_count = sum(1 for line in header_lines if re.match(r"^[A-Za-z][A-Za-z0-9-]{1,63}\s*:", line))
        has_mail_header = bool(
            re.search(
                r"(?im)^(?:from|sender|subject|reply-to|return-path|authentication-results|arc-authentication-results|received|received-spf|mime-version|dkim-signature)\s*:",
                head,
            )
        )
        return field_count >= 2 and has_mail_header

    def _extract_message_bodies(self, msg: Any) -> Tuple[str, str]:
        plain_parts: List[str] = []
        html_parts: List[str] = []
        parts = msg.walk() if getattr(msg, "is_multipart", lambda: False)() else [msg]
        for part in parts:
            try:
                if getattr(part, "is_multipart", lambda: False)():
                    continue
                disposition = str(part.get_content_disposition() or "").lower()
                if disposition == "attachment":
                    continue
                content_type = str(part.get_content_type() or "").lower()
                content = part.get_content()
            except Exception:
                continue
            if isinstance(content, bytes):
                try:
                    content = content.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    content = content.decode("utf-8", errors="replace")
            text = str(content or "").strip()
            if not text:
                continue
            if content_type == "text/plain":
                plain_parts.append(text)
            elif content_type == "text/html":
                html_parts.append(text)

        plain = "\n".join(plain_parts).strip()
        html_value = "\n".join(html_parts).strip()
        if not plain and html_value:
            plain = self._strip_html_to_text(html_value)
        return plain, html_value

    def _parse_raw_email_payload(
        self,
        *,
        subject: Optional[str],
        body_text: Optional[str],
        body_html: Optional[str],
        headers: Optional[Dict[str, Any]],
        sender_email: Optional[str],
    ) -> Dict[str, Any]:
        raw_body = str(body_text or "")
        if not self._looks_like_raw_rfc822_email(raw_body):
            return {
                "subject": subject,
                "body_text": body_text,
                "body_html": body_html,
                "headers": headers,
                "sender_email": sender_email,
                "parsed_raw_email": False,
            }
        try:
            msg = Parser(policy=policy.default).parsestr(raw_body)
        except Exception:
            return {
                "subject": subject,
                "body_text": body_text,
                "body_html": body_html,
                "headers": headers,
                "sender_email": sender_email,
                "parsed_raw_email": False,
            }

        parsed_headers: Dict[str, str] = {}
        for key, value in msg.items():
            clean_key = str(key or "").strip()
            if not clean_key:
                continue
            clean_value = str(value or "").strip()
            if clean_key in parsed_headers and clean_value:
                parsed_headers[clean_key] = f"{parsed_headers[clean_key]}\n{clean_value}"
            else:
                parsed_headers[clean_key] = clean_value

        plain_body, html_body = self._extract_message_bodies(msg)
        merged_headers: Dict[str, Any] = dict(parsed_headers)
        if isinstance(headers, dict):
            merged_headers.update(headers)

        parsed_subject = str(msg.get("Subject") or "").strip()
        parsed_sender = str(msg.get("From") or msg.get("Sender") or "").strip()
        return {
            "subject": subject or parsed_subject or None,
            "body_text": plain_body or body_text,
            "body_html": body_html or html_body or None,
            "headers": merged_headers or headers,
            "sender_email": sender_email or parsed_sender or None,
            "parsed_raw_email": True,
        }

    def _header_auth_indicators(
        self,
        headers: Optional[Dict[str, Any]],
        sender_email: Optional[str],
        url_hosts: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "available": False,
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
            "reply_to_domain": "",
            "return_path_domain": "",
            "from_header_domain": "",
            "sender_domain": "",
            "reply_to_mismatch": False,
            "return_path_mismatch": False,
            "from_header_mismatch": False,
            "domain_mismatch_with_urls": False,
            "score": 0.0,
            "reasons": [],
        }
        if not isinstance(headers, dict) or not headers:
            return out

        header_map = {str(k).strip().lower(): str(v or "").strip() for k, v in headers.items()}
        if not header_map:
            return out
        out["available"] = True
        sender_domain = self._email_domain_from_value(sender_email)
        out["sender_domain"] = sender_domain

        auth_blob = " ".join(
            [
                header_map.get("authentication-results", ""),
                header_map.get("arc-authentication-results", ""),
                header_map.get("received-spf", ""),
            ]
        ).lower()
        if "spf=pass" in auth_blob or re.search(r"received-spf\s*:\s*pass", auth_blob):
            out["spf"] = "pass"
        elif "spf=softfail" in auth_blob:
            out["spf"] = "softfail"
        elif "spf=fail" in auth_blob:
            out["spf"] = "fail"
        elif "spf=neutral" in auth_blob:
            out["spf"] = "neutral"
        elif "spf=none" in auth_blob:
            out["spf"] = "none"

        if "dkim=pass" in auth_blob:
            out["dkim"] = "pass"
        elif "dkim=fail" in auth_blob:
            out["dkim"] = "fail"
        elif "dkim=none" in auth_blob:
            out["dkim"] = "none"

        if "dmarc=pass" in auth_blob:
            out["dmarc"] = "pass"
        elif "dmarc=fail" in auth_blob:
            out["dmarc"] = "fail"
        elif "dmarc=none" in auth_blob:
            out["dmarc"] = "none"

        reply_to_domain = self._email_domain_from_value(header_map.get("reply-to"))
        return_path_domain = self._email_domain_from_value(header_map.get("return-path"))
        from_header_domain = self._email_domain_from_value(header_map.get("from"))
        out["reply_to_domain"] = reply_to_domain
        out["return_path_domain"] = return_path_domain
        out["from_header_domain"] = from_header_domain

        if sender_domain and reply_to_domain and reply_to_domain != sender_domain:
            out["reply_to_mismatch"] = True
            out["reasons"].append("reply_to_domain_mismatch")
        if sender_domain and return_path_domain and return_path_domain != sender_domain:
            out["return_path_mismatch"] = True
            out["reasons"].append("return_path_domain_mismatch")
        if sender_domain and from_header_domain and from_header_domain != sender_domain:
            out["from_header_mismatch"] = True
            out["reasons"].append("from_header_domain_mismatch")

        if sender_domain and url_hosts:
            base_hosts = {self._base_domain(str(h)) for h in (url_hosts or []) if str(h).strip()}
            if base_hosts and all((h and h != sender_domain) for h in base_hosts):
                out["domain_mismatch_with_urls"] = True
                out["reasons"].append("sender_domain_vs_url_domain_mismatch")

        score = 0.0
        dmarc_result = str(out["dmarc"])
        dkim_result = str(out["dkim"])
        spf_result = str(out["spf"])
        if dmarc_result == "fail":
            score += 0.32
            out["reasons"].append("dmarc_fail")
        elif dmarc_result in {"none", "unknown"}:
            score += 0.08
        if dkim_result == "fail":
            score += 0.24
            out["reasons"].append("dkim_fail")
        elif dkim_result in {"none", "unknown"}:
            score += 0.06
        if spf_result in {"fail", "softfail"}:
            score += 0.18 if spf_result == "fail" else 0.11
            out["reasons"].append("spf_fail")
        elif spf_result in {"none", "neutral", "unknown"}:
            score += 0.04

        if out["reply_to_mismatch"]:
            score += 0.16
        if out["return_path_mismatch"]:
            score += 0.12
        if out["from_header_mismatch"]:
            score += 0.12
        if out["domain_mismatch_with_urls"]:
            score += 0.12

        out["score"] = self._clamp01(score)
        return out

    def _trusted_aligned_url_context(
        self,
        *,
        url_indicators: Dict[str, Any],
        sender_email: Optional[str],
        header_indicators: Dict[str, Any],
    ) -> bool:
        total_urls = int(url_indicators.get("total_urls", 0) or 0)
        unique_hosts = int(url_indicators.get("unique_hosts", 0) or 0)
        allowlisted_count = int(url_indicators.get("allowlisted_count", 0) or 0)
        if total_urls <= 0 or unique_hosts <= 0 or allowlisted_count < unique_hosts:
            return False
        if int(url_indicators.get("blocklisted_count", 0) or 0) > 0:
            return False
        if int(url_indicators.get("reputation_high", 0) or 0) > 0 or int(url_indicators.get("reputation_medium", 0) or 0) > 0:
            return False
        if int(url_indicators.get("brand_impersonation_count", 0) or 0) > 0:
            return False

        sender_domain = self._email_domain_from_value(sender_email)
        if not sender_domain:
            return False
        url_bases = {self._base_domain(str(host)) for host in (url_indicators.get("hosts") or []) if str(host).strip()}
        if not url_bases or any(base != sender_domain for base in url_bases):
            return False

        if bool(header_indicators.get("reply_to_mismatch")) or bool(header_indicators.get("return_path_mismatch")):
            return False
        if bool(header_indicators.get("from_header_mismatch")) or bool(header_indicators.get("domain_mismatch_with_urls")):
            return False
        if str(header_indicators.get("dmarc") or "").lower() == "fail":
            return False
        if str(header_indicators.get("dkim") or "").lower() == "fail":
            return False
        if str(header_indicators.get("spf") or "").lower() in {"fail", "softfail"}:
            return False
        return True

    def _extract_inline_email_fields(
        self,
        subject: Optional[str],
        body_text: Optional[str],
        sender_email: Optional[str],
    ) -> Dict[str, Any]:
        subject_value = str(subject or "").strip()
        body_value = str(body_text or "")
        sender_value = str(sender_email or "").strip()

        lines = body_value.splitlines()
        body_lines: List[str] = []
        consumed_indexes: set = set()

        for idx, line in enumerate(lines[:16]):
            raw = str(line or "").strip()
            if not raw:
                continue
            if not subject_value:
                m_sub = re.match(r"(?i)^subject\s*:\s*(.+)$", raw)
                if m_sub:
                    subject_value = m_sub.group(1).strip()
                    consumed_indexes.add(idx)
                    continue
            if not sender_value:
                m_sender = re.match(r"(?i)^(?:from|sender)\s*:\s*(.+)$", raw)
                if m_sender:
                    sender_value = m_sender.group(1).strip()
                    consumed_indexes.add(idx)
                    continue

        for idx, line in enumerate(lines):
            if idx in consumed_indexes:
                continue
            body_lines.append(line)

        normalized_body = "\n".join(body_lines).strip()
        return {
            "subject": subject_value or None,
            "body_text": normalized_body,
            "sender_email": sender_value or None,
            "parsed_inline_fields": bool(consumed_indexes),
        }

    def _extract_urls(self, text: str) -> List[str]:
        normalized = self._normalize_obfuscated_text(text)
        url_regex = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>'\"]+")
        # Capture bare and obfuscated domains (e.g. "www . sendme . ie", "secure-bank-alerts . co/reverse")
        domain_regex = re.compile(
            r"(?ix)"
            r"(?<!@)\b"
            r"(?:www\s*\.\s*)?"
            r"(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\s*\.\s*(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,4}"
            r"(?:\s*/\s*[^\s<>'\"]*)?"
        )
        urls: List[str] = []
        seen: set[str] = set()

        for m in url_regex.finditer(normalized or ""):
            raw = m.group(0)
            canonical = self._canonicalize_url_candidate(raw, allow_bare=False)
            if canonical and canonical not in seen:
                seen.add(canonical)
                urls.append(canonical)

        for m in domain_regex.finditer(normalized or ""):
            raw = m.group(0)
            start, end = m.span()
            context_window = normalized[max(0, start - 24): min(len(normalized), end + 24)]
            canonical = self._canonicalize_url_candidate(raw, allow_bare=True, context_window=context_window)
            if canonical and canonical not in seen:
                seen.add(canonical)
                urls.append(canonical)
        return urls

    def _suspicious_tld_set(self) -> set:
        override = getattr(self, "_suspicious_tlds_override", None)
        return set(
            x.strip().lower()
            for x in (
                override
                or (
                    os.getenv(
                        "SUSPICIOUS_TLDS",
                        "zip,top,work,xyz,country,click,link,live,site,online,icu",
                    ).lower().split(",")
                )
            )
            if str(x).strip()
        )

    def _accept_bare_domain_candidate(self, candidate: str, raw: str, context_window: Optional[str]) -> bool:
        candidate = str(candidate or "").strip()
        if not candidate:
            return False
        if not self._looks_like_domain(candidate):
            return False
        try:
            parsed = urlparse(f"https://{candidate}")
        except Exception:
            return False

        host = str(parsed.hostname or "").strip().lower()
        if not host:
            return False
        base = self._base_domain(host)
        labels = [p for p in host.split(".") if p]
        tld = labels[-1] if labels else ""
        raw_value = str(raw or "")
        context = str(context_window or "").lower()

        has_path_or_query = bool((parsed.path and parsed.path != "/") or parsed.query or parsed.fragment)
        known_domain = bool(
            (self._blocklist_domains and (host in self._blocklist_domains or base in self._blocklist_domains))
            or (self._allowlist_domains and (host in self._allowlist_domains or base in self._allowlist_domains))
            or (self._domain_reputation and (host in self._domain_reputation or base in self._domain_reputation))
        )
        suspicious_tld = bool(tld and tld in self._suspicious_tld_set())
        suspicious_shape = bool(host.count(".") >= 2 or "-" in host or any(ch.isdigit() for ch in host))
        context_hint = bool(
            re.search(
                r"(?i)\b(click|visit|open|verify|login|log\s*in|portal|link|url|secure|account|reset|confirm|sign[-\s]*in)\b",
                context,
            )
        )

        # Reject common sentence boundary artifacts like "payment. Your" unless we have strong URL evidence.
        sentence_boundary_artifact = bool(re.search(r"\.[ \t]+[A-Z]", raw_value))
        if sentence_boundary_artifact and not (known_domain or suspicious_shape or has_path_or_query or context_hint):
            return False

        if known_domain or suspicious_shape or suspicious_tld or has_path_or_query or context_hint:
            return True
        return False

    def _looks_like_domain(self, value: str) -> bool:
        host = str(value or "").strip().lower().strip(".")
        if not host or "@" in host:
            return False
        if "." not in host:
            return False
        domain_re = re.compile(
            r"(?i)^(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\.(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
        )
        if not domain_re.match(host):
            return False
        tld = host.rsplit(".", 1)[-1]
        return bool(re.match(r"(?i)^(?:xn--)?[a-z]{2,24}$", tld))

    def _canonicalize_url_candidate(
        self,
        raw: Optional[str],
        *,
        allow_bare: bool = True,
        context_window: Optional[str] = None,
    ) -> str:
        raw_value = str(raw or "")
        candidate = raw_value.strip().rstrip(".,);]>\"'")
        if not candidate:
            return ""
        candidate = candidate.replace("hxxps://", "https://").replace("hxxp://", "http://")
        candidate = re.sub(r"(?i)\b(https?|ftp)\s*:\s*/\s*/", r"\1://", candidate)
        candidate = re.sub(r"(?i)\bwww\s*\.\s*", "www.", candidate)
        candidate = re.sub(r"\s*\.\s*", ".", candidate)
        candidate = re.sub(r"\s*/\s*", "/", candidate)
        candidate = re.sub(r"\s+", "", candidate)
        if not candidate:
            return ""

        has_scheme = bool(re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", candidate))
        if candidate.lower().startswith("www."):
            candidate = f"https://{candidate}"
            has_scheme = True

        if not has_scheme:
            if not self._looks_like_domain(candidate):
                return ""
            if allow_bare and not self._accept_bare_domain_candidate(candidate, raw_value, context_window):
                return ""
            candidate = f"https://{candidate}"

        try:
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").strip().lower()
        except Exception:
            return ""
        if not host:
            return ""
        if not (self._looks_like_domain(host) or self._is_ip_literal(host)):
            return ""
        return candidate

    def _domain_of(self, url: str) -> str:
        try:
            normalized = str(url or "").replace("hxxp://", "http://").replace("hxxps://", "https://")
            host = urlparse(normalized).hostname or ""
            return host.lower()
        except Exception:
            return ""

    def _is_ip_literal(self, host: str) -> bool:
        parts = str(host or "").split(".")
        if len(parts) != 4:
            return False
        try:
            nums = [int(p) for p in parts]
        except Exception:
            return False
        return all(0 <= n <= 255 for n in nums)

    def _base_domain(self, host: str) -> str:
        h = str(host or "").strip(".").lower()
        if not h:
            return ""
        if self._is_ip_literal(h):
            return h
        parts = [p for p in h.split(".") if p]
        if len(parts) < 2:
            return h
        if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"}:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def _normalize_hostname(host: Optional[str]) -> str:
        value = str(host or "").strip().lower().strip(".")
        if not value:
            return ""
        if value.startswith("www."):
            value = value[4:]
        try:
            value = value.encode("ascii", errors="ignore").decode("idna")
        except Exception:
            pass
        return value.strip(".")

    @staticmethod
    def _courier_brand_catalog() -> Dict[str, Dict[str, Any]]:
        return {
            "dhl": {
                "label": "DHL",
                "aliases": {"dhl", "dhl express"},
                "domains": {"dhl.com", "dhl.com.au"},
            },
            "fedex": {
                "label": "FedEx",
                "aliases": {"fedex", "fed ex", "federal express"},
                "domains": {"fedex.com"},
            },
            "ups": {
                "label": "UPS",
                "aliases": {"ups", "united parcel service"},
                "domains": {"ups.com"},
            },
            "usps": {
                "label": "USPS",
                "aliases": {"usps", "united states postal service"},
                "domains": {"usps.com"},
            },
            "auspost": {
                "label": "Australia Post",
                "aliases": {"australia post", "auspost", "aus post"},
                "domains": {"auspost.com.au"},
            },
            "startrack": {
                "label": "StarTrack",
                "aliases": {"startrack", "star track"},
                "domains": {"startrack.com.au"},
            },
            "toll": {
                "label": "Toll",
                "aliases": {"toll"},
                "domains": {"tollgroup.com"},
            },
            "aramex": {
                "label": "Aramex",
                "aliases": {"aramex"},
                "domains": {"aramex.com.au", "aramex.com"},
            },
            "sendle": {
                "label": "Sendle",
                "aliases": {"sendle"},
                "domains": {"sendle.com"},
            },
            "amazon": {
                "label": "Amazon",
                "aliases": {"amazon", "amazon delivery", "amazon logistics"},
                "domains": {"amazon.com", "amazon.com.au"},
            },
            "royal_mail": {
                "label": "Royal Mail",
                "aliases": {"royal mail", "royalmail"},
                "domains": {"royalmail.com"},
            },
            "evri": {
                "label": "Evri",
                "aliases": {"evri", "hermes"},
                "domains": {"evri.com"},
            },
            "dpd": {
                "label": "DPD",
                "aliases": {"dpd"},
                "domains": {"dpd.com", "dpd.co.uk"},
            },
            "tnt": {
                "label": "TNT",
                "aliases": {"tnt"},
                "domains": {"tnt.com"},
            },
        }

    def _host_matches_official_domain(self, host: Optional[str], official_domains: Any) -> bool:
        normalized = self._normalize_hostname(host)
        if not normalized:
            return False
        for domain in official_domains or []:
            official = self._normalize_hostname(str(domain or ""))
            if official and (normalized == official or normalized.endswith(f".{official}")):
                return True
        return False

    def _detect_claimed_courier_brand(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        normalized = f" {str(text or '').lower()} "
        for brand, spec in self._courier_brand_catalog().items():
            aliases = sorted(spec.get("aliases", set()), key=len, reverse=True)
            for alias in aliases:
                token = re.escape(str(alias).lower())
                if re.search(rf"(?<![a-z0-9]){token}(?![a-z0-9])", normalized):
                    return brand, str(spec.get("label") or brand)
        return None, None

    def _url_indicators(self, text: str) -> Dict[str, Any]:
        urls = self._extract_urls(text)
        hosts = [self._domain_of(u) for u in urls if u]
        indicators: Dict[str, Any] = {
            "total_urls": len(urls),
            "unique_hosts": 0,
            "ip_urls": 0,
            "suspicious_tlds": 0,
            "punycode": 0,
            "blocklisted": [],
            "blocklisted_count": 0,
            "allowlisted": [],
            "allowlisted_count": 0,
            "shortened_urls": 0,
            "non_standard_ports": 0,
            "at_symbol_urls": 0,
            "encoded_url_count": 0,
            "long_url_count": 0,
            "excessive_subdomains": 0,
            "high_entropy_domains": 0,
            "brand_impersonation_count": 0,
            "brand_impersonation_hosts": [],
            "impersonated_brands": [],
            "reputation_high": 0,
            "reputation_medium": 0,
            "reputation_score_max": 0.0,
            "reputation_score_avg": 0.0,
            "lexical_risk_avg": 0.0,
            "hosts": hosts[:10],
            "reputation_sources": [],
        }
        suspicious_tlds = self._suspicious_tld_set()
        shorteners = set(
            x.strip().lower()
            for x in os.getenv(
                "URL_SHORTENER_DOMAINS",
                "bit.ly,t.co,tinyurl.com,goo.gl,rb.gy,is.gd,ow.ly,rebrand.ly,cutt.ly,shorturl.at",
            ).split(",")
            if x.strip()
        )

        reputation_scores: List[float] = []
        lexical_scores: List[float] = []
        rep_sources: List[str] = []
        unique_hosts: set = set()
        blocklisted: List[str] = []
        allowlisted: List[str] = []
        brand_impersonation: List[Dict[str, Any]] = []

        for idx, h in enumerate(hosts):
            if not h:
                continue
            unique_hosts.add(h)
            if h.startswith("xn--"):
                indicators["punycode"] += 1
            base = self._base_domain(h)
            tld = base.split('.')[-1] if '.' in base else base
            if tld in suspicious_tlds:
                indicators["suspicious_tlds"] += 1
            if self._is_ip_literal(h):
                indicators["ip_urls"] += 1
            if (self._blocklist_domains and (base in self._blocklist_domains or h in self._blocklist_domains)) and h not in blocklisted:
                blocklisted.append(h)
            if (self._allowlist_domains and (base in self._allowlist_domains or h in self._allowlist_domains)) and h not in allowlisted:
                allowlisted.append(h)

            rep_score, rep_source = self._domain_reputation_score(h)
            reputation_scores.append(rep_score)
            rep_sources.append(rep_source)
            lexical_scores.append(self._domain_lexical_risk(h))
            if rep_score >= 0.80:
                indicators["reputation_high"] += 1
            elif rep_score >= 0.55:
                indicators["reputation_medium"] += 1
            brand_signal = self._brand_impersonation_signal(h)
            if brand_signal and not any(item.get("host") == h for item in brand_impersonation):
                brand_impersonation.append(brand_signal)

            normalized_url = urls[idx].replace("hxxp://", "http://").replace("hxxps://", "https://")
            try:
                p = urlparse(normalized_url)
            except Exception:
                p = None
            if p:
                if p.port and p.port not in {80, 443}:
                    indicators["non_standard_ports"] += 1
                if "@" in (p.netloc or ""):
                    indicators["at_symbol_urls"] += 1
            if base in shorteners or h in shorteners:
                indicators["shortened_urls"] += 1
            if "%" in normalized_url:
                indicators["encoded_url_count"] += 1
            if len(normalized_url) >= 120:
                indicators["long_url_count"] += 1
            base_label_count = len([part for part in base.split(".") if part])
            host_label_count = len([part for part in h.split(".") if part])
            if max(0, host_label_count - base_label_count) >= 3:
                indicators["excessive_subdomains"] += 1
            if self._shannon_entropy(h) >= 3.9:
                indicators["high_entropy_domains"] += 1

        indicators["unique_hosts"] = len(unique_hosts)
        indicators["blocklisted"] = blocklisted[:10]
        indicators["blocklisted_count"] = len(blocklisted)
        indicators["allowlisted"] = allowlisted[:10]
        indicators["allowlisted_count"] = len(allowlisted)
        indicators["brand_impersonation_count"] = len(brand_impersonation)
        indicators["brand_impersonation_hosts"] = [str(item.get("host")) for item in brand_impersonation[:10]]
        indicators["impersonated_brands"] = sorted({str(item.get("brand")) for item in brand_impersonation if item.get("brand")})[:10]
        indicators["reputation_sources"] = rep_sources[:10]
        if reputation_scores:
            indicators["reputation_score_max"] = max(reputation_scores)
            indicators["reputation_score_avg"] = sum(reputation_scores) / len(reputation_scores)
        if lexical_scores:
            indicators["lexical_risk_avg"] = sum(lexical_scores) / len(lexical_scores)
        return indicators

    def _sender_indicators(self, sender: Optional[str], url_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        ind = {
            "sender": sender or "",
            "domain": "",
            "punycode": False,
            "ip_sender": False,
            "domain_mismatch_with_urls": False,
            "sender_reputation_score": 0.0,
            "sender_reputation_source": "none",
        }
        if not sender:
            return ind
        m = re.search(r"<([^>]+)>", sender)
        email = m.group(1) if m else sender
        dom = email.split('@')[-1].lower() if '@' in email else ""
        ind["domain"] = dom
        ind["punycode"] = dom.startswith("xn--")
        ind["ip_sender"] = self._is_ip_literal(dom)
        sender_rep, sender_source = self._domain_reputation_score(dom)
        ind["sender_reputation_score"] = sender_rep
        ind["sender_reputation_source"] = sender_source
        if dom and url_hosts:
            host_values = [str(h).lower() for h in url_hosts if h]
            if host_values:
                ind["domain_mismatch_with_urls"] = all(
                    not (h.endswith(dom) or dom.endswith(self._base_domain(h)))
                    for h in host_values
                )
        return ind

    def _heuristic_phishing_score(self, indicators: Dict[str, Any], sender_ind: Dict[str, Any]) -> float:
        score = 0.0
        score += min(0.22, 0.04 * max(0, int(indicators.get("total_urls", 0) or 0) - 1))
        score += 0.08 if int(indicators.get("unique_hosts", 0) or 0) >= 2 else 0.0
        score += 0.18 if int(indicators.get("ip_urls", 0) or 0) > 0 else 0.0
        score += 0.17 if int(indicators.get("suspicious_tlds", 0) or 0) > 0 else 0.0
        score += 0.18 if int(indicators.get("punycode", 0) or 0) > 0 else 0.0
        score += 0.35 if int(indicators.get("blocklisted_count", 0) or 0) > 0 else 0.0
        score += 0.28 if int(indicators.get("reputation_high", 0) or 0) > 0 else 0.0
        score += 0.12 if int(indicators.get("reputation_medium", 0) or 0) > 0 else 0.0
        score += 0.10 if int(indicators.get("shortened_urls", 0) or 0) > 0 else 0.0
        score += 0.08 if int(indicators.get("non_standard_ports", 0) or 0) > 0 else 0.0
        score += 0.05 if int(indicators.get("encoded_url_count", 0) or 0) > 0 else 0.0
        score += 0.08 if int(indicators.get("excessive_subdomains", 0) or 0) > 0 else 0.0
        score += 0.20 if int(indicators.get("brand_impersonation_count", 0) or 0) > 0 else 0.0
        score += min(0.12, float(indicators.get("reputation_score_avg", 0.0) or 0.0) * 0.12)
        score += 0.10 if sender_ind.get("punycode") else 0.0
        score += 0.12 if sender_ind.get("ip_sender") else 0.0
        score += 0.14 if sender_ind.get("domain_mismatch_with_urls") else 0.0
        score += min(0.10, float(sender_ind.get("sender_reputation_score", 0.0) or 0.0) * 0.10)
        return min(score, 0.99)

    def _bec_detection_text(self, *parts: Optional[str]) -> str:
        raw = "\n".join(str(part or "") for part in parts)
        raw = self._strip_html_to_text(raw)
        normalized = self._normalize_obfuscated_text(raw)
        normalized = self._deobfuscate_leetspeak_tokens(normalized)
        return re.sub(r"\s+", " ", normalized.lower()).strip()

    def detect_courier_delivery_phishing_signals(
        self,
        *,
        message: Optional[str],
        sender: Optional[str],
        subject: Optional[str],
        url_indicators: Optional[Dict[str, Any]] = None,
        header_indicators: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect courier/customs/redelivery fee phishing without inflating generic shipping mail."""
        indicators = url_indicators if isinstance(url_indicators, dict) else {}
        headers = header_indicators if isinstance(header_indicators, dict) else {}
        text = self._bec_detection_text(subject, message, sender)
        raw_text = f"{subject or ''}\n{message or ''}\n{sender or ''}"
        claimed_key, claimed_label = self._detect_claimed_courier_brand(raw_text)
        brand_spec = self._courier_brand_catalog().get(claimed_key or "", {})
        official_domains = set(str(x).lower() for x in (brand_spec.get("domains") or set()))

        def has(pattern: str) -> bool:
            return bool(re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL))

        generic_courier_lure = has(
            r"\b(?:courier|post|parcel|package|shipment|delivery|tracking|consignment|depot)\b"
        )
        fee_lure = has(
            r"\b(?:customs\s+(?:fee|clearance|handling)|handling\s+fee|unpaid\s+(?:customs|fee)|"
            r"delivery\s+fee|re-?delivery\s+fee|redelivery\s+fee|postage\s+fee|shipping\s+fee|"
            r"service\s+fee|payment\s+required|payment\s+pending|settle\s+(?:the\s+)?fee|"
            r"outstanding\s+fee|small\s+fee|card\s+payment|enter\s+card\s+details|update\s+payment|"
            r"pay\s+now|aud\s*\$?\s*\d|usd\s*\$?\s*\d|gbp\s*\$?\s*\d|eur\s*\$?\s*\d|\$\s*\d+(?:\.\d{2})?)\b"
        )
        customs_fee = has(r"\b(?:customs|clearance|handling\s+fee|unpaid\s+customs)\b")
        redelivery_fee = has(r"\b(?:redelivery|re-?delivery|delivery\s+fee|postage\s+fee|shipping\s+fee)\b")
        delivery_problem = has(
            r"\b(?:parcel|package|shipment|delivery)\s+(?:hold|held|failed|waiting|cannot\s+be\s+delivered|"
            r"unable\s+to\s+deliver|returned\s+to\s+sender|missed)\b"
        ) or has(
            r"\b(?:held\s+at\s+depot|address\s+issue|confirm\s+address|customs\s+hold|waiting\s+clearance|final\s+notice)\b"
        )
        urgency_or_threat = has(
            r"\b(?:within\s+\d+\s*(?:hours?|minutes?)|today|immediately|final\s+notice|will\s+be\s+returned|"
            r"returned\s+to\s+sender|before\s+delivery|avoid\s+return|last\s+reminder|deadline)\b"
        )
        tracking_lure = has(
            r"\b(?:tracking\s+(?:number|id)|shipment\s+id|parcel\s+number|consignment|reference\s+number)\b"
        )
        training_context = has(
            r"\b(?:training|awareness|how\s+to\s+identify|identify\s+.*scams?|scam\s+awareness|"
            r"policy\s+update|article|guide|education)\b"
        )
        directive_payment = has(
            r"\b(?:pay\s+now|click|open|visit|enter\s+card|update\s+payment|settle\s+(?:the\s+)?fee|"
            r"confirm\s+address|avoid\s+return)\b"
        )

        urls = self._extract_urls(raw_text)
        hosts: List[str] = []
        payment_paths: List[str] = []
        link_domains: List[str] = []
        non_official_hosts: List[str] = []
        tracking_like_hosts: List[str] = []
        brand_keyword_hosts: List[str] = []
        suspicious_url = False
        suspicious_payment_link = False

        brand_tokens = set()
        if claimed_key:
            brand_tokens.add(claimed_key.replace("_", ""))
            brand_tokens.update(re.sub(r"[^a-z0-9]", "", str(alias).lower()) for alias in brand_spec.get("aliases", set()))
            brand_tokens.discard("")

        for url in urls:
            normalized_url = str(url or "").replace("hxxp://", "http://").replace("hxxps://", "https://")
            try:
                parsed = urlparse(normalized_url)
            except Exception:
                continue
            host = self._normalize_hostname(parsed.hostname or "")
            if not host:
                continue
            hosts.append(host)
            base = self._base_domain(host)
            if base and base not in link_domains:
                link_domains.append(base)
            official = bool(claimed_key and self._host_matches_official_domain(host, official_domains))
            if claimed_key and not official:
                non_official_hosts.append(host)
            path = str(parsed.path or "").lower()
            if re.search(r"/(?:customer/)?(?:pay|payment|customs|redelivery|tracking|fees?|verify|card)(?:/|$)", path):
                payment_paths.append(path or "/")
                if not official:
                    suspicious_payment_link = True
            compact_host = re.sub(r"[^a-z0-9]", "", self._base_domain(host).split(".", 1)[0])
            if claimed_key and any(token and token in compact_host for token in brand_tokens) and not official:
                brand_keyword_hosts.append(host)
            if re.search(r"(?:post|parcel|track|tracking|delivery|redelivery|customs|pay|fees?)", host) and not official:
                tracking_like_hosts.append(host)
            rep_score = self._safe_float(indicators.get("reputation_score_max"), 0.0)
            if (
                suspicious_payment_link
                or brand_keyword_hosts
                or tracking_like_hosts
                or self._is_ip_literal(host)
                or host.startswith("xn--")
                or rep_score >= 0.55
                or (base.split(".")[-1] if "." in base else base) in self._suspicious_tld_set()
            ):
                suspicious_url = True

        url_hosts = hosts or [self._normalize_hostname(x) for x in (indicators.get("hosts") or []) if str(x).strip()]
        if not urls and url_hosts:
            link_domains = sorted({self._base_domain(host) for host in url_hosts if self._base_domain(host)})
            for host in url_hosts:
                official = bool(claimed_key and self._host_matches_official_domain(host, official_domains))
                if claimed_key and not official:
                    non_official_hosts.append(host)

        if any(re.search(r"(?:tracking|track|pay|payment|customs|redelivery|fees?)", h) for h in tracking_like_hosts + hosts):
            tracking_lure = True

        brand_domain_mismatch = bool(claimed_key and non_official_hosts)
        sender_domain = self._email_domain_from_value(sender)
        sender_domain_mismatch = bool(
            claimed_key
            and sender_domain
            and not self._host_matches_official_domain(sender_domain, official_domains)
        )
        if claimed_key and bool(headers.get("domain_mismatch_with_urls")):
            sender_domain_mismatch = True

        all_links_official = bool(
            claimed_key
            and url_hosts
            and all(self._host_matches_official_domain(host, official_domains) for host in url_hosts)
        )
        official_domain_context = bool(
            claimed_key
            and all_links_official
            and not sender_domain_mismatch
            and not suspicious_payment_link
        )

        if training_context and not directive_payment:
            return {
                "courier_phishing_score": 0.0,
                "courier_category": None,
                "claimed_brand": claimed_label,
                "brand_domain_mismatch": False,
                "sender_domain_mismatch": False,
                "suspicious_payment_link": False,
                "matched_patterns": [],
                "evidence_reasons": [],
                "severity_hint": "low",
                "risk_floor": None,
                "heuristic_floor": 0.0,
                "recommended_handling_hint": None,
                "link_domains": link_domains,
                "payment_paths": [],
                "delivery_lure": generic_courier_lure,
                "payment_fee_lure": False,
                "urgency_or_threat": False,
                "tracking_lure": False,
                "official_domain_context": official_domain_context,
                "hard_signal": False,
            }

        score = 0.0
        risk_floor: Optional[float] = None
        category: Optional[str] = None
        severity = "low"
        handling: Optional[str] = None
        matched: List[str] = []
        reasons: List[str] = []

        if claimed_key:
            matched.append("claimed_courier_brand")
            reasons.append(f"Claimed courier identity: {claimed_label}.")
            score += 0.18
        elif generic_courier_lure:
            matched.append("generic_courier_lure")
            score += 0.10

        if fee_lure:
            matched.append("payment_or_fee_lure")
            reasons.append("Courier delivery/customs fee payment lure detected.")
            score += 0.24
        if delivery_problem:
            matched.append("delivery_problem_lure")
            score += 0.12
        if urgency_or_threat:
            matched.append("urgency_or_return_threat")
            reasons.append("Urgency/return-to-sender threat increases phishing risk.")
            score += 0.14
        if tracking_lure:
            matched.append("tracking_lure")
            reasons.append("Tracking-number or tracking-domain language is used to increase legitimacy.")
            score += 0.08
        if suspicious_payment_link:
            matched.append("suspicious_payment_link")
            reasons.append("Payment or customs path is hosted on a non-official courier domain.")
            score += 0.24
        if brand_domain_mismatch:
            matched.append("brand_domain_mismatch")
            label = claimed_label or "claimed courier"
            reasons.append(f"Claimed {label} identity but link domain is not an official {label} domain.")
            score += 0.22
        if sender_domain_mismatch:
            matched.append("sender_domain_mismatch")
            reasons.append("Sender domain does not align with the claimed courier brand.")
            score += 0.12
        if suspicious_url and not suspicious_payment_link:
            matched.append("suspicious_url_or_domain")
            score += 0.10

        if official_domain_context and not fee_lure and not directive_payment:
            score = min(score, 0.25)
            matched = [x for x in matched if x == "claimed_courier_brand"]
            reasons = ["Official courier-domain context with no payment or credential pressure."]
        elif claimed_key and fee_lure and (suspicious_payment_link or brand_domain_mismatch or suspicious_url):
            category = "courier_customs_fee_phishing" if customs_fee else "delivery_redelivery_fee_phishing"
            severity = "high"
            handling = "block"
            floor = 0.85 if (customs_fee and urgency_or_threat and (suspicious_payment_link or brand_domain_mismatch)) else 0.82
            risk_floor = max(risk_floor or 0.0, floor)
            score = max(score, 0.94 if floor >= 0.85 else 0.90)
        elif generic_courier_lure and fee_lure and (suspicious_payment_link or suspicious_url):
            category = "delivery_redelivery_fee_phishing" if redelivery_fee else "package_hold_phishing"
            severity = "high"
            handling = "block"
            risk_floor = max(risk_floor or 0.0, 0.75)
            score = max(score, 0.82)
        elif tracking_lure and suspicious_payment_link and tracking_like_hosts:
            category = "tracking_link_phishing"
            severity = "high"
            handling = "block"
            risk_floor = max(risk_floor or 0.0, 0.78)
            score = max(score, 0.84)
        elif brand_domain_mismatch:
            category = "courier_brand_impersonation"
            severity = "medium"
            handling = "review"
            risk_floor = max(risk_floor or 0.0, 0.62)
            score = max(score, 0.68)
        elif fee_lure and suspicious_payment_link:
            category = "payment_link_impersonation"
            severity = "medium"
            handling = "review"
            risk_floor = max(risk_floor or 0.0, 0.65)
            score = max(score, 0.70)

        if not category:
            return {
                "courier_phishing_score": self._clamp01(score if score >= 0.35 else 0.0),
                "courier_category": None,
                "claimed_brand": claimed_label,
                "brand_domain_mismatch": brand_domain_mismatch,
                "sender_domain_mismatch": sender_domain_mismatch,
                "suspicious_payment_link": suspicious_payment_link,
                "matched_patterns": matched,
                "evidence_reasons": reasons,
                "severity_hint": severity,
                "risk_floor": None,
                "heuristic_floor": 0.0,
                "recommended_handling_hint": None,
                "link_domains": link_domains,
                "payment_paths": payment_paths[:5],
                "delivery_lure": generic_courier_lure or delivery_problem,
                "payment_fee_lure": fee_lure,
                "urgency_or_threat": urgency_or_threat,
                "tracking_lure": tracking_lure,
                "official_domain_context": official_domain_context,
                "hard_signal": False,
            }

        return {
            "courier_phishing_score": self._clamp01(score),
            "courier_category": category,
            "claimed_brand": claimed_label,
            "brand_domain_mismatch": brand_domain_mismatch,
            "sender_domain_mismatch": sender_domain_mismatch,
            "suspicious_payment_link": suspicious_payment_link,
            "matched_patterns": matched,
            "evidence_reasons": reasons,
            "severity_hint": severity,
            "risk_floor": self._clamp01(risk_floor) if risk_floor is not None else None,
            "heuristic_floor": self._clamp01(max(0.0, min(0.90, score - 0.08))),
            "recommended_handling_hint": handling,
            "link_domains": link_domains,
            "payment_paths": payment_paths[:5],
            "delivery_lure": generic_courier_lure or delivery_problem,
            "payment_fee_lure": fee_lure,
            "urgency_or_threat": urgency_or_threat,
            "tracking_lure": tracking_lure,
            "official_domain_context": official_domain_context,
            "hard_signal": bool(risk_floor is not None and risk_floor >= 0.75 and score >= 0.80),
        }

    @staticmethod
    def _fraud_category_label(category: Optional[str]) -> str:
        labels = {
            "gift_card_fraud": "Gift-card fraud",
            "payroll_direct_deposit_change": "Payroll/direct-deposit change fraud",
            "credential_harvesting": "Credential harvesting",
            "invoice_payment_redirection": "Invoice/payment redirection",
            "wire_transfer_fraud": "Wire-transfer fraud",
            "supplier_bank_change": "Supplier bank-detail change",
            "mfa_security_alert_phishing": "MFA/security-alert phishing",
            "fake_it_support_remote_access": "Fake IT support remote-access scam",
            "tax_or_hr_document_lure": "Tax/HR document lure",
            "qr_phishing_or_image_lure": "QR-code/image phishing",
            "urgent_executive_request": "Urgent executive request",
            "malicious_attachment_lure": "Malicious attachment lure",
            "courier_customs_fee_phishing": "Courier/customs fee phishing",
            "delivery_redelivery_fee_phishing": "Delivery/redelivery fee phishing",
            "package_hold_phishing": "Package-hold phishing",
            "courier_brand_impersonation": "Courier brand impersonation",
            "payment_link_impersonation": "Payment-link impersonation",
            "tracking_link_phishing": "Tracking-link phishing",
        }
        return labels.get(str(category or ""), str(category or "Business email compromise").replace("_", " ").title())

    def detect_business_email_compromise_signals(
        self,
        *,
        message: Optional[str],
        sender: Optional[str],
        subject: Optional[str],
        url_indicators: Optional[Dict[str, Any]] = None,
        header_indicators: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect deterministic BEC/fraud patterns without globally inflating spam scores."""
        indicators = url_indicators if isinstance(url_indicators, dict) else {}
        headers = header_indicators if isinstance(header_indicators, dict) else {}
        text = self._bec_detection_text(subject, message, sender)
        url_count = int(indicators.get("total_urls", 0) or 0)
        trusted_context = self._trusted_aligned_url_context(
            url_indicators=indicators,
            sender_email=sender,
            header_indicators=headers,
        )
        suspicious_url = bool(
            url_count > 0
            and not trusted_context
            and (
                int(indicators.get("blocklisted_count", 0) or 0) > 0
                or int(indicators.get("reputation_high", 0) or 0) > 0
                or int(indicators.get("reputation_medium", 0) or 0) > 0
                or int(indicators.get("suspicious_tlds", 0) or 0) > 0
                or int(indicators.get("ip_urls", 0) or 0) > 0
                or int(indicators.get("punycode", 0) or 0) > 0
                or int(indicators.get("brand_impersonation_count", 0) or 0) > 0
                or int(indicators.get("shortened_urls", 0) or 0) > 0
                or int(indicators.get("encoded_url_count", 0) or 0) > 0
                or int(indicators.get("excessive_subdomains", 0) or 0) > 0
            )
        )

        def has(pattern: str) -> bool:
            return bool(re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL))

        candidates: List[Dict[str, Any]] = []

        def add_candidate(
            category: str,
            score: float,
            risk_floor: Optional[float],
            heuristic_floor: float,
            reasons: List[str],
            pattern_ids: List[str],
            *,
            handling: Optional[str] = None,
            severity: str = "high",
        ) -> None:
            candidates.append(
                {
                    "fraud_category": category,
                    "score": self._clamp01(score),
                    "risk_floor": self._clamp01(risk_floor) if isinstance(risk_floor, (int, float)) else None,
                    "heuristic_floor": self._clamp01(heuristic_floor),
                    "evidence_reasons": reasons,
                    "matched_patterns": pattern_ids,
                    "recommended_handling_hint": handling,
                    "severity_hint": severity,
                }
            )

        courier_bundle = self.detect_courier_delivery_phishing_signals(
            message=message,
            sender=sender,
            subject=subject,
            url_indicators=indicators,
            header_indicators=headers,
        )
        if courier_bundle.get("courier_category"):
            add_candidate(
                str(courier_bundle.get("courier_category")),
                self._safe_float(courier_bundle.get("courier_phishing_score"), 0.0),
                courier_bundle.get("risk_floor"),
                self._safe_float(courier_bundle.get("heuristic_floor"), 0.0),
                list(courier_bundle.get("evidence_reasons") or []),
                list(courier_bundle.get("matched_patterns") or []),
                handling=str(courier_bundle.get("recommended_handling_hint") or "review"),
                severity=str(courier_bundle.get("severity_hint") or "high"),
            )

        gift_card = has(r"\b(?:gift\s*cards?|vouchers?|prepaid\s+cards?|apple\s+cards?|google\s*play\s+cards?|steam\s+cards?|amazon\s+cards?)\b")
        gift_purchase = has(r"\b(?:buy|purchase|get|pick\s*up|procure)\b.{0,80}\b(?:gift\s*cards?|vouchers?|prepaid\s+cards?|apple\s+cards?|google\s*play|steam|amazon)\b")
        card_secret = has(r"\b(?:pins?|card\s+numbers?|codes?|serials?|scratch|back\s+of\s+(?:the\s+)?cards?)\b")
        exfil = has(r"\b(?:send|text|email|reply\s+with|share|forward)\b.{0,100}\b(?:photos?|pictures?|images?|codes?|pins?|card\s+numbers?|serials?)\b")
        urgency_unavailable = has(r"\b(?:urgent|immediately|asap|right\s+now|quick\s+task|before\s+(?:the\s+)?(?:meeting|board\s+call)|board\s+call|cannot\s+(?:talk|call)|can't\s+(?:talk|call)|in\s+a\s+meeting|sent\s+from\s+mobile|client\s+incentives?)\b")
        if gift_card and gift_purchase and card_secret and exfil and urgency_unavailable:
            add_candidate(
                "gift_card_fraud",
                0.94,
                0.82,
                0.86,
                [
                    "Gift-card purchase request with PIN/card-number exfiltration",
                    "Request to send photos/codes rather than normal procurement records",
                    "Urgency or unavailability pattern common in BEC fraud",
                ],
                ["gift_card_purchase", "pin_or_card_number_exfiltration", "send_photo_or_code", "urgency_unavailability"],
                handling="block",
            )

        payroll_context = has(r"\b(?:payroll|salary|wages?|hr)\b") and has(r"\b(?:direct\s+deposit|bank(?:ing)?\s+(?:account|details?)|account\s+details?|routing\s+number|bsb|account\s+number|new\s+account)\b")
        payroll_change = has(r"\b(?:change|update|replace|verify|confirm|submit|send)\b.{0,80}\b(?:direct\s+deposit|bank(?:ing)?\s+(?:account|details?)|account\s+details?|routing\s+number|bsb|account\s+number)\b") or has(r"\b(?:direct\s+deposit|bank(?:ing)?\s+(?:account|details?)|account\s+details?)\b.{0,80}\b(?:change|update|new|verify|confirm|submit|send)\b")
        payroll_pressure = has(r"\b(?:urgent|before\s+(?:the\s+)?next\s+pay\s+cycle|next\s+pay\s+cycle|do\s+not\s+call|cannot\s+(?:talk|call)|unavailable|manual\s+hold|delayed\s+salary)\b")
        if payroll_context and payroll_change and payroll_pressure:
            add_candidate(
                "payroll_direct_deposit_change",
                0.90,
                0.80,
                0.82,
                ["Payroll/direct-deposit change request with financial-account context", "Urgency or out-of-band handling pressure"],
                ["payroll_context", "direct_deposit_change", "urgency_or_unavailability"],
                handling="block",
            )

        credential_language = has(r"\b(?:verify|confirm|reset|re-?authenticate|login|log\s*in|sign\s*in|secure|unlock)\b.{0,90}\b(?:account|identity|mailbox|password|credentials?|document|invoice|portal)\b") or has(r"\b(?:password\s+(?:expired|expires?|reset|required)|mailbox\s+(?:full|quota)|account\s+(?:suspended|locked|disabled|unusual\s+activity)|secure\s+document|view\s+(?:invoice|document))\b")
        if credential_language and suspicious_url:
            add_candidate(
                "credential_harvesting",
                0.90,
                0.81,
                0.80,
                ["Credential-harvesting language with suspicious link/domain evidence"],
                ["credential_lure", "suspicious_url_or_domain"],
                handling="block",
            )
        elif credential_language and url_count == 0 and has(r"\b(?:urgent|immediately|lockout|suspended|disabled|expires?)\b"):
            add_candidate(
                "credential_harvesting",
                0.72,
                0.65,
                0.58,
                ["Strong credential-harvesting language without URL evidence"],
                ["credential_lure", "coercive_account_language"],
                handling="review",
                severity="medium",
            )

        payment_redirection = has(r"\b(?:invoice|payment|remittance|beneficiary|supplier|vendor|accounts\s+payable)\b") and has(r"\b(?:new|update|updated|changed|replace|change)\b.{0,80}\b(?:bank|account|beneficiary|remittance|wire|ach|payment\s+instructions?)\b")
        wire_fraud = has(r"\b(?:wire\s+transfer|transfer\s+funds?|send\s+funds?|remit\s+payment|process\s+payment)\b") and has(r"\b(?:urgent|immediately|confidential|do\s+not\s+call|cannot\s+(?:talk|call)|new\s+account|updated\s+instructions?)\b")
        if payment_redirection:
            category = "supplier_bank_change" if has(r"\b(?:supplier|vendor)\b") else "invoice_payment_redirection"
            add_candidate(
                category,
                0.89,
                0.80,
                0.82,
                ["Payment redirection or bank-detail change request with social-engineering indicators"],
                ["payment_or_invoice_context", "new_bank_details_or_instructions"],
                handling="block",
            )
        if wire_fraud:
            add_candidate(
                "wire_transfer_fraud",
                0.88,
                0.78,
                0.80,
                ["Wire-transfer request with urgency/confidentiality indicators"],
                ["wire_transfer_request", "urgency_or_confidentiality"],
                handling="block",
            )

        mfa_security = has(r"\b(?:mfa|2fa|authentication\s+code|security\s+alert|verify\s+sign-?in|account\s+locked|approve\s+(?:the\s+)?request|secure\s+account)\b")
        if mfa_security and (suspicious_url or has(r"\b(?:click|open|approve|confirm|verify)\b.{0,60}\b(?:link|request|identity|account)\b")):
            add_candidate(
                "mfa_security_alert_phishing",
                0.84 if suspicious_url else 0.72,
                0.78 if suspicious_url else 0.66,
                0.74 if suspicious_url else 0.60,
                ["Security/MFA alert wording uses coercive verification language"],
                ["mfa_or_security_alert", "verification_pressure"],
                handling="block" if suspicious_url else "review",
            )

        remote_access = has(r"\b(?:anydesk|teamviewer|remote\s+desktop|screen\s+share|support\s+session|install\s+remote\s+support|call\s+(?:this\s+)?number|malware\s+detected|refund\s+support)\b")
        if remote_access:
            combined_financial_or_credential = credential_language or has(r"\b(?:payment|refund|bank|card|wire|transfer)\b")
            add_candidate(
                "fake_it_support_remote_access",
                0.86 if combined_financial_or_credential else 0.76,
                0.80 if combined_financial_or_credential else 0.70,
                0.80 if combined_financial_or_credential else 0.70,
                ["Remote-access support lure associated with account takeover or payment fraud"],
                ["remote_access_tool_or_support_session"],
                handling="block" if combined_financial_or_credential else "review",
            )

        tax_hr_lure = has(r"\b(?:tax|irs|ato|hmrc|hr|human\s+resources|employee\s+file|w-?2|payslip|refund)\b") and has(r"\b(?:submit|upload|verify|confirm|send)\b.{0,80}\b(?:tax\s+id|ssn|tfn|bank|payroll|identity|credentials?|document)\b")
        if tax_hr_lure:
            add_candidate(
                "tax_or_hr_document_lure",
                0.82,
                0.74 if suspicious_url else 0.68,
                0.70,
                ["Tax/HR document lure requests sensitive identity, payroll, or banking data"],
                ["tax_or_hr_context", "sensitive_data_request"],
                handling="block" if suspicious_url else "review",
            )

        qr_lure = has(r"\b(?:qr\s*code|scan\s+(?:the\s+)?qr|scan\s+code)\b") and has(r"\b(?:payment|login|verify|account|invoice|bill|secure|document)\b")
        if qr_lure:
            add_candidate(
                "qr_phishing_or_image_lure",
                0.78 if suspicious_url else 0.70,
                0.75 if suspicious_url else 0.65,
                0.66,
                ["QR-code or image-based lure asks the user to continue payment/login verification out of band"],
                ["qr_or_image_lure", "payment_or_login_context"],
                handling="block" if suspicious_url else "review",
            )

        executive_request = has(r"\b(?:ceo|cfo|president|director|board|executive|boss)\b") and has(r"\b(?:urgent|quick\s+task|confidential|before\s+(?:the\s+)?meeting|cannot\s+(?:talk|call)|in\s+a\s+meeting)\b") and has(r"\b(?:payment|wire|transfer|gift\s*cards?|bank|client\s+incentives?)\b")
        if executive_request:
            add_candidate(
                "urgent_executive_request",
                0.80,
                0.72,
                0.70,
                ["Urgent executive-style request involving financial action"],
                ["executive_authority", "urgent_financial_request"],
                handling="review",
            )

        attachment_lure = has(r"\b(?:attachment|attached|xlsm|docm|macro|enable\s+content|protected\s+(?:view|payment\s+fields)|open\s+in\s+desktop\s+office)\b") and has(r"\b(?:invoice|payment|document|remittance|payroll|contract)\b")
        if attachment_lure:
            add_candidate(
                "malicious_attachment_lure",
                0.78,
                0.70,
                0.68,
                ["Attachment lure encourages risky document handling or macro-enabled content"],
                ["document_attachment_lure", "risky_open_or_enable_instruction"],
                handling="review",
            )

        if not candidates:
            return {
                "bec_score": 0.0,
                "fraud_pattern_score": 0.0,
                "fraud_category": None,
                "matched_patterns": [],
                "evidence_reasons": [],
                "severity_hint": "low",
                "risk_floor": None,
                "heuristic_floor": 0.0,
                "recommended_handling_hint": None,
                "hard_signal": False,
                "matches": [],
                "suspicious_url": suspicious_url,
                "trusted_aligned_url_context": trusted_context,
                "courier_phishing_score": courier_bundle.get("courier_phishing_score", 0.0),
                "courier_category": courier_bundle.get("courier_category"),
                "claimed_brand": courier_bundle.get("claimed_brand"),
                "brand_domain_mismatch": courier_bundle.get("brand_domain_mismatch", False),
                "sender_domain_mismatch": courier_bundle.get("sender_domain_mismatch", False),
                "suspicious_payment_link": courier_bundle.get("suspicious_payment_link", False),
                "courier_evidence_reasons": courier_bundle.get("evidence_reasons") or [],
                "courier_link_domains": courier_bundle.get("link_domains") or [],
                "courier_payment_paths": courier_bundle.get("payment_paths") or [],
                "courier_delivery_lure": courier_bundle.get("delivery_lure", False),
                "courier_payment_fee_lure": courier_bundle.get("payment_fee_lure", False),
                "courier_urgency_or_threat": courier_bundle.get("urgency_or_threat", False),
                "courier_tracking_lure": courier_bundle.get("tracking_lure", False),
                "courier_official_domain_context": courier_bundle.get("official_domain_context", False),
            }

        candidates.sort(key=lambda item: (float(item.get("risk_floor") or 0.0), float(item.get("score") or 0.0)), reverse=True)
        best = candidates[0]
        evidence_reasons: List[str] = []
        matched_patterns: List[str] = []
        for item in candidates:
            for reason in list(item.get("evidence_reasons") or []):
                if reason not in evidence_reasons:
                    evidence_reasons.append(str(reason))
            for pattern_id in list(item.get("matched_patterns") or []):
                if pattern_id not in matched_patterns:
                    matched_patterns.append(str(pattern_id))

        score = max(float(item.get("score") or 0.0) for item in candidates)
        if len(candidates) >= 2:
            score = min(0.99, score + 0.04)
        risk_floor_values = [float(item.get("risk_floor") or 0.0) for item in candidates if item.get("risk_floor") is not None]
        risk_floor = max(risk_floor_values) if risk_floor_values else None
        heuristic_floor = max(float(item.get("heuristic_floor") or 0.0) for item in candidates)

        return {
            "bec_score": self._clamp01(score),
            "fraud_pattern_score": self._clamp01(score),
            "fraud_category": best.get("fraud_category"),
            "fraud_category_label": self._fraud_category_label(best.get("fraud_category")),
            "matched_patterns": matched_patterns,
            "evidence_reasons": evidence_reasons,
            "severity_hint": str(best.get("severity_hint") or "high"),
            "risk_floor": self._clamp01(risk_floor) if risk_floor is not None else None,
            "heuristic_floor": self._clamp01(heuristic_floor),
            "recommended_handling_hint": best.get("recommended_handling_hint"),
            "hard_signal": bool(risk_floor is not None and risk_floor >= 0.75 and score >= 0.80),
            "matches": candidates,
            "suspicious_url": suspicious_url,
            "trusted_aligned_url_context": trusted_context,
            "courier_phishing_score": courier_bundle.get("courier_phishing_score", 0.0),
            "courier_category": courier_bundle.get("courier_category"),
            "claimed_brand": courier_bundle.get("claimed_brand"),
            "brand_domain_mismatch": courier_bundle.get("brand_domain_mismatch", False),
            "sender_domain_mismatch": courier_bundle.get("sender_domain_mismatch", False),
            "suspicious_payment_link": courier_bundle.get("suspicious_payment_link", False),
            "courier_evidence_reasons": courier_bundle.get("evidence_reasons") or [],
            "courier_link_domains": courier_bundle.get("link_domains") or [],
            "courier_payment_paths": courier_bundle.get("payment_paths") or [],
            "courier_delivery_lure": courier_bundle.get("delivery_lure", False),
            "courier_payment_fee_lure": courier_bundle.get("payment_fee_lure", False),
            "courier_urgency_or_threat": courier_bundle.get("urgency_or_threat", False),
            "courier_tracking_lure": courier_bundle.get("tracking_lure", False),
            "courier_official_domain_context": courier_bundle.get("official_domain_context", False),
        }

    def _modern_campaign_pattern_score(
        self,
        *,
        subject: Optional[str],
        body_text: Optional[str],
        sender_email: Optional[str],
        url_indicators: Dict[str, Any],
    ) -> Dict[str, Any]:
        text = self._deobfuscate_leetspeak_tokens(
            self._normalize_obfuscated_text(f"{subject or ''}\n{body_text or ''}")
        ).lower()
        url_count = int(url_indicators.get("total_urls", 0) or 0)
        matched: List[Dict[str, Any]] = []
        themes: set = set()
        score = 0.0

        pattern_specs: List[Dict[str, Any]] = [
            {
                "id": "credential_harvest",
                "theme": "credential",
                "weight": 0.28,
                "severity": "high",
                "label": "Credential verification lure",
                "impact": "Credential theft or account takeover risk.",
                "patterns": [
                    r"\bverify\b.*\b(account|identity|mailbox|password)\b",
                    r"\bre-?authenticate\b",
                    r"\bpassword\b.*\b(expires?|expiry|reset)\b",
                    r"\bsso\b.*\b(token|certificate|lockout)\b",
                    r"\bsign in\b.*\b(decrypt|unlock|continue)\b",
                ],
            },
            {
                "id": "collaboration_credential_sheet_lure",
                "theme": "credential",
                "weight": 0.30,
                "severity": "high",
                "label": "Collaboration mention + credentials document lure",
                "impact": "Impersonated collaboration notification attempting credential theft.",
                "patterns": [
                    r"\byou were mentioned\b",
                    r"\btagged you\b.{0,50}\bcomment\b",
                    r"\bview\s+comment\b",
                    r"\b(?:updated|latest|new)\s+credentials?\s+(?:sheet|file|doc(?:ument)?)\b",
                    r"\breview\b.{0,60}\bcredentials?\s+(?:sheet|file|doc(?:ument)?)\b",
                ],
            },
            {
                "id": "urgency_pressure",
                "theme": "urgency",
                "weight": 0.16,
                "severity": "medium",
                "label": "Urgency/pressure wording",
                "impact": "Rush tactics reduce user scrutiny and increase compromise risk.",
                "patterns": [
                    r"\burgent\b",
                    r"\bimmediately\b",
                    r"\bfinal notice\b",
                    r"\bwithin\s+\d+\s*(?:minutes?|hours?)\b",
                    r"\bexpires?\s+in\s+\d+\s*(?:minutes?|hours?)\b",
                ],
            },
            {
                "id": "promotion_prize_scam",
                "theme": "scam",
                "weight": 0.28,
                "severity": "high",
                "label": "Promotion/prize scam wording",
                "impact": "Classic consumer spam/fraud campaign language.",
                "patterns": [
                    r"\blimited\s+time\s+offer\b",
                    r"\blimited[-\s]+time\b.{0,30}\boffer\b",
                    r"\b(?:lucky\s+winner|you\s+have\s+won|you\s+are\s+our\s+lucky\s+winner)\b",
                    r"\bfree\s+(?:iphone|voucher|gift\s*card)\b",
                    r"\b(?:[6-9]\d|100)\s*%\s*discount\b",
                    r"\b(?:[6-9]\d|100)\s*%\s*off\b",
                    r"\b(?:buy\s+one[, ]+get\s+(?:one|two|three|\d+)\s+free)\b",
                    r"\b(?:special|exclusive)\s+(?:offer|deal|bonus|invite)\b",
                    r"\b(?:you(?:'|’)?ve\s+been\s+selected|you(?:'|’)?re\s+our\s+lucky)\b",
                    r"\b(?:you(?:'|’)?ve\s+been\s+chosen)\b",
                    r"\b(?:exclusive|vip)\s+(?:membership|event|invitation|upgrade|access)\b",
                    r"\b(?:free|win)\s+(?:trip|vacation|cruise|laptop|smartwatch|gaming\s+console)\b",
                    r"\b(?:free\s+(?:trial|membership|consultation|webinar|online\s+course|product\s+trial|spa\s+day|shopping\s+spree))\b",
                    r"\bwin\s+(?:a|an)?\s*(?:free\s+)?(?:year|trip|cruise|supply|home\s+makeover)\b",
                    r"\bearn\s+\$?\s*[\d,]+(?:\.\d{2})?\s*(?:per|a)\s*(?:day|week|month)\b",
                    r"\bwork\s+from\s+home\b",
                    r"\bno\s+experience\s+required\b",
                    r"\bdouble\s+your\s+bitcoin\b",
                    r"\bguaranteed\s+returns?\b",
                    r"\blowest\s+\w+\s+rates?\b.{0,40}\b(?:today\s+only|act\s+now)\b",
                ],
            },
            {
                "id": "finance_impersonation",
                "theme": "finance",
                "weight": 0.18,
                "severity": "medium",
                "label": "Payroll/finance impersonation theme",
                "impact": "Business email compromise and payment diversion risk.",
                "patterns": [
                    r"\bpayroll\b",
                    r"\bdirect deposit\b",
                    r"\baccounts payable\b",
                    r"\bremittance\b",
                    r"\bbeneficiary\b",
                    r"\bbank(?:ing)? details\b",
                    r"\bpre-?approved\b.{0,40}\b(?:loan|credit\s+line)\b",
                    r"\b(?:invoice|payment)\b.{0,60}\b(?:pending|overdue|failed|late fees?)\b",
                    r"\b(?:pay|payment)\s+now\b.{0,40}\b(?:avoid|prevent)\b",
                    r"\bpayment\s+(?:method\s+is\s+invalid|failed|is\s+pending)\b",
                    r"\bupdate\s+(?:billing|payment)\s+(?:info|details?)\b",
                    r"\binvoice\b.{0,50}\b(?:ready|pending)\b.{0,50}\b(?:download|pay)\b",
                ],
            },
            {
                "id": "loan_credit_offer_scam",
                "theme": "finance",
                "weight": 0.26,
                "severity": "high",
                "label": "Pre-approved loan/credit scam offer",
                "impact": "Advance-fee and lending scams often use instant approval language.",
                "patterns": [
                    r"\bpre-?approved\b.{0,50}\b(?:loan|credit\s+line)\b",
                    r"\b(?:loan|credit\s+line)\b.{0,50}\bno\s+(?:documents|credit\s+check|required)\b",
                    r"\b(?:borrow|get)\s+\$?\s*[\d,]+(?:\.\d{2})?\b.{0,50}\b(?:instantly|today|now)\b",
                ],
            },
            {
                "id": "account_lockout_verification_lure",
                "theme": "credential",
                "weight": 0.26,
                "severity": "high",
                "label": "Account lockout/verification lure",
                "impact": "Likely credential-harvesting or account takeover attempt.",
                "patterns": [
                    r"\b(?:account|mailbox)\s+(?:has\s+been\s+)?(?:suspended|locked|deactivated|blocked)\b",
                    r"\b(?:account|user)\s+is\s+(?:temporarily\s+)?blocked\b",
                    r"\bconfirm\s+your\s+(?:details|identity|password)\b",
                    r"\bupdate\s+payment\s+details\b",
                    r"\bsecurity\s+alert\b.{0,60}\b(?:verify|confirm)\b",
                    r"\bmailbox\s+has\s+exceeded\s+storage\b",
                    r"\byour\s+account\s+(?:has\s+unusual\s+activity|has\s+been\s+compromised|is\s+at\s+risk|is\s+under\s+review|has\s+been\s+flagged)\b",
                    r"\b(?:secure|protect)\s+(?:it|your\s+account)\s+now\b",
                    r"\baccount\s+will\s+be\s+deleted\b",
                    r"\baccount\s+is\s+inactive\b.{0,30}\breactivate\b",
                    r"\b(?:email|mailbox)\s+storage\s+(?:is\s+)?(?:full|almost\s+full)\b",
                    r"\bapple\s+id\b.{0,40}\b(?:locked|disabled)\b",
                    r"\b(?:subscription|account)\s+has\s+been\s+suspended\b",
                ],
            },
            {
                "id": "multilingual_account_verification_lure",
                "theme": "credential",
                "weight": 0.28,
                "severity": "high",
                "label": "Multilingual account verification lure",
                "impact": "Credential phishing translated into non-English account-security wording.",
                "patterns": [
                    r"\bactualizaci[o\u00f3]n\s+(?:urgente\s+)?de\s+seguridad\b",
                    r"\bconfirme\s+su\s+cuenta\b",
                    r"\bactividad\s+inusual\b.{0,80}\bconfirme\s+su\s+cuenta\b",
                    r"\bevitar\s+bloqueo\b",
                    r"\bbenutzerkonto\s+best(?:ae|\u00e4|a)tigen\b",
                    r"\bbitte\s+melden\s+sie\s+sich\s+sofort\s+an\b",
                    r"\bkonto[-\s]?sicherheit\b",
                ],
            },
            {
                "id": "renewal_or_warranty_pressure",
                "theme": "scam",
                "weight": 0.20,
                "severity": "medium",
                "label": "Renewal/warranty pressure wording",
                "impact": "Recurring subscription or warranty pressure is common in bulk spam campaigns.",
                "patterns": [
                    r"\bfinal\s+notice\b.{0,80}\b(?:renew|subscription|warranty)\b",
                    r"\b(?:subscription|membership|warranty)\b.{0,60}\b(?:expir(?:ing|e|ed)|about\s+to\s+expire)\b",
                    r"\brenew\s+today\b.{0,40}\b(?:lose\s+access|avoid\s+penalties?)\b",
                ],
            },
            {
                "id": "credential_collection_request",
                "theme": "credential",
                "weight": 0.28,
                "severity": "high",
                "label": "Direct credential collection request",
                "impact": "Direct request for passwords/IDs strongly indicates phishing intent.",
                "patterns": [
                    r"\breply\s+with\s+your\s+.*\bpassword\b",
                    r"\b(?:provide|send)\s+.*\b(?:password|credentials?)\b",
                    r"\bemployee\s+id\s+and\s+password\b",
                    r"\b(?:security|account)\s+audit\b.{0,50}\b(?:password|credentials?)\b",
                ],
            },
            {
                "id": "bank_transfer_fraud_alert",
                "theme": "finance",
                "weight": 0.30,
                "severity": "high",
                "label": "Unauthorized transfer fraud lure",
                "impact": "Banking/payment social-engineering pattern with transaction-reversal pressure.",
                "patterns": [
                    r"\b(?:suspicious|unauthori[sz]ed)\s+(?:transfer|transaction|payment)\b",
                    r"\btransfer\s+of\s+(?:aud|usd|eur|gbp|cad|sgd)?\s*[\d,]+(?:\.\d{2})?\b",
                    r"\bif\s+unauthori[sz]ed\b.{0,40}\b(?:cancel|reverse|stop)\b",
                    r"\b(?:cancel|reverse|stop)\s+now\b",
                    r"\b(?:transfer|transaction)\s+will\s+be\s+processed\b",
                ],
            },
            {
                "id": "direct_money_request_no_link",
                "theme": "finance",
                "weight": 0.24,
                "severity": "high",
                "label": "Direct money transfer request (no-link)",
                "impact": "Potential social-engineering cash transfer fraud without explicit URL.",
                "patterns": [
                    r"\b(?:send|transfer|wire|pay)\s+(?:\$|usd|aud|eur|gbp|cad|sgd)\s*[\d,]+(?:\.\d{2})?\b",
                    r"\b(?:send|transfer|wire)\s+.*\bright\s+now\b",
                    r"\bdon'?t\s+tell\s+anyone\b",
                ],
            },
            {
                "id": "executive_urgent_payment_no_link",
                "theme": "bec",
                "weight": 0.26,
                "severity": "high",
                "label": "Executive urgent payment pressure",
                "impact": "Common BEC tactic to force rushed unauthorized payments.",
                "patterns": [
                    r"\bthis\s+is\s+the\s+ceo\b",
                    r"\burgent\s+confidential\s+payment\b",
                    r"\bprocess\s+an\s+urgent\s+.*payment\b",
                    r"\b(?:cannot|can't)\s+talk\b.{0,50}\bpayment\b",
                ],
            },
            {
                "id": "delivery_redelivery_phish",
                "theme": "delivery",
                "weight": 0.22,
                "severity": "medium",
                "label": "Fake delivery/redelivery lure",
                "impact": "Common phishing method using package delivery urgency and link click prompts.",
                "patterns": [
                    r"\bmissed\s+(?:delivery|package)\b",
                    r"\b(?:update|confirm)\s+(?:street\s+address|address|zip\s*code|postal\s*code)\b",
                    r"\breturn(?:ed)?\s+to\s+sender\b",
                    r"\b(?:redelivery|re-?delivery)\b",
                    r"\bdelivery\s+fee\b",
                    r"\bpackage\s+is\s+waiting\b",
                    r"\bconfirm\s+delivery\b",
                    r"\btrack\s+(?:here|delivery|package)\b",
                ],
            },
            {
                "id": "bec_invoice_payment_reroute",
                "theme": "bec",
                "weight": 0.28,
                "severity": "high",
                "label": "Invoice/wire rerouting BEC pattern",
                "impact": "Business email compromise indicators for fraudulent payment destination changes.",
                "patterns": [
                    r"\b(?:invoice|payment)\b.{0,80}\b(?:overdue|past due|due today)\b",
                    r"\b(?:wire|ach|bank)\s+(?:instructions?|details?)\s+(?:updated|changed)\b",
                    r"\b(?:new|updated)\s+beneficiary\b",
                    r"\b(?:urgent|same day)\s+(?:wire|transfer|payment)\b",
                    r"\bremit(?:tance)?\s+to\b",
                ],
            },
            {
                "id": "government_impersonation_payment",
                "theme": "government_impersonation",
                "weight": 0.30,
                "severity": "high",
                "label": "Government impersonation payment scam",
                "impact": "Fraudulent claims of taxes/fines/account penalties demanding immediate payment.",
                "patterns": [
                    r"\b(?:irs|social security administration|ssa|ftc|ato)\b.{0,90}\b(?:pay|payment|fine|penalty|tax\s+debt|overdue|immediately|warrant|legal\s+action|gift\s*card|crypto(?:currency)?)\b",
                    r"\b(?:tax|fine|penalty)\b.{0,50}\b(?:pay|payment|immediately)\b",
                    r"\b(?:government|federal)\s+(?:notice|agency)\b",
                    r"\bonly\s+way\s+to\s+pay\s+is\s+(?:gift\s*card|crypto(?:currency)?)\b",
                    r"\b(?:warrant|legal action)\b.{0,60}\b(?:unless|if)\b.{0,30}\bpay\b",
                ],
            },
            {
                "id": "tech_support_remote_access_scam",
                "theme": "tech_support",
                "weight": 0.24,
                "severity": "high",
                "label": "Tech-support remote access scam",
                "impact": "Social engineering to gain remote control or payment for fake support incidents.",
                "patterns": [
                    r"\b(?:microsoft|windows|apple)\s+(?:support|security)\s+alert\b",
                    r"\byour\s+(?:computer|device)\s+is\s+(?:infected|compromised)\b",
                    r"\bcall\s+(?:support|helpline)\s+now\b",
                    r"\b(?:install|open)\s+(?:teamviewer|anydesk|remote\s+desktop)\b",
                    r"\bdo\s+not\s+shut\s+down\s+your\s+(?:computer|device)\b",
                ],
            },
            {
                "id": "crypto_exchange_impersonation",
                "theme": "crypto",
                "weight": 0.24,
                "severity": "high",
                "label": "Crypto exchange account compromise lure",
                "impact": "Impersonation of crypto platforms to steal credentials or wallet recovery secrets.",
                "patterns": [
                    r"\b(?:coinbase|binance|kraken|crypto(?:currency)?\s+exchange)\b",
                    r"\b(?:wallet|account)\s+(?:compromised|locked|suspended)\b",
                    r"\bmove\s+funds?\s+to\s+(?:safe|secure)\s+wallet\b",
                    r"\b(?:recovery|seed)\s+phrase\b",
                    r"\bunauthori[sz]ed\s+withdrawal\b",
                ],
            },
            {
                "id": "employment_task_scam",
                "theme": "employment",
                "weight": 0.20,
                "severity": "medium",
                "label": "Employment/task scam pattern",
                "impact": "Fraudulent recruiting offers that demand fees or move chats off-platform quickly.",
                "patterns": [
                    r"\bwork\s+from\s+home\b.{0,60}\b(?:daily|weekly)\s+pay\b",
                    r"\b(?:task|rating)\s+job\b.{0,60}\bcommission\b",
                    r"\binterview\s+on\s+(?:whatsapp|telegram)\b",
                    r"\bpay\s+(?:registration|training|onboarding)\s+fee\b",
                    r"\bno\s+experience\s+required\b.{0,60}\bhigh\s+income\b",
                ],
            },
            {
                "id": "gift_card_bec",
                "theme": "bec",
                "weight": 0.26,
                "severity": "high",
                "label": "Gift-card BEC pattern",
                "impact": "Immediate financial fraud risk.",
                "patterns": [
                    r"\bgift\s*cards?\b",
                    r"\bpins?\b",
                    r"\bsend\s+(?:me\s+)?(?:the\s+)?(?:pin|pins|code|codes|photos?)\b",
                    r"\bcan(?:not|'t)\s+take\s+calls\b",
                    r"\b(?:apple|google play|target|amazon)\s+gift\s*cards?\b",
                ],
            },
            {
                "id": "mfa_fatigue",
                "theme": "mfa",
                "weight": 0.24,
                "severity": "high",
                "label": "MFA fatigue social engineering",
                "impact": "Potential unauthorized account access if prompt is approved.",
                "patterns": [
                    r"\bmfa\b.*\b(prompt|approve|push)\b",
                    r"\bapprove\b.*\bnext\b.*\bmfa\b",
                    r"\brepeated\s+mfa\s+prompts?\b",
                ],
            },
            {
                "id": "macro_or_html_attachment_lure",
                "theme": "malware_lure",
                "weight": 0.24,
                "severity": "high",
                "label": "Attachment execution lure",
                "impact": "Potential malware delivery via macro/script-enabled content.",
                "patterns": [
                    r"\benable\s+content\b",
                    r"\benable\s+macros?\b",
                    r"\.xlsm\b",
                    r"\.html\b",
                    r"\bopen\s+attachment\b",
                ],
            },
            {
                "id": "investment_or_refund_scam",
                "theme": "scam",
                "weight": 0.16,
                "severity": "medium",
                "label": "Investment/refund scam language",
                "impact": "Financial theft via scam onboarding or fee extraction.",
                "patterns": [
                    r"\bguaranteed\b.*\broi\b",
                    r"\busdt\b",
                    r"\barbitrage\b",
                    r"\btax refund\b",
                    r"\boverpayment\b",
                    r"\bprocessing fee\b",
                    r"\bget\s+rich\s+quick\b",
                    r"\bearn\s+\$?\s*[\d,]+(?:\.\d{2})?\s*(?:per|a)\s*(?:day|week|month)\b",
                    r"\binvest\s+\$?\s*[\d,]+(?:\.\d{2})?\s+and\s+earn\s+\$?\s*[\d,]+(?:\.\d{2})?\b",
                    r"\bearn\s+\$?\s*[\d,]+(?:\.\d{2})?\s+in\s+\d+\s+days?\b",
                    r"\b(?:crypto|investment)\s+opportunity\b",
                    r"\b(?:credit\s+line|loan)\b.{0,40}\bno\s+(?:documents|credit\s+check)\b",
                ],
            },
            {
                "id": "dating_or_adult_lure",
                "theme": "scam",
                "weight": 0.24,
                "severity": "medium",
                "label": "Dating/adult engagement lure",
                "impact": "Common mass-spam lure to force click-through and credential harvesting.",
                "patterns": [
                    r"\bsingles?\s+(?:near\s+you|in\s+your\s+area)\b",
                    r"\bmeet\s+attractive\s+singles\b",
                    r"\bjoin\s+free\b.{0,40}\b(?:dating|singles?)\b",
                    r"\bhot\s+singles\b",
                ],
            },
            {
                "id": "health_miracle_lure",
                "theme": "scam",
                "weight": 0.22,
                "severity": "medium",
                "label": "Miracle health product lure",
                "impact": "Frequent spam pattern using unrealistic health claims and urgency.",
                "patterns": [
                    r"\bget\s+rid\s+of\b.{0,30}\bfat\b.{0,30}\b(?:\d+\s+days?|miracle)\b",
                    r"\bmiracle\s+(?:pill|supplement)\b",
                    r"\b(?:weight\s+loss|belly\s+fat)\b.{0,40}\b(?:order\s+now|today\s+only)\b",
                ],
            },
            {
                "id": "qr_payment_redirection",
                "theme": "payment_redirect",
                "weight": 0.14,
                "severity": "medium",
                "label": "QR/payment redirection pattern",
                "impact": "Payment redirection or malicious destination risk.",
                "patterns": [
                    r"\bqr code\b",
                    r"\bscan\b.*\bqr\b",
                    r"\bpay now\b",
                    r"\boverdue bill\b",
                ],
            },
        ]

        for spec in pattern_specs:
            for pattern in spec["patterns"]:
                m = re.search(pattern, text, flags=re.IGNORECASE)
                if not m:
                    continue
                score += float(spec["weight"])
                themes.add(str(spec["theme"]))
                snippet = text[max(0, m.start() - 32): min(len(text), m.end() + 48)].strip()
                matched.append(
                    {
                        "id": str(spec["id"]),
                        "label": str(spec["label"]),
                        "severity": str(spec["severity"]),
                        "impact": str(spec["impact"]),
                        "snippet": snippet or m.group(0),
                        "theme": str(spec["theme"]),
                        "weight": float(spec["weight"]),
                    }
                )
                break

        has_credential_lure = bool(
            re.search(
                r"\b(?:verify|re-?authenticate|confirm|reset)\b.{0,45}\b(?:account|identity|mailbox|password|credentials?)\b",
                text,
                flags=re.IGNORECASE | re.DOTALL,
            )
        )
        if has_credential_lure and url_count > 0:
            score += 0.25
            matched.append(
                {
                    "id": "credential_lure_with_link",
                    "label": "Credential lure combined with link",
                    "severity": "high",
                    "impact": "High likelihood of phishing credential harvesting.",
                    "snippet": "credential-verification language appears with embedded URL(s)",
                    "theme": "credential",
                    "weight": 0.25,
                }
            )

        has_collab_credential_lure = bool(
            re.search(
                r"\b(?:mentioned|tagged)\b.{0,120}\b(?:comment|project|document|file)\b",
                text,
                flags=re.IGNORECASE | re.DOTALL,
            )
            and re.search(
                r"\bcredentials?\s+(?:sheet|file|doc(?:ument)?)\b",
                text,
                flags=re.IGNORECASE,
            )
        )
        if has_collab_credential_lure and url_count > 0:
            score += 0.24
            themes.add("credential")
            matched.append(
                {
                    "id": "collaboration_credential_lure_with_link",
                    "label": "Collaboration mention with credentials file lure",
                    "severity": "high",
                    "impact": "Likely fake collaboration alert used to harvest credentials.",
                    "snippet": "mention/tag notification + credentials sheet request + embedded link",
                    "theme": "credential",
                    "weight": 0.24,
                }
            )

        has_money_request_with_link = bool(
            re.search(
                r"\b(?:send|transfer|wire|pay)\s+(?:me\s+)?(?:\$|usd|aud|eur|gbp|cad|sgd)\s*[\d,]+(?:\.\d{2})?\b",
                text,
                flags=re.IGNORECASE,
            )
            and url_count > 0
        )
        if has_money_request_with_link:
            score += 0.30
            themes.add("finance")
            matched.append(
                {
                    "id": "money_request_with_link",
                    "label": "Direct money request with external link",
                    "severity": "high",
                    "impact": "Classic financial scam pattern combining transfer request and click-through lure.",
                    "snippet": "transfer/payment demand appears with an embedded domain/link",
                    "theme": "finance",
                    "weight": 0.30,
                }
            )

        if len(themes) >= 3:
            score += 0.15
            matched.append(
                {
                    "id": "multi_theme_social_engineering",
                    "label": "Multi-theme social engineering",
                    "severity": "high",
                    "impact": "Cross-theme pressure signals indicate coordinated phishing attempt.",
                    "snippet": ", ".join(sorted(list(themes))[:5]),
                    "theme": "composite",
                    "weight": 0.15,
                }
            )

        high_risk_with_link = False
        high_risk_themes = {
            "credential",
            "finance",
            "bec",
            "mfa",
            "malware_lure",
            "payment_redirect",
            "delivery",
            "government_impersonation",
            "tech_support",
            "crypto",
            "employment",
        }
        if url_count > 0 and any(t in high_risk_themes for t in themes):
            high_risk_with_link = True
            score += 0.12
            matched.append(
                {
                    "id": "high_risk_theme_with_link",
                    "label": "High-risk campaign theme with embedded link",
                    "severity": "high",
                    "impact": "Click-through may lead to credential theft, malware, or payment fraud.",
                    "snippet": ", ".join(sorted(list(themes))[:6]),
                    "theme": "composite",
                    "weight": 0.12,
                }
            )

        high_severity_hits = sum(1 for item in matched if str(item.get("severity") or "").lower() == "high")
        medium_severity_hits = sum(1 for item in matched if str(item.get("severity") or "").lower() == "medium")
        text_only_high_risk = False
        if (
            url_count == 0
            and any(t in high_risk_themes for t in themes)
            and (
                (high_severity_hits >= 2 and score >= 0.36)
                or (high_severity_hits >= 1 and medium_severity_hits >= 1 and score >= 0.44)
                or score >= 0.62
            )
        ):
            text_only_high_risk = True
            score += 0.12
            matched.append(
                {
                    "id": "text_only_high_risk_campaign",
                    "label": "High-risk campaign theme without link",
                    "severity": "high",
                    "impact": "Message contains multiple high-risk scam indicators even without embedded URL.",
                    "snippet": ", ".join(sorted(list(themes))[:6]),
                    "theme": "composite",
                    "weight": 0.12,
                }
            )

        if sender_email and re.search(r"\b(?:ceo|finance|hr|payroll|it)\b", str(sender_email).lower()):
            score += 0.05
            matched.append(
                {
                    "id": "sensitive_sender_theme",
                    "label": "Sensitive sender role theme",
                    "severity": "low",
                    "impact": "Role impersonation themes can increase success of phishing campaigns.",
                    "snippet": str(sender_email)[:120],
                    "theme": "impersonation",
                    "weight": 0.05,
                }
            )

        return {
            "score": min(score, 0.99),
            "matches": matched[:12],
            "themes": sorted(list(themes)),
            "credential_lure_with_link": has_credential_lure and url_count > 0,
            "collaboration_credential_lure_with_link": has_collab_credential_lure and url_count > 0,
            "money_request_with_link": has_money_request_with_link,
            "high_risk_with_link": high_risk_with_link,
            "text_only_high_risk": text_only_high_risk,
        }

    def _fraud_pattern_pack_score(
        self,
        *,
        subject: Optional[str],
        body_text: Optional[str],
        sender_email: Optional[str],
        url_indicators: Dict[str, Any],
    ) -> Dict[str, Any]:
        pack = self._fraud_pattern_pack or {}
        patterns = list(pack.get("patterns") or [])
        if not patterns:
            return {
                "score": 0.0,
                "matches": [],
                "themes": [],
                "hard_signal": False,
                "version": pack.get("version"),
            }

        text = self._deobfuscate_leetspeak_tokens(
            self._normalize_obfuscated_text(f"{subject or ''}\n{body_text or ''}\n{sender_email or ''}")
        )
        has_url = int(url_indicators.get("total_urls", 0) or 0) > 0
        score = 0.0
        matched: List[Dict[str, Any]] = []
        themes: set[str] = set()
        high_hits = 0
        medium_hits = 0
        for item in patterns:
            try:
                requires_url = bool(item.get("requires_url"))
                if requires_url and not has_url:
                    continue
                regexes = list(item.get("regex") or [])
                match_obj = None
                for rgx in regexes:
                    m = rgx.search(text)
                    if m is not None:
                        match_obj = m
                        break
                if match_obj is None:
                    continue

                weight = self._clamp01(self._safe_float(item.get("weight"), 0.10))
                score += weight
                severity = str(item.get("severity") or "medium").strip().lower()
                if severity == "high":
                    high_hits += 1
                elif severity == "medium":
                    medium_hits += 1
                theme = str(item.get("theme") or "generic").strip().lower()
                if theme:
                    themes.add(theme)
                start = max(0, match_obj.start() - 40)
                end = min(len(text), match_obj.end() + 90)
                snippet = text[start:end].strip()
                matched.append(
                    {
                        "id": str(item.get("id") or "fraud_pattern"),
                        "label": str(item.get("label") or "Fraud pattern"),
                        "severity": severity,
                        "impact": str(item.get("impact") or "Known fraud campaign pattern."),
                        "snippet": snippet[:220] if snippet else None,
                        "theme": theme,
                        "requires_url": requires_url,
                        "weight": weight,
                    }
                )
            except Exception:
                continue

        if len(themes) >= 2:
            score += 0.08
            matched.append(
                {
                    "id": "fraud_multi_theme",
                    "label": "Multi-theme fraud pattern overlap",
                    "severity": "high",
                    "impact": "Combined social-engineering themes increase phishing likelihood.",
                    "snippet": ", ".join(sorted(list(themes))[:6]),
                    "theme": "composite",
                    "requires_url": has_url,
                    "weight": 0.08,
                }
            )
            high_hits += 1

        url_backed_hard_signal = bool(
            has_url and (
                high_hits >= 2
                or (high_hits >= 1 and medium_hits >= 1 and float(score) >= 0.35)
                or float(score) >= 0.55
            )
        )
        text_only_hard_signal = bool(
            (not has_url)
            and (
                high_hits >= 2
                or (high_hits >= 1 and medium_hits >= 2 and float(score) >= 0.40)
                or float(score) >= 0.62
            )
        )
        hard_signal = bool(url_backed_hard_signal or text_only_hard_signal)
        return {
            "score": self._clamp01(score),
            "matches": matched[:12],
            "themes": sorted(list(themes)),
            "hard_signal": hard_signal,
            "text_only_hard_signal": text_only_hard_signal,
            "version": pack.get("version"),
        }

    def _normalize_transformer_output(self, raw: Any) -> Optional[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if isinstance(raw, list):
            if raw and isinstance(raw[0], list):
                entries = [x for x in raw[0] if isinstance(x, dict)]
            elif raw and isinstance(raw[0], dict):
                entries = [x for x in raw if isinstance(x, dict)]
        elif isinstance(raw, dict):
            entries = [raw]
        if not entries:
            return None

        malicious_scores: List[float] = []
        benign_scores: List[float] = []
        top_label = ""
        top_score = 0.0
        for item in entries:
            label = str(item.get("label", "")).strip().lower()
            score = self._clamp01(self._safe_float(item.get("score"), 0.0))
            if score >= top_score:
                top_score = score
                top_label = label
            if (
                "spam" in label
                or "phish" in label
                or "malicious" in label
                or "fraud" in label
                or "scam" in label
                or "junk" in label
                or label in {"label_1", "1"}
            ):
                malicious_scores.append(score)
            elif (
                "ham" in label
                or "benign" in label
                or "safe" in label
                or "legit" in label
                or "clean" in label
                or label in {"label_0", "0"}
            ):
                benign_scores.append(score)

        if malicious_scores or benign_scores:
            if malicious_scores and benign_scores:
                p_m = max(malicious_scores)
                p_b = max(benign_scores)
                denom = p_m + p_b
                malicious_prob = (p_m / denom) if denom > 0 else 0.5
            elif malicious_scores:
                malicious_prob = max(malicious_scores)
            else:
                malicious_prob = 1.0 - max(benign_scores)
        else:
            malicious_prob = top_score if top_score >= 0.5 else (1.0 - top_score)

        malicious_prob = self._clamp01(malicious_prob)
        confidence = max(malicious_prob, 1.0 - malicious_prob)
        uncertainty = 1.0 - confidence
        return {
            "malicious_probability": malicious_prob,
            "confidence": confidence,
            "uncertainty": uncertainty,
            "label": top_label,
            "raw": entries,
        }

    def _transformer_segment_score(self, text: str) -> Optional[Dict[str, Any]]:
        if not self._transformer_pipeline:
            return None
        chunk = str(text or "").strip()
        if not chunk:
            return None
        try:
            try:
                raw = self._transformer_pipeline(chunk, truncation=True, return_all_scores=True)
            except Exception:
                raw = self._transformer_pipeline(chunk, truncation=True)
            normalized = self._normalize_transformer_output(raw)
            if normalized is None:
                return None
            return normalized
        except Exception as e:
            logger.error(f"Transformer inference failed: {e}")
            return None

    def _transformer_semantic_score(self, subject: Optional[str], body_text: Optional[str], urls: List[str]) -> Optional[Dict[str, Any]]:
        if not self._transformer_pipeline:
            return None
        segments = [
            ("subject", str(subject or "").strip(), 0.25),
            ("body", str(body_text or "")[:2400].strip(), 0.55),
            ("urls", " ".join(urls[:5]).strip(), 0.20),
        ]
        weighted_sum = 0.0
        weight_used = 0.0
        weighted_conf = 0.0
        pieces: List[Dict[str, Any]] = []
        for name, text, weight in segments:
            if not text:
                continue
            score = self._transformer_segment_score(text)
            if not score:
                continue
            malicious_prob = float(score["malicious_probability"])
            confidence = float(score["confidence"])
            pieces.append(
                {
                    "segment": name,
                    "score": malicious_prob,
                    "confidence": confidence,
                    "uncertainty": float(score["uncertainty"]),
                    "label": score.get("label"),
                    "weight": weight,
                }
            )
            weighted_sum += weight * malicious_prob
            weighted_conf += weight * confidence
            weight_used += weight
        if weight_used <= 0.0:
            return None
        final_score = self._clamp01(weighted_sum / weight_used)
        final_conf = self._clamp01(weighted_conf / weight_used)
        return {
            "score": final_score,
            "confidence": final_conf,
            "uncertainty": 1.0 - final_conf,
            "segments": pieces,
            "label": "malicious" if final_score >= 0.5 else "benign",
        }

    def _transformer_score(self, text: str) -> Optional[float]:
        bundle = self._transformer_semantic_score(subject=None, body_text=text, urls=[])
        if not bundle:
            return None
        return float(bundle.get("score", 0.0))

    def _fuse_component_scores(self, components: Dict[str, Optional[float]]) -> Dict[str, Any]:
        weights = self._resolved_feature_weights()
        weighted_sum = 0.0
        total_weight = 0.0
        used_weights: Dict[str, float] = {}
        normalized_components: Dict[str, float] = {}
        for name, raw in components.items():
            if raw is None:
                continue
            weight = float(weights.get(name, 0.0))
            if weight <= 0.0:
                continue
            score = self._clamp01(float(raw))
            weighted_sum += weight * score
            total_weight += weight
            used_weights[name] = weight
            normalized_components[name] = score
        raw_score = (weighted_sum / total_weight) if total_weight > 0 else 0.0
        calibration = self._resolved_calibration()
        calibrated = self._sigmoid(float(calibration["a"]) * raw_score + float(calibration["b"]))
        return {
            "raw": self._clamp01(raw_score),
            "calibrated": self._clamp01(calibrated),
            "weights": weights,
            "used_weights": used_weights,
            "components": normalized_components,
            "calibration": calibration,
        }

    def _compute_ood_score(
        self,
        text: str,
        url_indicators: Dict[str, Any],
        classical_score: Optional[float],
        transformer_bundle: Optional[Dict[str, Any]],
        online_score: Optional[float],
    ) -> Dict[str, Any]:
        raw = str(text or "")
        text_len = len(raw)
        alpha_chars = sum(1 for ch in raw if ch.isalpha())
        symbol_chars = sum(1 for ch in raw if (not ch.isalnum() and not ch.isspace()))
        alpha_ratio = alpha_chars / max(1, text_len)
        symbol_ratio = symbol_chars / max(1, text_len)
        tokens = re.findall(r"[a-zA-Z]{2,}", raw.lower())
        token_count = len(tokens)
        unique_ratio = (len(set(tokens)) / token_count) if token_count > 0 else 0.0

        transformer_score = None
        transformer_uncertainty = None
        if transformer_bundle:
            transformer_score = self._safe_float(transformer_bundle.get("score"), 0.0)
            transformer_uncertainty = self._safe_float(transformer_bundle.get("uncertainty"), 0.0)

        disagreement = 0.0
        if classical_score is not None and transformer_score is not None:
            disagreement = abs(float(classical_score) - float(transformer_score))

        signals = 0.0
        reasons: List[str] = []
        if token_count < 4:
            signals += 0.22
            reasons.append("very_low_token_count")
        if alpha_ratio < 0.35:
            signals += 0.18
            reasons.append("low_alphabetic_ratio")
        if symbol_ratio > 0.30:
            signals += 0.20
            reasons.append("high_symbol_density")
        if token_count >= 6 and unique_ratio > 0.95:
            signals += 0.10
            reasons.append("token_distribution_outlier")
        if transformer_uncertainty is not None and transformer_uncertainty >= 0.45:
            signals += 0.25
            reasons.append("high_transformer_uncertainty")
        if disagreement >= 0.50:
            signals += 0.22
            reasons.append("model_disagreement")
        if classical_score is None and transformer_score is None and online_score is None:
            signals += 0.25
            reasons.append("model_signal_missing")
        if int(url_indicators.get("total_urls", 0) or 0) == 0 and token_count < 5:
            signals += 0.10
            reasons.append("context_sparse")

        ood_score = min(signals, 0.99)
        return {
            "score": ood_score,
            "reasons": reasons,
            "metrics": {
                "token_count": token_count,
                "alpha_ratio": round(alpha_ratio, 4),
                "symbol_ratio": round(symbol_ratio, 4),
                "unique_token_ratio": round(unique_ratio, 4),
                "model_disagreement": round(disagreement, 4),
                "transformer_uncertainty": round(transformer_uncertainty, 4) if transformer_uncertainty is not None else None,
            },
        }

    def analyze_email(
        self,
        db: Session,
        email_data: EmailAnalysisRequest,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        effective_tenant_id = str(tenant_id or "").strip() or DEFAULT_TENANT_ID
        analysis_id = f"email-spam-{uuid.uuid4()}"
        analysis_timestamp_dt = datetime.now(timezone.utc)
        errors_encountered: List[str] = []
        spam_payload = SpamClassificationResult(is_spam=False, spam_score=0.0, classification_label="Unavailable")

        raw_email_fields = self._parse_raw_email_payload(
            subject=getattr(email_data, "subject", None),
            body_text=getattr(email_data, "body_text", None),
            body_html=getattr(email_data, "body_html", None),
            headers=getattr(email_data, "headers", None),
            sender_email=getattr(email_data, "sender_email", None),
        )
        parsed_fields = self._extract_inline_email_fields(
            subject=raw_email_fields.get("subject"),
            body_text=raw_email_fields.get("body_text"),
            sender_email=raw_email_fields.get("sender_email"),
        )
        subject_value = parsed_fields.get("subject")
        body_text_value = str(parsed_fields.get("body_text") or "")
        sender_email_value = parsed_fields.get("sender_email")
        body_html_value = raw_email_fields.get("body_html") or ""
        header_values = raw_email_fields.get("headers")

        combined_text = self._normalize_obfuscated_text(body_html_value + "\n" + body_text_value)
        url_inds = self._url_indicators(combined_text)
        sender_inds = self._sender_indicators(sender_email_value, url_inds.get("hosts"))
        header_inds = self._header_auth_indicators(
            headers=header_values,
            sender_email=sender_email_value,
            url_hosts=url_inds.get("hosts"),
        )
        url_sender_heuristic_score = self._heuristic_phishing_score(url_inds, sender_inds)
        campaign_bundle = self._modern_campaign_pattern_score(
            subject=subject_value,
            body_text=body_text_value,
            sender_email=sender_email_value,
            url_indicators=url_inds,
        )
        fraud_bundle = self._fraud_pattern_pack_score(
            subject=subject_value,
            body_text=body_text_value,
            sender_email=sender_email_value,
            url_indicators=url_inds,
        )
        bec_bundle = self.detect_business_email_compromise_signals(
            message=body_text_value,
            sender=sender_email_value,
            subject=subject_value,
            url_indicators=url_inds,
            header_indicators=header_inds,
        )
        campaign_score = self._clamp01(self._safe_float(campaign_bundle.get("score"), 0.0))
        bec_fraud_score = self._clamp01(self._safe_float(bec_bundle.get("bec_score"), 0.0))
        courier_phishing_score = self._clamp01(self._safe_float(bec_bundle.get("courier_phishing_score"), 0.0))
        brand_impersonation_score = 0.72 if bool(bec_bundle.get("brand_domain_mismatch")) else 0.0
        payment_link_impersonation_score = 0.78 if bool(bec_bundle.get("suspicious_payment_link")) else 0.0
        bec_heuristic_floor = self._clamp01(self._safe_float(bec_bundle.get("heuristic_floor"), 0.0))
        heur_phish_score = max(url_sender_heuristic_score, bec_heuristic_floor)
        fraud_pattern_score = max(
            self._clamp01(self._safe_float(fraud_bundle.get("score"), 0.0)),
            bec_fraud_score,
        )
        header_score = self._clamp01(self._safe_float(header_inds.get("score"), 0.0))

        full_text = self._normalize_obfuscated_text(f"{subject_value or ''} {body_text_value or ''}").strip()
        classical_score: Optional[float] = None
        if self._spam_detection_pipeline:
            try:
                processed_text = self._preprocess_email_text_for_spam(full_text)
                if processed_text:
                    probs = self._spam_detection_pipeline.predict_proba([processed_text])[0]
                    classical_score = self._clamp01(float(probs[1]))
            except Exception as e:
                errors_encountered.append(f"Spam detection failed: {e}")

        transformer_bundle: Optional[Dict[str, Any]] = None
        transf_score: Optional[float] = None
        try:
            transformer_bundle = self._transformer_semantic_score(
                subject=subject_value,
                body_text=body_text_value,
                urls=self._extract_urls(combined_text),
            )
            if transformer_bundle is not None:
                transf_score = self._clamp01(self._safe_float(transformer_bundle.get("score"), 0.0))
        except Exception as e:
            errors_encountered.append(f"Transformer scoring failed: {e}")

        online_score: Optional[float] = None
        try:
            model = self._load_online_model()
            if model is not None:
                try:
                    proba = model.predict_proba([full_text])[0]
                    online_score = self._clamp01(float(proba[1]))
                except Exception:
                    pass
        except Exception as e:
            errors_encountered.append(f"Online learner scoring failed: {e}")

        reputation_score = self._clamp01(
            max(
                float(url_inds.get("reputation_score_avg", 0.0) or 0.0),
                float(url_inds.get("reputation_score_max", 0.0) or 0.0),
                1.0 if int(url_inds.get("blocklisted_count", 0) or 0) > 0 else 0.0,
            )
        )
        fused = self._fuse_component_scores(
            {
                "classical": classical_score,
                "transformer": transf_score,
                "online": online_score,
                "heuristic": heur_phish_score,
                "reputation": reputation_score,
                "campaign": campaign_score,
                "header": header_score,
                "fraud_pattern": fraud_pattern_score,
            }
        )
        thresholds = self._resolved_thresholds()
        ood = self._compute_ood_score(
            text=full_text,
            url_indicators=url_inds,
            classical_score=classical_score,
            transformer_bundle=transformer_bundle,
            online_score=online_score,
        )
        ood_score = self._clamp01(float(ood["score"]))
        trusted_url_context = self._trusted_aligned_url_context(
            url_indicators=url_inds,
            sender_email=sender_email_value,
            header_indicators=header_inds,
        )

        hard_block_signal = (
            int(url_inds.get("blocklisted_count", 0) or 0) > 0
            and max(
                reputation_score,
                transf_score or 0.0,
                heur_phish_score or 0.0,
            ) >= 0.65
        )
        campaign_link_hard_signal = bool(
            campaign_bundle.get("credential_lure_with_link")
            or campaign_bundle.get("money_request_with_link")
            or (campaign_bundle.get("high_risk_with_link") and not trusted_url_context)
        ) and campaign_score >= 0.35
        campaign_text_hard_signal = bool(campaign_bundle.get("text_only_high_risk")) and campaign_score >= 0.30
        campaign_hard_signal = bool(campaign_link_hard_signal or campaign_text_hard_signal)
        fraud_pattern_hard_signal = bool(fraud_bundle.get("hard_signal") or bec_bundle.get("hard_signal"))
        header_hard_signal = bool(
            header_score >= 0.66
            and (
                str(header_inds.get("dmarc")) == "fail"
                or str(header_inds.get("dkim")) == "fail"
                or bool(header_inds.get("reply_to_mismatch"))
            )
        )
        campaign_themes = set(campaign_bundle.get("themes") or [])
        final_score = self._clamp01(float(fused["calibrated"]))
        bec_risk_floor = bec_bundle.get("risk_floor")
        if isinstance(bec_risk_floor, (int, float)) and final_score < float(bec_risk_floor):
            final_score = max(final_score, min(0.99, float(bec_risk_floor)))
        if hard_block_signal:
            final_score = max(final_score, min(0.99, thresholds["block"] + 0.03))
        if campaign_score >= 0.25 and not trusted_url_context and final_score < thresholds["suspicious"]:
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.01))
        if (
            int(url_inds.get("total_urls", 0) or 0) > 0
            and campaign_score >= 0.20
            and not trusted_url_context
            and final_score < thresholds["suspicious"]
        ):
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.01))
        if (
            campaign_score >= 0.45
            and campaign_themes.intersection({"bec", "mfa", "finance", "credential"})
            and not trusted_url_context
            and final_score < thresholds["block"]
        ):
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.03))
        if (
            campaign_score >= 0.22
            and campaign_themes.intersection({"credential", "bec", "finance", "delivery", "malware_lure", "scam"})
            and not trusted_url_context
            and final_score < thresholds["suspicious"]
        ):
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.01))
        if campaign_hard_signal and final_score < thresholds["block"]:
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.05))
        if campaign_text_hard_signal and final_score < thresholds["suspicious"]:
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.04))
        if campaign_bundle.get("money_request_with_link") and final_score < thresholds["suspicious"]:
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.06))
        if (
            int(url_inds.get("brand_impersonation_count", 0) or 0) > 0
            and (
                campaign_score >= 0.16
                or fraud_pattern_score >= 0.15
                or heur_phish_score >= 0.18
                or header_score >= 0.35
            )
            and final_score < thresholds["suspicious"]
        ):
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.04))
        if (
            campaign_score >= 0.85
            and int(url_inds.get("total_urls", 0) or 0) > 0
            and (
                int(url_inds.get("reputation_high", 0) or 0) > 0
                or int(url_inds.get("blocklisted_count", 0) or 0) > 0
            )
            and final_score < thresholds["block"]
        ):
            final_score = max(final_score, min(0.99, thresholds["block"] + 0.01))
        if (
            fraud_pattern_score >= 0.35
            and int(url_inds.get("total_urls", 0) or 0) > 0
            and final_score < thresholds["suspicious"]
        ):
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.03))
        if fraud_pattern_hard_signal and final_score < thresholds["block"]:
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.07))
        if (
            header_hard_signal
            and int(url_inds.get("total_urls", 0) or 0) > 0
            and final_score < thresholds["suspicious"]
        ):
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.04))
        if (
            header_score >= 0.70
            and fraud_pattern_score >= 0.35
            and int(url_inds.get("total_urls", 0) or 0) > 0
            and final_score < thresholds["block"]
        ):
            final_score = max(final_score, min(0.99, thresholds["block"] + 0.01))
        strong_classical_signal = classical_score is not None and float(classical_score) >= 0.95
        strong_model_contradiction = (
            classical_score is not None
            and transf_score is not None
            and float(classical_score) >= 0.90
            and float(transf_score) <= 0.20
        )
        supporting_non_ml_signal = bool(
            campaign_score >= 0.16
            or fraud_pattern_score >= 0.15
            or heur_phish_score >= 0.12
            or campaign_text_hard_signal
            or int(url_inds.get("reputation_medium", 0) or 0) > 0
            or int(url_inds.get("suspicious_tlds", 0) or 0) > 0
            or int(url_inds.get("blocklisted_count", 0) or 0) > 0
            or int(url_inds.get("brand_impersonation_count", 0) or 0) > 0
        )
        if strong_classical_signal and supporting_non_ml_signal and final_score < thresholds["suspicious"]:
            floor_delta = 0.02 if strong_model_contradiction else 0.01
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + floor_delta))
        if ood_score >= thresholds["ood"] and final_score < thresholds["block"]:
            final_score = max(final_score, min(0.99, thresholds["suspicious"] + 0.02))

        if final_score >= thresholds["block"]:
            final_label = "Phishing"
            decision = "BLOCK_EMAIL"
            severity = "High"
            category = "blocked"
        elif final_score >= thresholds["suspicious"] or ood_score >= thresholds["ood"]:
            if ood_score >= thresholds["ood"] and final_score < thresholds["block"]:
                final_label = "Suspicious (OOD Review)"
                decision = "FLAG_FOR_REVIEW"
            elif final_score < 0.65:
                final_label = "Suspicious (Review)"
                decision = "FLAG_FOR_REVIEW"
            else:
                final_label = "Spam"
                decision = "FLAG_AS_SPAM"
            severity = "Medium"
            category = "suspicious"
        else:
            final_label = "Ham"
            decision = "ALLOW"
            severity = "Low"
            category = "safe"

        decision_confidence = self._compute_decision_confidence(
            spam_score=final_score,
            category=category,
        )

        spam_payload = SpamClassificationResult(
            is_spam=(category != "safe"),
            spam_score=float(final_score),
            decision_confidence=float(decision_confidence),
            classification_label=final_label,
        )
        explanation_evidence: List[XAIExplanationEvidence] = []
        if url_inds.get("blocklisted"):
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="blocklisted_domain",
                    label="Blocklisted domain found",
                    severity="high",
                    description="A URL hostname matches the reputation blocklist.",
                    snippet=", ".join(list(url_inds.get("blocklisted", []))[:5]),
                    source="url_indicators",
                    impact="Potential malicious or known-bad destination link.",
                )
            )
        if int(url_inds.get("reputation_high", 0) or 0) > 0:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="domain_reputation_high",
                    label="High-risk domain reputation",
                    severity="high",
                    description="One or more domains have high reputation risk scores.",
                    snippet=", ".join(list(url_inds.get("hosts", []))[:5]) if url_inds.get("hosts") else None,
                    source="reputation",
                    impact="High likelihood of phishing landing page or malware delivery.",
                )
            )
        if int(url_inds.get("suspicious_tlds", 0) or 0) > 0:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="suspicious_tld",
                    label="Suspicious TLD detected",
                    severity="medium",
                    description="Suspicious top-level domains are commonly used in phishing and spam campaigns.",
                    snippet=", ".join(list(url_inds.get("hosts", []))[:5]) if url_inds.get("hosts") else None,
                    source="url_indicators",
                    impact="Increased likelihood of phishing or scam links.",
                )
            )
        if int(url_inds.get("ip_urls", 0) or 0) > 0:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="ip_url",
                    label="IP-based URL detected",
                    severity="medium",
                    description="Links using raw IP addresses often attempt to bypass domain reputation controls.",
                    source="url_indicators",
                    impact="Potential malware delivery or phishing landing page.",
                )
            )
        if int(url_inds.get("shortened_urls", 0) or 0) > 0:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="shortener_usage",
                    label="Shortened URL usage",
                    severity="medium",
                    description="URL shorteners can hide final destinations and are often used in phishing.",
                    source="url_indicators",
                    impact="Destination obfuscation increases user-risk.",
                )
            )
        if sender_inds.get("punycode"):
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="sender_punycode",
                    label="Punycode sender domain",
                    severity="medium",
                    description="Punycode can be used for look-alike domains (IDN homograph attacks).",
                    snippet=str(sender_inds.get("domain") or ""),
                    source="meta_features",
                    impact="Potential impersonation of trusted domains.",
                )
            )
        if sender_inds.get("domain_mismatch_with_urls"):
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="sender_domain_mismatch",
                    label="Sender/link domain mismatch",
                    severity="medium",
                    description="Sender domain does not align with linked destination domains.",
                    snippet=str(sender_inds.get("domain") or ""),
                    source="meta_features",
                    impact="Common impersonation or redirection pattern.",
                )
            )
        if header_inds.get("available"):
            header_fail_tokens: List[str] = []
            if str(header_inds.get("spf")) in {"fail", "softfail"}:
                header_fail_tokens.append(f"SPF={header_inds.get('spf')}")
            if str(header_inds.get("dkim")) in {"fail", "none"}:
                header_fail_tokens.append(f"DKIM={header_inds.get('dkim')}")
            if str(header_inds.get("dmarc")) in {"fail", "none"}:
                header_fail_tokens.append(f"DMARC={header_inds.get('dmarc')}")
            if bool(header_inds.get("reply_to_mismatch")):
                header_fail_tokens.append("Reply-To mismatch")
            if bool(header_inds.get("return_path_mismatch")):
                header_fail_tokens.append("Return-Path mismatch")
            if header_fail_tokens:
                explanation_evidence.append(
                    XAIExplanationEvidence(
                        id="header_auth_anomaly",
                        label="Header authentication anomaly",
                        severity="high" if header_score >= 0.66 else "medium",
                        description="SPF/DKIM/DMARC or sender-header consistency checks indicate elevated spoofing risk.",
                        snippet=", ".join(header_fail_tokens[:5]),
                        source="header_auth",
                        score=header_score,
                        impact="Higher probability of sender spoofing and phishing impersonation.",
                    )
                )
        if int(url_inds.get("brand_impersonation_count", 0) or 0) > 0:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="brand_lookalike_domain",
                    label="Brand lookalike domain",
                    severity="high",
                    description="A URL domain resembles a trusted brand but is not an allowlisted official domain.",
                    snippet=", ".join(list(url_inds.get("brand_impersonation_hosts") or [])[:5]),
                    source="url_indicators",
                    score=heur_phish_score,
                    impact="Potential credential-harvesting or brand impersonation phishing.",
                )
            )
        if sender_inds.get("ip_sender"):
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="sender_ip_domain",
                    label="Sender domain is an IP",
                    severity="low",
                    description="Sender domains that look like IP addresses are unusual and may indicate low-quality senders.",
                    snippet=str(sender_inds.get("sender") or ""),
                    source="meta_features",
                    impact="Increased spam likelihood.",
                )
            )
        if bec_bundle.get("fraud_category"):
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id=f"bec_{bec_bundle.get('fraud_category')}",
                    label=str(bec_bundle.get("fraud_category_label") or "Business email compromise indicators"),
                    severity=str(bec_bundle.get("severity_hint") or "high"),
                    description="Deterministic BEC/fraud heuristic matched multiple required evidence conditions.",
                    snippet="; ".join(list(bec_bundle.get("evidence_reasons") or [])[:4]) or None,
                    source="bec_fraud_heuristics",
                    score=bec_fraud_score,
                    impact="Known business email compromise pattern; handling should follow fraud-response policy.",
                )
            )
        for item in list(fraud_bundle.get("matches") or [])[:6]:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id=f"fraud_{item.get('id')}",
                    label=str(item.get("label") or "Fraud pattern"),
                    severity=str(item.get("severity") or "medium"),
                    description="Matched fraud pattern from curated threat-intel pack.",
                    snippet=str(item.get("snippet") or "")[:220] or None,
                    source="fraud_pattern_pack",
                    score=float(item.get("weight") or fraud_pattern_score or 0.0),
                    impact=str(item.get("impact") or "Elevated phishing/spam campaign likelihood."),
                )
            )
        for item in list(campaign_bundle.get("matches") or [])[:6]:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id=f"campaign_{item.get('id')}",
                    label=str(item.get("label") or "Campaign pattern"),
                    severity=str(item.get("severity") or "medium"),
                    description="Modern social-engineering campaign pattern detected in message content.",
                    snippet=str(item.get("snippet") or "")[:200] or None,
                    source="campaign_patterns",
                    score=campaign_score,
                    impact=str(item.get("impact") or "Elevated phishing/spam campaign likelihood."),
                )
            )
        if transf_score is not None and transf_score >= thresholds["suspicious"]:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="transformer_semantic_phishing",
                    label="Transformer semantic phishing signal",
                    severity="medium",
                    description="Semantic model indicates phishing/spam language patterns.",
                    source="transformer",
                    score=float(transf_score),
                    impact="Elevated confidence in malicious intent.",
                )
            )
        if ood_score >= thresholds["ood"]:
            explanation_evidence.append(
                XAIExplanationEvidence(
                    id="ood_review_required",
                    label="Out-of-distribution content",
                    severity="medium",
                    description="Input appears unlike normal training distribution; model certainty is reduced.",
                    snippet=", ".join((ood.get("reasons") or [])[:3]),
                    source="ood_guard",
                    score=ood_score,
                    impact="Route to manual review to reduce false positives/negatives.",
                )
            )

        model_attributions: List[Dict[str, Any]] = [
            {"component": "classical", "score": classical_score, "weight": fused["used_weights"].get("classical")},
            {"component": "transformer", "score": transf_score, "weight": fused["used_weights"].get("transformer")},
            {"component": "online", "score": online_score, "weight": fused["used_weights"].get("online")},
            {"component": "heuristic", "score": heur_phish_score, "weight": fused["used_weights"].get("heuristic")},
            {"component": "reputation", "score": reputation_score, "weight": fused["used_weights"].get("reputation")},
            {"component": "campaign", "score": campaign_score, "weight": fused["used_weights"].get("campaign")},
            {"component": "header", "score": header_score, "weight": fused["used_weights"].get("header")},
            {"component": "fraud_pattern", "score": fraud_pattern_score, "weight": fused["used_weights"].get("fraud_pattern")},
            {"component": "bec_fraud", "score": bec_fraud_score},
            {"component": "courier_phishing", "score": courier_phishing_score},
            {"component": "brand_impersonation", "score": brand_impersonation_score if brand_impersonation_score > 0.0 else None},
            {"component": "payment_link_impersonation", "score": payment_link_impersonation_score if payment_link_impersonation_score > 0.0 else None},
            {"component": "ood", "score": ood_score},
            {"component": "raw_fused", "score": fused["raw"]},
            {"component": "calibrated_final", "score": final_score},
            {"component": "decision_confidence", "score": decision_confidence},
        ]
        trace: List[XAIExplanationTraceStep] = [
            XAIExplanationTraceStep(
                stage="feature_extraction",
                summary="Extracted semantic, URL/domain, and reputation indicators.",
                details={
                    "url_indicators": url_inds,
                    "sender": sender_inds,
                    "header_auth": header_inds,
                    "fraud_pattern_pack": {
                        "version": fraud_bundle.get("version"),
                        "score": fraud_pattern_score,
                        "themes": fraud_bundle.get("themes"),
                        "matches": fraud_bundle.get("matches"),
                    },
                    "bec_fraud": bec_bundle,
                    "campaign_patterns": campaign_bundle,
                    "transformer_semantics": transformer_bundle,
                    "ood_metrics": ood.get("metrics"),
                },
            ),
            XAIExplanationTraceStep(
                stage="fusion_calibration",
                summary=f"raw={fused['raw']:.3f} calibrated={final_score:.3f}",
                details={
                    "components": fused["components"],
                    "weights": fused["weights"],
                    "used_weights": fused["used_weights"],
                    "calibration": fused["calibration"],
                    "thresholds": thresholds,
                    "ood_score": ood_score,
                    "trusted_aligned_url_context": trusted_url_context,
                    "bec_risk_floor": bec_bundle.get("risk_floor"),
                    "hard_block_signal": hard_block_signal,
                    "campaign_hard_signal": campaign_hard_signal,
                    "fraud_pattern_hard_signal": fraud_pattern_hard_signal,
                    "header_hard_signal": header_hard_signal,
                },
            ),
            XAIExplanationTraceStep(
                stage="decision",
                summary=f"{final_label} -> {decision}",
                details={
                    "category": category,
                    "severity": severity,
                    "spam_score": final_score,
                    "decision_confidence": decision_confidence,
                },
            ),
        ]
        if category == "blocked" and bec_bundle.get("fraud_category"):
            impact = f"High-confidence {bec_bundle.get('fraud_category_label')} evidence with deterministic BEC indicators."
        elif category == "blocked":
            impact = "High-confidence phishing risk with malicious destination indicators."
        elif category == "suspicious":
            impact = "Suspicious message with elevated phishing/spam risk; review recommended."
        else:
            impact = "No strong phishing indicators remained after calibrated scoring."
        provisional_handling = self._default_handling_for_category(category)
        provisional_review_required = bool(category == "suspicious" or ood_score >= thresholds["ood"])
        remediation = self._spam_suggested_actions(
            recommended_handling=provisional_handling,
            review_required=provisional_review_required,
            fraud_category=bec_bundle.get("fraud_category"),
        )
        counterfactual = (
            "If suspicious links/domain reputation signals were absent and calibrated score fell below "
            f"{thresholds['suspicious']:.2f}, this message would be classified as Ham."
        )

        confidence = float(decision_confidence)
        if confidence >= 0.85:
            confidence_label = "high"
        elif confidence >= 0.60:
            confidence_label = "medium"
        else:
            confidence_label = "low"

        component_values: List[float] = []
        component_support = 0
        decision_is_restrictive = category != "safe"
        support_margin = 0.05
        for comp_score in [
            classical_score,
            transf_score,
            online_score,
            heur_phish_score,
            reputation_score,
            campaign_score,
            header_score if header_inds.get("available") else None,
            fraud_pattern_score,
        ]:
            if comp_score is None:
                continue
            score_val = float(comp_score)
            if abs(score_val - thresholds["suspicious"]) <= support_margin:
                continue
            component_values.append(score_val)
            comp_restrictive = score_val >= thresholds["suspicious"]
            if comp_restrictive == decision_is_restrictive:
                component_support += 1
        fidelity_score = (
            round(component_support / len(component_values), 4)
            if component_values
            else None
        )
        if bec_bundle.get("hard_signal") and fidelity_score is not None:
            # Multi-condition BEC evidence is deterministic support. It should
            # reduce ambiguity when optional ML/header components are weak or
            # missing, without changing the risk or decision-confidence scores.
            fidelity_score = round(max(float(fidelity_score), 0.72), 4)
        uncertainty_score, uncertainty_components, missing_important_components = self._compute_spam_uncertainty(
            spam_score=final_score,
            suspicious_threshold=thresholds["suspicious"],
            ood_score=ood_score,
            component_scores={
                "classical": classical_score,
                "transformer": transf_score,
                "online": online_score,
                "heuristic": heur_phish_score,
                "reputation": reputation_score,
                "campaign": campaign_score,
                "header": header_score if header_inds.get("available") else None,
                "fraud_pattern": fraud_pattern_score,
            },
            component_weights=fused["used_weights"],
            transformer_available=transf_score is not None,
            reputation_available=bool(self._blocklist_domains or self._domain_reputation),
            headers_available=bool(header_inds.get("available")),
            fidelity_score=fidelity_score,
        )

        abstain_reason = None
        if ood_score >= thresholds["ood"] and category != "blocked":
            abstain_reason = "OOD_REVIEW_REQUIRED"

        model_tokens: List[str] = []
        if self._spam_detection_pipeline is not None:
            model_tokens.append(self._spam_detection_pipeline.__class__.__name__)
        if self._transformer_model_name:
            model_tokens.append(f"transformer:{self._transformer_model_name}")
        if online_score is not None:
            model_tokens.append("online:sgd_hashing")
        if (self._fraud_pattern_pack or {}).get("version"):
            model_tokens.append(f"fraud_pack:{(self._fraud_pattern_pack or {}).get('version')}")
        model_version = " + ".join(model_tokens) if model_tokens else None
        ruleset_version = "spam_reputation_rules_v3"
        policy_version = "spam_policy_calibrated_v3"
        caveats: List[str] = []
        if self._transformer_pipeline is None:
            caveats.append("Transformer semantic model unavailable; fusion relies on classical/reputation signals.")
        if not (self._blocklist_domains or set()) and not (self._domain_reputation or {}):
            caveats.append("No external domain reputation data loaded.")
        if not header_inds.get("available"):
            caveats.append("No email headers provided; SPF/DKIM/DMARC checks could not be evaluated.")
        if abstain_reason:
            caveats.append("Out-of-distribution content contributes to review policy and uncertainty scoring.")
        if missing_important_components:
            caveats.append(
                "Uncertainty includes missing-component review risk for: "
                + ", ".join(missing_important_components)
                + "."
            )
        if bec_bundle.get("risk_floor"):
            caveats.append(
                "A deterministic BEC/fraud risk floor was applied because multiple category-specific evidence conditions were satisfied."
            )

        explanation = XAIExplanation(
            decision=decision,
            severity=severity,
            threat_category="Spam/Phishing",
            risk_score=float(final_score),
            decision_confidence=confidence,
            confidence=confidence,
            spam_risk=float(final_score),
            confidence_label=confidence_label,
            uncertainty_score=uncertainty_score,
            uncertainty_components=uncertainty_components,
            fidelity_score=fidelity_score,
            ood_score=ood_score,
            abstain_reason=abstain_reason,
            impact=impact,
            evidence=explanation_evidence or None,
            model_attributions=[x for x in model_attributions if x.get("score") is not None],
            decision_trace=trace,
            remediation=remediation,
            counterfactual=counterfactual,
            model_version=model_version,
            ruleset_version=ruleset_version,
            policy_version=policy_version,
            thresholds={k: float(v) for k, v in thresholds.items()},
            provenance={
                "pipeline": "spam_detection_v2",
                "components_used": [x.get("component") for x in model_attributions if x.get("score") is not None],
                "hard_block_signal": hard_block_signal,
                "campaign_hard_signal": campaign_hard_signal,
                "fraud_pattern_hard_signal": fraud_pattern_hard_signal,
                "header_hard_signal": header_hard_signal,
                "trusted_aligned_url_context": trusted_url_context,
                "courier_phishing": {
                    "score": courier_phishing_score,
                    "category": bec_bundle.get("courier_category"),
                    "claimed_brand": bec_bundle.get("claimed_brand"),
                    "brand_domain_mismatch": bec_bundle.get("brand_domain_mismatch"),
                    "sender_domain_mismatch": bec_bundle.get("sender_domain_mismatch"),
                    "suspicious_payment_link": bec_bundle.get("suspicious_payment_link"),
                    "link_domains": bec_bundle.get("courier_link_domains"),
                    "evidence_reasons": bec_bundle.get("courier_evidence_reasons"),
                },
                "uncertainty_components": uncertainty_components,
                "missing_important_components": missing_important_components,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            },
            caveats=caveats or None,
        )
        ai_reliability = None
        try:
            reliability_rule_hits: List[str] = []
            if url_inds.get("blocklisted"):
                reliability_rule_hits.extend(["blocklist_match"] + [str(x) for x in list(url_inds.get("blocklisted") or [])[:5]])
            if int(url_inds.get("suspicious_tlds", 0) or 0) > 0:
                reliability_rule_hits.append("suspicious_tld")
            if int(url_inds.get("ip_urls", 0) or 0) > 0:
                reliability_rule_hits.append("ip_link")
            if sender_inds.get("punycode"):
                reliability_rule_hits.append("sender_punycode")
            if sender_inds.get("domain_mismatch_with_urls"):
                reliability_rule_hits.append("domain_mismatch")
            if header_hard_signal:
                reliability_rule_hits.append("header_hard_signal")
            if hard_block_signal:
                reliability_rule_hits.append("hard_block_signal")
            if campaign_hard_signal:
                reliability_rule_hits.append("campaign_hard_signal")
            if fraud_pattern_hard_signal:
                reliability_rule_hits.append("fraud_pattern_hard_signal")
            if bec_bundle.get("hard_signal"):
                reliability_rule_hits.append("bec_fraud_hard_signal")
            if bec_bundle.get("fraud_category"):
                reliability_rule_hits.append(str(bec_bundle.get("fraud_category")))
            if bec_bundle.get("courier_category"):
                reliability_rule_hits.append("courier_delivery_phishing")
            if bec_bundle.get("brand_domain_mismatch"):
                reliability_rule_hits.append("courier_brand_domain_mismatch")
            if bec_bundle.get("suspicious_payment_link"):
                reliability_rule_hits.append("courier_suspicious_payment_link")
            ai_reliability = assess_ai_reliability(
                domain="spam",
                risk_score=final_score,
                decision_confidence=decision_confidence,
                uncertainty_score=uncertainty_score,
                ood_score=ood_score,
                fidelity_score=fidelity_score,
                score_breakdown={
                    "final": final_score,
                    "decision_confidence": decision_confidence,
                    "classical": classical_score,
                    "transformer": transf_score,
                    "online": online_score,
                    "heuristic": heur_phish_score,
                    "reputation": reputation_score,
                    "campaign": campaign_score,
                    "header": header_score,
                    "fraud_pattern": fraud_pattern_score,
                    "bec_fraud": bec_fraud_score,
                    "courier_phishing": courier_phishing_score,
                    "brand_impersonation": brand_impersonation_score if brand_impersonation_score > 0.0 else None,
                    "payment_link_impersonation": payment_link_impersonation_score if payment_link_impersonation_score > 0.0 else None,
                    "bec_fraud_hard_signal": bool(bec_bundle.get("hard_signal")),
                    "bec_fraud_risk_floor": bec_bundle.get("risk_floor"),
                    "ood": ood_score,
                    "hard_block_signal": hard_block_signal,
                    "campaign_hard_signal": campaign_hard_signal,
                    "fraud_pattern_hard_signal": fraud_pattern_hard_signal,
                    "header_hard_signal": header_hard_signal,
                    "sender_punycode": bool(sender_inds.get("punycode")),
                    "domain_mismatch": bool(sender_inds.get("domain_mismatch_with_urls")),
                },
                final_action=decision,
                severity=severity,
                rule_hits=reliability_rule_hits,
                model_version=model_version,
                ruleset_version=ruleset_version,
            )
            explanation.ai_reliability = ai_reliability
        except Exception as e_rel:
            logger.error(f"AI reliability assessment failed for spam analysis: {e_rel}", exc_info=True)

        effective_handling = (
            str(getattr(ai_reliability, "recommended_handling", provisional_handling) or provisional_handling).strip().lower()
        )
        effective_review_required = bool(
            getattr(ai_reliability, "review_required", provisional_review_required)
        )
        remediation = self._spam_suggested_actions(
            recommended_handling=effective_handling,
            review_required=effective_review_required,
            fraud_category=bec_bundle.get("fraud_category"),
        )
        explanation.remediation = remediation
        decision_display = self._classify_spam_decision_display(
            spam_score=final_score,
            decision_confidence=decision_confidence,
            uncertainty_score=uncertainty_score,
            ood_score=ood_score,
            ai_reliability=ai_reliability,
            category=category,
            suspicious_threshold=thresholds["suspicious"],
            fraud_category=bec_bundle.get("fraud_category"),
        )
        explanation = complete_explainability_contract(
            explanation,
            domain="spam",
            input_summary=f"subject={subject_value[:120]}" if subject_value else "subject not provided",
            limitations=[
                "This spam/phishing score is a calibrated fusion risk score, not a guaranteed probability.",
                "Durable quarantine is recommended only when policy/configuration performs it; this response does not claim durable quarantine by itself.",
            ],
        ) or explanation

        defender_action_summary: Optional[Dict[str, Any]] = None
        defender_actions: Optional[List[str]] = None
        try:
            ir_service = self._incident_response_service_instance or IncidentResponseService.get_instance()
            action_planner_decision = decision
            if decision_display.review_required:
                action_planner_decision = "FLAG_FOR_REVIEW"
            elif decision_display.recommended_handling == "block":
                action_planner_decision = "BLOCK_EMAIL"
            elif decision_display.recommended_handling == "quarantine":
                action_planner_decision = "QUARANTINE_EMAIL"
            elif decision_display.recommended_handling == "monitor":
                action_planner_decision = "FLAG_AS_SPAM"
            elif decision_display.recommended_handling == "allow":
                action_planner_decision = "ALLOW"
            defender_action_summary = ir_service.execute_actions(
                db=db,
                domain="spam",
                entity_id=analysis_id,
                suggested_action=action_planner_decision,
                risk_level=severity,
                details={"message": f"Spam classifier decision: {action_planner_decision} ({final_label})."},
                create_alert_if_missing=False,
            )
            defender_actions = list(defender_action_summary.get("actions") or [])
        except Exception as e_ir:
            logger.error(f"Incident response action planning failed for spam analysis: {e_ir}", exc_info=True)

        # Persist analysis log for trends
        try:
            model = SpamAnalysisLogModel(
                id=analysis_id,
                tenant_id=effective_tenant_id,
                timestamp=analysis_timestamp_dt,
                received_subject=subject_value or None,
                is_spam=bool(spam_payload.is_spam),
                spam_score=float(final_score),
                classification_label=str(final_label or ""),
                category=category,
            )
            model.spam_classification_result = spam_payload.model_dump() if hasattr(spam_payload, 'model_dump') else None
            model.errors = errors_encountered or None
            db.add(model)
            db.commit()
        except Exception as e_persist:
            logger.error(f"Failed to persist spam analysis log: {e_persist}", exc_info=True)

        if spam_payload.is_spam and self._alerts_service_instance:
            # Derive tags from indicators for easier triage
            tags: List[str] = []
            if url_inds.get("blocklisted"):
                tags += [f"blocklist:{h}" for h in url_inds.get("blocklisted", [])[:5]]
            if url_inds.get("suspicious_tlds", 0) > 0:
                tags.append("suspicious_tld")
            if url_inds.get("ip_urls", 0) > 0:
                tags.append("ip_link")
            if sender_inds.get("punycode"):
                tags.append("sender_punycode")
            if sender_inds.get("ip_sender"):
                tags.append("sender_ip")
            if sender_inds.get("domain_mismatch_with_urls"):
                tags.append("sender_domain_mismatch")
            if int(url_inds.get("brand_impersonation_count", 0) or 0) > 0:
                tags.append("brand_lookalike")
            if str(header_inds.get("dmarc")) == "fail":
                tags.append("dmarc_fail")
            if str(header_inds.get("dkim")) == "fail":
                tags.append("dkim_fail")
            if str(header_inds.get("spf")) in {"fail", "softfail"}:
                tags.append("spf_fail")
            if bool(header_inds.get("reply_to_mismatch")):
                tags.append("reply_to_mismatch")
            if ood_score >= thresholds["ood"]:
                tags.append("ood_review")
            for item in list(campaign_bundle.get("matches") or [])[:3]:
                pattern_id = str(item.get("id") or "").strip()
                if pattern_id:
                    tags.append(f"campaign:{pattern_id}")
            for item in list(fraud_bundle.get("matches") or [])[:3]:
                pattern_id = str(item.get("id") or "").strip()
                if pattern_id:
                    tags.append(f"fraud:{pattern_id}")
            alert_to_create = AlertSchema(
                id=f"alert-{analysis_id}",
                timestamp=analysis_timestamp_dt,
                severity="High" if category == "blocked" else "Medium",
                title=(
                    "Phishing Email Blocked"
                    if decision_display.hard_detection and category == "blocked"
                    else "Possible Spam/Phishing Requires Review"
                    if decision_display.review_required
                    else "Suspicious Email Flagged"
                ),
                message=f"Subject: '{subject_value or 'N/A'}'",
                target="Email_System",
                acknowledged=False,
                tags=tags or None,
            )
            created_alert_model = self._alerts_service_instance.create_alert(
                db=db,
                alert_data=alert_to_create,
                tenant_id=effective_tenant_id,
            )

            try:
                alert_details = AlertSchema.model_validate(created_alert_model)
                payload = {
                    "type": "NEW_ALERT_DETAILS",
                    "tenant_id": effective_tenant_id,
                    "alert": alert_details.model_dump(mode='json'),
                }
                manager.broadcast_nowait(json.dumps(payload))
            except Exception as e_ws:
                logger.error(f"Failed to broadcast spam alert WebSocket message: {e_ws}", exc_info=True)

        # Broadcast live event for dashboard feed
        try:
            live_event = {
                "id": analysis_id,
                "type": "spam_check",
                "message": f"Spam check: {decision_display.status_label.lower()}",
                "timestamp": analysis_timestamp_dt.isoformat(),
                "isMalicious": bool(spam_payload.is_spam),
                "tenant_id": effective_tenant_id,
            }
            manager.broadcast_nowait(json.dumps(live_event))
        except Exception:
            pass

        return {
            "analysis_id": analysis_id,
            "analysis_timestamp": analysis_timestamp_dt,
            "received_subject": subject_value,
            "spam_classification": spam_payload.model_dump(),
            "errors": errors_encountered or None,
            "url_indicators": url_inds,
            "meta_features": {
                **sender_inds,
                "parsed_inline_fields": bool(parsed_fields.get("parsed_inline_fields") or raw_email_fields.get("parsed_raw_email")),
                "parsed_raw_email": bool(raw_email_fields.get("parsed_raw_email")),
                "trusted_aligned_url_context": trusted_url_context,
                "campaign_score": campaign_score,
                "campaign_match_ids": [str(x.get("id")) for x in (campaign_bundle.get("matches") or [])[:10]],
                "fraud_pattern_score": fraud_pattern_score,
                "fraud_pattern_match_ids": [str(x.get("id")) for x in (fraud_bundle.get("matches") or [])[:10]],
                "fraud_pattern_themes": fraud_bundle.get("themes"),
                "bec_fraud_score": bec_fraud_score,
                "fraud_category": bec_bundle.get("fraud_category"),
                "fraud_category_label": bec_bundle.get("fraud_category_label"),
                "bec_matched_patterns": bec_bundle.get("matched_patterns"),
                "bec_evidence_reasons": bec_bundle.get("evidence_reasons"),
                "bec_risk_floor": bec_bundle.get("risk_floor"),
                "bec_recommended_handling_hint": bec_bundle.get("recommended_handling_hint"),
                "courier_phishing_score": courier_phishing_score,
                "courier_category": bec_bundle.get("courier_category"),
                "claimed_brand": bec_bundle.get("claimed_brand"),
                "brand_domain_mismatch": bec_bundle.get("brand_domain_mismatch"),
                "sender_domain_mismatch": bec_bundle.get("sender_domain_mismatch"),
                "suspicious_payment_link": bec_bundle.get("suspicious_payment_link"),
                "courier_evidence_reasons": bec_bundle.get("courier_evidence_reasons"),
                "courier_link_domains": bec_bundle.get("courier_link_domains"),
                "courier_payment_paths": bec_bundle.get("courier_payment_paths"),
                "courier_delivery_lure": bec_bundle.get("courier_delivery_lure"),
                "courier_payment_fee_lure": bec_bundle.get("courier_payment_fee_lure"),
                "courier_urgency_or_threat": bec_bundle.get("courier_urgency_or_threat"),
                "courier_tracking_lure": bec_bundle.get("courier_tracking_lure"),
                "courier_official_domain_context": bec_bundle.get("courier_official_domain_context"),
                "header_indicators": header_inds,
                "ood_score": ood_score,
                "ood_reasons": ood.get("reasons"),
                "ood_metrics": ood.get("metrics"),
                "transformer_confidence": transformer_bundle.get("confidence") if transformer_bundle else None,
                "decision_category": category,
                "decision_confidence": decision_confidence,
                "uncertainty_score": uncertainty_score,
                "uncertainty_components": uncertainty_components,
                "pipeline_version": "spam_detection_v3",
            },
            "score_breakdown": {
                "final": final_score,
                "decision_confidence": decision_confidence,
                "raw_fused": fused["raw"],
                "classical": classical_score,
                "transformer": transf_score,
                "online": online_score,
                "heuristic": heur_phish_score,
                "url_heuristic": url_sender_heuristic_score,
                "reputation": reputation_score,
                "campaign": campaign_score,
                "header": header_score,
                "fraud_pattern": fraud_pattern_score,
                "bec_fraud": bec_fraud_score,
                "courier_phishing": courier_phishing_score,
                "brand_impersonation": brand_impersonation_score if brand_impersonation_score > 0.0 else None,
                "payment_link_impersonation": payment_link_impersonation_score if payment_link_impersonation_score > 0.0 else None,
                "fraud_category": bec_bundle.get("fraud_category"),
                "bec_risk_floor": bec_bundle.get("risk_floor"),
                "ood": ood_score,
                "thresholds": thresholds,
                "hard_block_signal": hard_block_signal,
                "campaign_hard_signal": campaign_hard_signal,
                "fraud_pattern_hard_signal": fraud_pattern_hard_signal,
                "header_hard_signal": header_hard_signal,
                "trusted_aligned_url_context": trusted_url_context,
                "uncertainty_components": uncertainty_components,
            },
            "explanation": explanation,
            "ai_reliability": ai_reliability,
            "decision_display": decision_display,
            "defender_actions": defender_actions,
            "defender_action_summary": defender_action_summary,
        }

    # Settings helpers
    def get_settings(self) -> Dict[str, Any]:
        suspicious_tlds = list(
            getattr(self, "_suspicious_tlds_override", None)
            or (os.getenv("SUSPICIOUS_TLDS", "zip,top,work,xyz,country,click,link,live,site,online,icu").lower()).split(",")
        )
        thresholds = self._resolved_thresholds()
        feature_weights = self._resolved_feature_weights()
        calibration = self._resolved_calibration()
        return {
            "transformer_enabled": bool(self._transformer_pipeline is not None),
            "final_threshold": float(thresholds["suspicious"]),
            "thresholds": thresholds,
            "feature_weights": feature_weights,
            "calibration": calibration,
            "suspicious_tlds": suspicious_tlds,
            "blocklist_count": len(self._blocklist_domains or []),
            "allowlist_count": len(self._allowlist_domains or []),
            "reputation_entries": len(self._domain_reputation or {}),
            "fraud_pattern_count": len((self._fraud_pattern_pack or {}).get("patterns") or []),
            "fraud_pattern_version": (self._fraud_pattern_pack or {}).get("version"),
            "fraud_pattern_source": (self._fraud_pattern_pack or {}).get("source_type"),
            "fraud_pattern_path": self._fraud_pattern_pack_path(),
            "phase_status": {
                "phase_1_signal_fusion": True,
                "phase_1_ood_routing": True,
                "phase_2_fraud_pattern_pack": len((self._fraud_pattern_pack or {}).get("patterns") or []) > 0,
                "phase_2_header_auth_signals": True,
                "phase_3_feedback_retraining": True,
                "phase_3_auto_pipeline": str(os.getenv("SPAM_AUTOPIPELINE_ENABLED", "true")).strip().lower() in {"1", "true", "yes", "on"},
            },
            "blocklist_path": os.getenv("REPUTATION_BLOCKLIST_PATH", "backend/data/reputation/blocklist.txt"),
            "allowlist_path": os.getenv("REPUTATION_ALLOWLIST_PATH", "backend/data/reputation/allowlist.txt"),
            "reputation_scores_path": os.getenv("REPUTATION_SCORES_PATH", "backend/data/reputation/domain_scores.csv"),
        }

    def set_settings(
        self,
        final_threshold: Optional[Any] = None,
        suspicious_tlds: Optional[Any] = None,
        thresholds: Optional[Any] = None,
        feature_weights: Optional[Any] = None,
        calibration: Optional[Any] = None,
        allow_threshold: Optional[Any] = None,
        suspicious_threshold: Optional[Any] = None,
        block_threshold: Optional[Any] = None,
        ood_threshold: Optional[Any] = None,
    ) -> Dict[str, Any]:
        if final_threshold is not None:
            try:
                thr = float(final_threshold)
            except Exception as e:
                raise ValueError(f"Invalid final_threshold: {e}")
            if thr < 0.0 or thr > 1.0:
                raise ValueError("final_threshold must be between 0.0 and 1.0")
            self._final_threshold_override = thr
            existing = dict(getattr(self, "_thresholds_override", {}) or {})
            existing["suspicious"] = thr
            self._thresholds_override = existing

        if suspicious_tlds is not None:
            if isinstance(suspicious_tlds, str):
                values = [x.strip().lower() for x in suspicious_tlds.split(",") if x and x.strip()]
            elif isinstance(suspicious_tlds, list):
                values = [str(x).strip().lower() for x in suspicious_tlds if str(x).strip()]
            else:
                raise ValueError("suspicious_tlds must be a list of strings or comma-separated string")
            self._suspicious_tlds_override = values

        merged_thresholds = dict(getattr(self, "_thresholds_override", {}) or {})
        if isinstance(thresholds, dict):
            for key in ("allow", "suspicious", "block", "ood"):
                value = thresholds.get(key)
                if value is None:
                    continue
                try:
                    merged_thresholds[key] = self._clamp01(float(value))
                except Exception as e:
                    raise ValueError(f"Invalid thresholds.{key}: {e}")
        if allow_threshold is not None:
            merged_thresholds["allow"] = self._clamp01(self._safe_float(allow_threshold, 0.0))
        if suspicious_threshold is not None:
            merged_thresholds["suspicious"] = self._clamp01(self._safe_float(suspicious_threshold, 0.0))
        if block_threshold is not None:
            merged_thresholds["block"] = self._clamp01(self._safe_float(block_threshold, 0.0))
        if ood_threshold is not None:
            merged_thresholds["ood"] = self._clamp01(self._safe_float(ood_threshold, 0.0))
        if merged_thresholds:
            if merged_thresholds.get("suspicious", 0.0) < merged_thresholds.get("allow", 0.0):
                raise ValueError("suspicious threshold must be >= allow threshold")
            if merged_thresholds.get("block", 0.0) < merged_thresholds.get("suspicious", 0.0):
                raise ValueError("block threshold must be >= suspicious threshold")
            self._thresholds_override = merged_thresholds

        if feature_weights is not None:
            if not isinstance(feature_weights, dict):
                raise ValueError("feature_weights must be an object")
            merged_weights = dict(getattr(self, "_feature_weights_override", {}) or {})
            for key in ("classical", "transformer", "online", "heuristic", "reputation", "campaign", "header", "fraud_pattern"):
                if key in feature_weights and feature_weights[key] is not None:
                    try:
                        parsed = float(feature_weights[key])
                    except Exception as e:
                        raise ValueError(f"Invalid feature_weights.{key}: {e}")
                    if parsed < 0.0:
                        raise ValueError(f"feature_weights.{key} must be non-negative")
                    merged_weights[key] = parsed
            self._feature_weights_override = merged_weights

        if calibration is not None:
            if not isinstance(calibration, dict):
                raise ValueError("calibration must be an object")
            merged_cal = dict(getattr(self, "_calibration_override", {}) or {})
            if "a" in calibration and calibration["a"] is not None:
                try:
                    merged_cal["a"] = float(calibration["a"])
                except Exception as e:
                    raise ValueError(f"Invalid calibration.a: {e}")
            if "b" in calibration and calibration["b"] is not None:
                try:
                    merged_cal["b"] = float(calibration["b"])
                except Exception as e:
                    raise ValueError(f"Invalid calibration.b: {e}")
            self._calibration_override = merged_cal

        out = self.get_settings()
        out["updated"] = True
        return out

    def reload_blocklist(self, path: Optional[str] = None) -> Dict[str, Any]:
        bl_path = path or os.getenv("REPUTATION_BLOCKLIST_PATH", "backend/data/reputation/blocklist.txt")
        try:
            if os.path.exists(bl_path):
                self._blocklist_domains = self._load_domain_list(bl_path)
                return {"reloaded": True, "blocklist_count": len(self._blocklist_domains), "path": bl_path}
            self._blocklist_domains = set()
            return {"reloaded": False, "error": "path_not_found", "path": bl_path}
        except Exception as e:
            logger.error(f"Failed to reload blocklist: {e}")
            return {"reloaded": False, "error": str(e)}

    def reload_allowlist(self, path: Optional[str] = None) -> Dict[str, Any]:
        al_path = path or os.getenv("REPUTATION_ALLOWLIST_PATH", "backend/data/reputation/allowlist.txt")
        try:
            if os.path.exists(al_path):
                self._allowlist_domains = self._load_domain_list(al_path)
                return {"reloaded": True, "allowlist_count": len(self._allowlist_domains), "path": al_path}
            self._allowlist_domains = set()
            return {"reloaded": False, "error": "path_not_found", "path": al_path}
        except Exception as e:
            logger.error(f"Failed to reload allowlist: {e}")
            return {"reloaded": False, "error": str(e)}

    def reload_reputation_scores(self, path: Optional[str] = None) -> Dict[str, Any]:
        rep_path = path or os.getenv("REPUTATION_SCORES_PATH", "backend/data/reputation/domain_scores.csv")
        try:
            if os.path.exists(rep_path):
                self._domain_reputation = self._load_reputation_map(rep_path)
                return {"reloaded": True, "reputation_entries": len(self._domain_reputation), "path": rep_path}
            self._domain_reputation = {}
            return {"reloaded": False, "error": "path_not_found", "path": rep_path}
        except Exception as e:
            logger.error(f"Failed to reload reputation scores: {e}")
            return {"reloaded": False, "error": str(e)}
