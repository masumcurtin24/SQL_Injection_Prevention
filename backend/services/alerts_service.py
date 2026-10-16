# backend/services/alerts_service.py (Corrected)
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from backend.utils.logging_utils import setup_logger
from backend.core.models import (
    DEFAULT_TENANT_ID,
    Alert as AlertModel,
    AlertCaseLink as AlertCaseLinkModel,
    SQLAnalysisLog as SQLAnalysisLogModel,
    FileAnalysisLog as FileAnalysisLogModel,
    SpamAnalysisLog as SpamAnalysisLogModel,
    SecurityCase as SecurityCaseModel,
)
from backend.server.schemas.responses import Alert as AlertSchema, AlertsListResponse
from backend.services.ai_reliability_service import assess_ai_reliability
from backend.services.explainability_contract import complete_explainability_contract
from backend.server.schemas.responses import XAIExplanation
from backend.utils.user_summary import build_user_summary_map

logger = setup_logger(__name__)

class AlertsService:
    _instance: Optional['AlertsService'] = None
    _initialized_flag: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(AlertsService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if AlertsService._initialized_flag:
            return
        logger.info("Initializing AlertsService...")
        AlertsService._initialized_flag = True
        logger.info("AlertsService initialized successfully.")

    @classmethod
    def get_instance(cls) -> 'AlertsService':
        if not cls._initialized_flag or cls._instance is None:
            raise RuntimeError("AlertsService has not been initialized correctly. Call the constructor once at startup.")
        return cls._instance

    @classmethod # <--- FIX: Added @classmethod decorator
    def is_initialized(cls) -> bool:
        return cls._initialized_flag

    @staticmethod
    def _resolve_tenant_id(tenant_id: Optional[str]) -> str:
        value = str(tenant_id or "").strip()
        return value or DEFAULT_TENANT_ID

    def create_alert(self, db: Session, alert_data: AlertSchema, tenant_id: Optional[str] = None) -> AlertModel:
        logger.info(f"Creating new alert in DB: Title='{alert_data.title}', Severity='{alert_data.severity}'")

        if not alert_data.id:
            alert_data.id = f"alert-{uuid.uuid4()}"

        payload = alert_data.model_dump(
            exclude={"owner_user_id", "owner"},
            exclude_none=True,
        )
        payload.pop("tenant_id", None)
        payload["tenant_id"] = self._resolve_tenant_id(tenant_id)
        db_alert = AlertModel(**payload)

        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)

        logger.info(f"New alert created with ID: {db_alert.id}")
        return db_alert

    def get_alerts(
        self, db: Session, page: int = 1, page_size: int = 10,
        severity: Optional[str] = None, acknowledged: Optional[bool] = None,
        search_term: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> AlertsListResponse:
        tenant = self._resolve_tenant_id(tenant_id)
        query = db.query(AlertModel).filter(AlertModel.tenant_id == tenant)

        if severity:
            query = query.filter(AlertModel.severity == severity)
        if acknowledged is not None:
            query = query.filter(AlertModel.acknowledged == acknowledged)
        if search_term:
            search_filter = or_(
                AlertModel.title.ilike(f"%{search_term}%"),
                AlertModel.message.ilike(f"%{search_term}%"),
                AlertModel.source_ip.ilike(f"%{search_term}%"),
                AlertModel.query.ilike(f"%{search_term}%"),
                AlertModel._tags_json.ilike(f"%{search_term}%")
            )
            query = query.filter(search_filter)

        total_alerts = query.count()
        total_pages = (total_alerts + page_size - 1) // page_size

        alerts = query.order_by(AlertModel.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()

        alert_ids = [str(alert.id) for alert in alerts]
        latest_case_by_alert: Dict[str, str] = {}
        owner_by_case: Dict[str, Optional[str]] = {}
        owner_map: Dict[str, Dict[str, Any]] = {}

        if alert_ids:
            link_rows = (
                db.query(AlertCaseLinkModel.alert_id, AlertCaseLinkModel.case_id)
                .filter(AlertCaseLinkModel.tenant_id == tenant, AlertCaseLinkModel.alert_id.in_(alert_ids))
                .order_by(AlertCaseLinkModel.linked_at.desc())
                .all()
            )
            for alert_id, case_id in link_rows:
                alert_key = str(alert_id)
                if alert_key in latest_case_by_alert:
                    continue
                latest_case_by_alert[alert_key] = str(case_id)

            linked_case_ids = list(set(latest_case_by_alert.values()))
            if linked_case_ids:
                case_rows = (
                    db.query(SecurityCaseModel.id, SecurityCaseModel.owner_user_id)
                    .filter(SecurityCaseModel.tenant_id == tenant, SecurityCaseModel.id.in_(linked_case_ids))
                    .all()
                )
                for case_id, owner_user_id in case_rows:
                    owner_by_case[str(case_id)] = str(owner_user_id or "").strip() or None
                owner_map = build_user_summary_map(
                    db=db,
                    user_ids=[owner for owner in owner_by_case.values() if owner],
                    include_unknown=False,
                )

        payload_rows: List[AlertSchema] = []
        for alert in alerts:
            base = AlertSchema.model_validate(alert).model_dump()
            case_id = latest_case_by_alert.get(str(alert.id))
            owner_user_id = owner_by_case.get(case_id) if case_id else None
            base["owner_user_id"] = owner_user_id
            base["owner"] = owner_map.get(str(owner_user_id)) if owner_user_id else None
            payload_rows.append(AlertSchema.model_validate(base))

        return AlertsListResponse(
            alerts=payload_rows,
            total_alerts=total_alerts,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    def get_alert_by_id(self, db: Session, alert_id: str, tenant_id: Optional[str] = None) -> Optional[AlertModel]:
        tenant = self._resolve_tenant_id(tenant_id)
        return db.query(AlertModel).filter(AlertModel.tenant_id == tenant, AlertModel.id == alert_id).first()

    def _extract_analysis_id(self, alert_id: str) -> Optional[str]:
        if not alert_id:
            return None
        if alert_id.startswith("alert-") and len(alert_id) > len("alert-"):
            return alert_id[len("alert-"):]
        return None

    def _severity_to_action(self, severity: str, domain: str, decision_hint: Optional[str] = None) -> List[str]:
        decision = str(decision_hint or "").upper()
        sev = str(severity or "").lower()
        actions: List[str] = []
        if "BLOCK" in decision:
            actions.append("BLOCK_REQUEST")
        elif "QUARANTINE" in decision:
            actions.append("QUARANTINE")
        elif decision.startswith("FLAG") or decision.startswith("WARN"):
            actions.append("FLAG_FOR_REVIEW")

        if sev in {"critical", "high"}:
            if "BLOCK_REQUEST" not in actions:
                actions.append("BLOCK_REQUEST")
            actions.append("NOTIFY_SOC")
            actions.append("CREATE_INVESTIGATION_CASE")
        elif sev == "medium":
            if "FLAG_FOR_REVIEW" not in actions:
                actions.append("FLAG_FOR_REVIEW")
            actions.append("NOTIFY_ANALYST")
        else:
            actions.append("MONITOR")

        # Domain-specific default hints.
        if domain == "file" and "QUARANTINE" not in actions and sev in {"critical", "high", "medium"}:
            actions.append("QUARANTINE")
        if domain == "spam" and sev in {"critical", "high", "medium"}:
            actions.append("TAG_MESSAGE")
        if domain == "sql" and sev in {"critical", "high"}:
            actions.append("RATE_LIMIT_SOURCE")

        # Keep stable ordering with duplicates removed.
        seen = set()
        ordered: List[str] = []
        for a in actions:
            if a in seen:
                continue
            seen.add(a)
            ordered.append(a)
        return ordered

    @staticmethod
    def _normalize_confidence_meta(value: Any) -> tuple[Optional[float], Optional[str], Optional[float]]:
        try:
            conf = float(value)
        except Exception:
            return None, None, None
        conf = max(0.0, min(1.0, conf))
        if conf >= 0.85:
            label = "high"
        elif conf >= 0.60:
            label = "medium"
        else:
            label = "low"
        # Alert explainability reconstruction should not invent uncertainty as
        # a cosmetic inverse of confidence. Analyzer-specific uncertainty is
        # attached where it is actually available.
        return conf, label, None

    @staticmethod
    def _clamp01(value: Any) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return 0.0

    @classmethod
    def _decision_confidence_from_risk(
        cls,
        *,
        risk_score: Any,
        decision: str,
        safe_tokens: Optional[set[str]] = None,
        uncertainty_score: Any = 0.0,
        ood_score: Any = 0.0,
    ) -> float:
        risk = cls._clamp01(risk_score)
        action = str(decision or "").strip().upper().replace("-", "_")
        safe = safe_tokens or {"ALLOW", "SAFE", "CLEAN", "HAM", "NOT_SPAM", "MONITOR", "ALLOW_UPLOAD"}
        safe_decision = action.startswith("ALLOW") or action in safe
        base_confidence = (1.0 - risk) if safe_decision else risk
        _ = uncertainty_score, ood_score
        return round(cls._clamp01(base_confidence), 4)

    @staticmethod
    def _attach_ai_reliability(xai: Dict[str, Any], *, domain: str) -> Dict[str, Any]:
        if not isinstance(xai, dict):
            return xai
        try:
            score_breakdown: Dict[str, Any] = {}
            for step in xai.get("decision_trace") or []:
                if not isinstance(step, dict):
                    continue
                stage = str(step.get("stage") or "stage")
                details = step.get("details")
                if isinstance(details, dict):
                    score_breakdown[stage] = details
            rule_hits: List[str] = []
            for item in xai.get("evidence") or []:
                if not isinstance(item, dict):
                    continue
                for key in ("id", "source", "snippet"):
                    value = str(item.get(key) or "").strip()
                    if value:
                        rule_hits.append(value)
            assessment = assess_ai_reliability(
                domain=domain,
                risk_score=xai.get("risk_score"),
                decision_confidence=xai.get("decision_confidence") or xai.get("confidence"),
                uncertainty_score=xai.get("uncertainty_score") or 0.0,
                ood_score=xai.get("ood_score") or 0.0,
                fidelity_score=xai.get("fidelity_score") if xai.get("fidelity_score") is not None else 1.0,
                score_breakdown=score_breakdown or None,
                final_action=xai.get("decision"),
                severity=xai.get("severity"),
                rule_hits=rule_hits,
                model_version=xai.get("model_version"),
                ruleset_version=xai.get("ruleset_version"),
            )
            xai["ai_reliability"] = assessment.model_dump(mode="json")
            try:
                explanation = XAIExplanation.model_validate(xai)
                completed = complete_explainability_contract(
                    explanation,
                    domain=domain,
                    input_summary=f"alert_id={xai.get('provenance', {}).get('analysis_log_id')}",
                    limitations=["Alert explainability is reconstructed from persisted analyzer logs."],
                )
                if completed is not None:
                    xai = completed.model_dump(mode="json", exclude_none=True)
            except Exception as contract_exc:
                logger.error(
                    "Failed to complete alert explainability contract: %s",
                    contract_exc,
                    exc_info=True,
                )
        except Exception as exc:
            logger.error("Failed to attach AI reliability to alert explainability: %s", exc, exc_info=True)
        return xai

    def _build_sql_explainability(self, alert: AlertModel, log: SQLAnalysisLogModel) -> Dict[str, Any]:
        anomaly = log.anomaly_detection_result or {}
        validation = log.query_validation_result or {}
        combined = log.combined_assessment or {}
        severity = str(combined.get("overall_risk_level") or alert.severity or "Medium")
        decision = str(combined.get("suggested_action") or ("BLOCK_IMMEDIATE" if severity.lower() in {"critical", "high"} else "WARN"))
        risk_score = combined.get("calibrated_risk_score")
        if not isinstance(risk_score, (int, float)):
            try:
                score = float(validation.get("classification_score"))
                label = str(validation.get("classification_label") or "").lower()
                if "benign" in label or "safe" in label:
                    risk_score = 1.0 - self._clamp01(score)
                else:
                    risk_score = self._clamp01(score)
            except Exception:
                risk_score = None
        anomaly_score = anomaly.get("score")
        anomaly_is_anom = bool(anomaly.get("is_anomalous"))
        ood_score = None
        try:
            risk_for_ood = self._clamp01(risk_score) if isinstance(risk_score, (int, float)) else None
            if anomaly_is_anom and (risk_for_ood is None or risk_for_ood < 0.55):
                ood_score = 0.7
            elif anomaly_is_anom:
                ood_score = 0.45
        except Exception:
            ood_score = None
        decision_confidence = None
        if isinstance(risk_score, (int, float)):
            decision_confidence = self._decision_confidence_from_risk(
                risk_score=risk_score,
                decision=decision,
                ood_score=ood_score,
            )
        conf, conf_label, uncertainty = self._normalize_confidence_meta(decision_confidence)

        evidence: List[Dict[str, Any]] = []
        if bool(anomaly.get("is_anomalous")):
            evidence.append({
                "id": "anomaly_model_hit",
                "label": "Anomaly model flagged query",
                "severity": "high" if severity.lower() in {"critical", "high"} else "medium",
                "description": "The anomaly detector considered this query outside normal behavior.",
                "snippet": f"score={anomaly.get('score')}",
                "source": "anomaly_model",
            })
        if validation.get("classification_label"):
            evidence.append({
                "id": "nlp_classifier_label",
                "label": "Classifier label",
                "severity": "medium",
                "description": "Language model classification contributed to risk scoring.",
                "snippet": f"{validation.get('classification_label')} (p={validation.get('classification_score')})",
                "source": "query_validation",
            })

        for idx, tag in enumerate(alert.tags or []):
            t = str(tag or "").strip()
            if not t or t.startswith("decision:") or t.startswith("anomaly:"):
                continue
            evidence.append({
                "id": f"tag_{idx}",
                "label": "Heuristic / policy indicator",
                "severity": "low",
                "description": "Tag captured during SQL analysis and alert generation.",
                "snippet": t,
                "source": "heuristics",
            })

        trace = [
            {
                "stage": "anomaly_detection",
                "summary": "Scored query behavior using anomaly model.",
                "details": anomaly or None,
            },
            {
                "stage": "query_validation",
                "summary": "Classified query intent and known malicious signatures.",
                "details": validation or None,
            },
            {
                "stage": "risk_aggregation",
                "summary": f"Risk={severity}; decision={decision}.",
                "details": combined or None,
            },
        ]

        remediation = [
            "Use parameterized queries/prepared statements.",
            "Enforce input allow-lists and query length limits.",
            "Block repeated high-risk requests from the same source.",
        ]
        if severity.lower() in {"critical", "high"}:
            remediation.append("Trigger incident response and review application logs around this request.")

        fidelity_score = None
        try:
            signal_total = 0
            signal_support = 0
            restrictive = decision != "ALLOW"
            if anomaly:
                signal_total += 1
                if anomaly_is_anom == restrictive:
                    signal_support += 1
            if validation:
                signal_total += 1
                val_mal = "malicious" in str(validation.get("classification_label") or "").lower()
                if val_mal == restrictive:
                    signal_support += 1
            fidelity_score = round(signal_support / signal_total, 4) if signal_total > 0 else None
        except Exception:
            fidelity_score = None

        abstain_reason = "LOW_CONSENSUS_REVIEW_REQUIRED" if (ood_score is not None and ood_score >= 0.7 and severity.lower() not in {"critical"}) else None

        return {
            "decision": decision,
            "severity": severity,
            "threat_category": "SQL Injection",
            "risk_score": risk_score,
            "decision_confidence": conf,
            "confidence": conf,
            "confidence_label": conf_label,
            "uncertainty_score": uncertainty,
            "fidelity_score": fidelity_score,
            "ood_score": ood_score,
            "abstain_reason": abstain_reason,
            "impact": "Potential data exposure or unauthorized query execution.",
            "evidence": evidence or None,
            "decision_trace": trace,
            "remediation": remediation,
            "counterfactual": "If anomaly score was normal and malicious indicators were absent, this request would likely be allowed.",
            "model_version": "sql_alert_enrichment_v1",
            "ruleset_version": "sql_heuristics_v2",
            "policy_version": "sql_policy_precision_v2",
            "thresholds": {"classification_suspicious": 0.60, "classification_high": 0.85},
            "provenance": {
                "source": "alerts_service_enrichment",
                "analysis_log_id": log.id,
                "anomaly_score": anomaly_score,
            },
            "caveats": [
                "Explainability reconstructed from persisted alert-linked SQL logs.",
            ],
        }

    def _build_file_explainability(self, alert: AlertModel, log: FileAnalysisLogModel) -> Dict[str, Any]:
        details = log.file_details or {}
        type_validation = details.get("type_validation") or {}
        malware_scan = details.get("malware_scan") or {}
        ml_scan = details.get("ml_scan") or {}
        overall = log.overall_assessment or {}

        severity = str(alert.severity or overall.get("overall_status") or "Medium")
        decision = str(overall.get("recommended_action") or ("BLOCK_UPLOAD_QUARANTINE" if severity.lower() in {"critical", "high"} else "FLAG_REVIEW"))
        risk_score = overall.get("risk_score")

        evidence: List[Dict[str, Any]] = []
        if type_validation.get("is_allowed_type") is False:
            evidence.append({
                "id": "disallowed_mime",
                "label": "Disallowed file type",
                "severity": "high",
                "description": "Detected MIME type is outside allowed upload policy.",
                "snippet": str(type_validation.get("detected_mime_type")),
                "source": "type_validation",
            })

        if bool(malware_scan.get("is_malicious")):
            scan_details = malware_scan.get("scan_details") or {}
            outer = scan_details.get("outer_yara_matches") or []
            matched = ", ".join([str(x) for x in outer[:8]]) if isinstance(outer, list) else None
            evidence.append({
                "id": "yara_match",
                "label": "YARA/signature match",
                "severity": "high",
                "description": "Known malicious or suspicious signature matched the uploaded file.",
                "snippet": matched or str(malware_scan.get("threat_name") or ""),
                "source": "yara",
            })

        if bool(ml_scan.get("is_suspicious_ml")):
            evidence.append({
                "id": "ml_suspicious_content",
                "label": "ML suspicious content",
                "severity": "medium",
                "description": "Content model indicated suspicious tokens or behavior.",
                "snippet": f"{ml_scan.get('prediction_label_ml')} (p={ml_scan.get('prediction_score_ml')})",
                "source": "ml",
            })

        for idx, reason in enumerate((overall.get("reasoning") or [])[:8]):
            evidence.append({
                "id": f"reason_{idx}",
                "label": "Assessment reason",
                "severity": "low",
                "description": "Rule/heuristic reasoning from the file assessment pipeline.",
                "snippet": str(reason),
                "source": "aggregator",
            })

        trace = [
            {
                "stage": "type_validation",
                "summary": "Validated MIME and extension policy.",
                "details": type_validation or None,
            },
            {
                "stage": "signature_scan",
                "summary": "Executed YARA/signature checks.",
                "details": malware_scan or None,
            },
            {
                "stage": "ml_scan",
                "summary": "Ran ML file-content scanner.",
                "details": ml_scan or None,
            },
            {
                "stage": "risk_aggregation",
                "summary": f"Status={overall.get('overall_status')}; decision={decision}.",
                "details": overall or None,
            },
        ]

        fidelity_score = None
        try:
            signal_total = 0
            signal_support = 0
            restrictive = not decision.startswith("ALLOW")
            if type_validation:
                signal_total += 1
                type_restrictive = type_validation.get("is_allowed_type") is False
                if type_restrictive == restrictive:
                    signal_support += 1
            if malware_scan:
                signal_total += 1
                if bool(malware_scan.get("is_malicious")) == restrictive:
                    signal_support += 1
            if ml_scan:
                signal_total += 1
                if bool(ml_scan.get("is_suspicious_ml")) == restrictive:
                    signal_support += 1
            fidelity_score = round(signal_support / signal_total, 4) if signal_total > 0 else None
        except Exception:
            fidelity_score = None

        ood_score = None
        mime = str(type_validation.get("detected_mime_type") or "").lower()
        if mime in {"application/octet-stream", "binary/octet-stream"}:
            ood_score = 0.75
        elif type_validation.get("is_allowed_type") is False:
            ood_score = 0.55
        abstain_reason = "HIGH_OOD_FILE_REVIEW_REQUIRED" if (ood_score is not None and ood_score >= 0.7 and severity.lower() not in {"critical", "high"}) else None
        decision_confidence = None
        if isinstance(risk_score, (int, float)):
            decision_confidence = self._decision_confidence_from_risk(
                risk_score=risk_score,
                decision=decision,
                safe_tokens={"ALLOW", "ALLOW_UPLOAD", "SAFE", "CLEAN"},
                ood_score=ood_score,
            )
        conf, conf_label, uncertainty = self._normalize_confidence_meta(decision_confidence)

        return {
            "decision": decision,
            "severity": severity,
            "threat_category": "File Upload Security",
            "risk_score": risk_score,
            "decision_confidence": conf,
            "confidence": conf,
            "confidence_label": conf_label,
            "uncertainty_score": uncertainty,
            "fidelity_score": fidelity_score,
            "ood_score": ood_score,
            "abstain_reason": abstain_reason,
            "impact": "Potential malware delivery, exploit artifacts, or policy violations in uploaded content.",
            "evidence": evidence or None,
            "model_attributions": ml_scan.get("shap_top_features"),
            "decision_trace": trace,
            "remediation": [
                "Quarantine flagged files for analyst review.",
                "Keep YARA signatures and blocklists up to date.",
                "Restrict uploads to approved MIME types and enforce archive inspection.",
            ],
            "counterfactual": "Without policy violations/signature matches and with benign ML score, this file would likely be allowed.",
            "model_version": str(ml_scan.get("model_name") or ml_scan.get("classifier_name") or "file_alert_enrichment_v1"),
            "ruleset_version": str(malware_scan.get("scan_engine_version") or "yara_ruleset_unknown"),
            "policy_version": "file_detection_policy_v2",
            "thresholds": {"review_risk_min": 0.60, "block_risk_min": 0.80},
            "provenance": {
                "source": "alerts_service_enrichment",
                "analysis_log_id": log.id,
            },
            "caveats": [
                "Explainability reconstructed from persisted alert-linked file logs.",
            ],
        }

    def _build_spam_explainability(self, alert: AlertModel, log: SpamAnalysisLogModel) -> Dict[str, Any]:
        cls = log.spam_classification_result or {}
        is_spam = bool(cls.get("is_spam"))
        spam_score = cls.get("spam_score")
        label = str(cls.get("classification_label") or ("Spam" if is_spam else "Ham"))
        severity = str(alert.severity or ("Medium" if is_spam else "Low"))
        decision_confidence = cls.get("decision_confidence")
        if not isinstance(decision_confidence, (int, float)):
            try:
                risk = max(0.0, min(1.0, float(spam_score)))
            except Exception:
                risk = 0.0
            safe_labels = {"safe", "ham", "clean", "benign", "not_spam", "not spam", "legitimate", "normal"}
            label_lc = label.strip().lower()
            decision_confidence = (1.0 - risk) if (label_lc in safe_labels or not is_spam) else risk
        try:
            spam_risk_value = max(0.0, min(1.0, float(spam_score)))
        except Exception:
            spam_risk_value = None
        grey_zone = bool(spam_risk_value is not None and 0.45 <= spam_risk_value <= 0.65)
        low_confidence = bool(isinstance(decision_confidence, (int, float)) and float(decision_confidence) < 0.70)
        if grey_zone or low_confidence:
            decision = "FLAG_FOR_REVIEW"
        elif is_spam and spam_risk_value is not None and spam_risk_value >= 0.85:
            decision = "BLOCK_OR_QUARANTINE"
        elif is_spam:
            decision = "MONITOR_AND_REVIEW"
        else:
            decision = "ALLOW_WITH_MONITORING"
        conf, conf_label, uncertainty = self._normalize_confidence_meta(decision_confidence)
        fidelity_score = 0.8 if is_spam else 0.7

        evidence: List[Dict[str, Any]] = []
        evidence.append({
            "id": "spam_classifier",
            "label": "Spam classifier output",
            "severity": "medium" if is_spam else "low",
            "description": "Email classifier output used in alerting.",
            "snippet": f"{label} (score={spam_score})",
            "source": "spam_classifier",
        })

        for idx, tag in enumerate((alert.tags or [])[:8]):
            evidence.append({
                "id": f"tag_{idx}",
                "label": "Indicator tag",
                "severity": "low",
                "description": "Additional indicator from spam triage metadata.",
                "snippet": str(tag),
                "source": "policy",
            })

        return {
            "decision": decision,
            "severity": severity,
            "threat_category": "Spam / Phishing",
            "risk_score": spam_score,
            "decision_confidence": conf,
            "confidence": conf,
            "spam_risk": spam_score,
            "confidence_label": conf_label,
            "uncertainty_score": uncertainty,
            "fidelity_score": fidelity_score,
            "ood_score": None,
            "abstain_reason": None,
            "impact": "Potential phishing, credential theft, or malicious link delivery.",
            "evidence": evidence,
            "decision_trace": [
                {
                    "stage": "spam_classification",
                    "summary": f"Classifier label={label}, spam={is_spam}.",
                    "details": cls or None,
                },
                {
                    "stage": "policy_decision",
                    "summary": f"Policy decided: {decision}.",
                    "details": {"alert_tags": alert.tags or []},
                },
            ],
            "remediation": (
                [
                    "Route to analyst review before blocking.",
                    "Verify sender/domain independently.",
                    "Check headers, URL reputation, and business context.",
                    "Do not automatically block sender/domain from this single grey-zone result.",
                ]
                if decision == "FLAG_FOR_REVIEW"
                else [
                    "Quarantine according to configured mail policy.",
                    "Preserve evidence and investigate related recipients.",
                    "Collect analyst feedback for continuous model improvement.",
                ]
                if is_spam
                else [
                    "No strong indicators found.",
                    "Continue normal handling and monitor if similar reports appear.",
                ]
            ),
            "counterfactual": "If spam score and suspicious indicators were low, this message would likely pass.",
            "model_version": "spam_alert_enrichment_v1",
            "ruleset_version": "spam_reputation_rules_v2",
            "policy_version": "spam_policy_calibrated_v2",
            "thresholds": {"suspicious_min": 0.60, "block_min": 0.85},
            "provenance": {
                "source": "alerts_service_enrichment",
                "analysis_log_id": log.id,
            },
            "caveats": [
                "Explainability reconstructed from persisted alert-linked spam logs.",
            ],
        }

    def get_alert_detail_payload(self, db: Session, alert_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        tenant = self._resolve_tenant_id(tenant_id)
        alert = self.get_alert_by_id(db=db, alert_id=alert_id, tenant_id=tenant)
        if not alert:
            return None

        linked_case_ids = [
            str(row.case_id)
            for row in db.query(AlertCaseLinkModel.case_id)
            .filter(AlertCaseLinkModel.tenant_id == tenant, AlertCaseLinkModel.alert_id == alert.id)
            .order_by(AlertCaseLinkModel.linked_at.desc())
            .all()
        ]
        case_owner_rows: List[tuple[str, Optional[str]]] = []
        owner_map: Dict[str, Dict[str, Any]] = {}
        if linked_case_ids:
            case_owner_rows = (
                db.query(SecurityCaseModel.id, SecurityCaseModel.owner_user_id)
                .filter(SecurityCaseModel.tenant_id == tenant, SecurityCaseModel.id.in_(linked_case_ids))
                .all()
            )
            owner_ids = [str(owner or "").strip() for _, owner in case_owner_rows if str(owner or "").strip()]
            owner_map = build_user_summary_map(db=db, user_ids=owner_ids, include_unknown=False)
        linked_case_owner_user_ids = [
            str(owner_user_id or "").strip()
            for _case_id, owner_user_id in case_owner_rows
            if str(owner_user_id or "").strip()
        ]
        dedup_owner_ids: List[str] = []
        for owner_id in linked_case_owner_user_ids:
            if owner_id in dedup_owner_ids:
                continue
            dedup_owner_ids.append(owner_id)
        primary_owner = dedup_owner_ids[0] if dedup_owner_ids else None

        payload: Dict[str, Any] = AlertSchema.model_validate(alert).model_dump(mode="json")
        analysis_id = self._extract_analysis_id(alert.id)
        payload.update(
            {
                "analysis_id": analysis_id,
                "analysis_type": None,
                "explainability": None,
                "analysis_context": None,
                "defender_actions": [],
                "linked_case_ids": linked_case_ids,
                "owner_user_id": primary_owner,
                "owner": owner_map.get(primary_owner) if primary_owner else None,
                "linked_case_owner_user_ids": dedup_owner_ids,
                "linked_case_owners": [owner_map.get(owner_id) for owner_id in dedup_owner_ids if owner_map.get(owner_id)],
            }
        )

        if not analysis_id:
            payload["defender_actions"] = self._severity_to_action(alert.severity, domain="unknown")
            return payload

        try:
            if analysis_id.startswith("sql-"):
                sql_log = (
                    db.query(SQLAnalysisLogModel)
                    .filter(SQLAnalysisLogModel.tenant_id == tenant, SQLAnalysisLogModel.id == analysis_id)
                    .first()
                )
                if sql_log:
                    xai = self._build_sql_explainability(alert, sql_log)
                    xai = self._attach_ai_reliability(xai, domain="sql")
                    payload["analysis_type"] = "sql"
                    payload["explainability"] = xai
                    payload["analysis_context"] = {
                        "query_received": sql_log.query_received,
                        "combined_assessment": sql_log.combined_assessment,
                        "anomaly_detection_result": sql_log.anomaly_detection_result,
                        "query_validation_result": sql_log.query_validation_result,
                    }
                    payload["defender_actions"] = self._severity_to_action(
                        alert.severity, domain="sql", decision_hint=xai.get("decision")
                    )
                    return payload

            if analysis_id.startswith("file-"):
                file_log = (
                    db.query(FileAnalysisLogModel)
                    .filter(FileAnalysisLogModel.tenant_id == tenant, FileAnalysisLogModel.id == analysis_id)
                    .first()
                )
                if file_log:
                    xai = self._build_file_explainability(alert, file_log)
                    xai = self._attach_ai_reliability(xai, domain="file")
                    payload["analysis_type"] = "file"
                    payload["explainability"] = xai
                    payload["analysis_context"] = {
                        "filename": file_log.filename,
                        "filesize_kb": file_log.filesize_kb,
                        "file_details": file_log.file_details,
                        "overall_assessment": file_log.overall_assessment,
                    }
                    payload["defender_actions"] = self._severity_to_action(
                        alert.severity, domain="file", decision_hint=xai.get("decision")
                    )
                    return payload

            if analysis_id.startswith("email-spam-"):
                spam_log = (
                    db.query(SpamAnalysisLogModel)
                    .filter(SpamAnalysisLogModel.tenant_id == tenant, SpamAnalysisLogModel.id == analysis_id)
                    .first()
                )
                if spam_log:
                    xai = self._build_spam_explainability(alert, spam_log)
                    xai = self._attach_ai_reliability(xai, domain="spam")
                    payload["analysis_type"] = "spam"
                    payload["explainability"] = xai
                    payload["analysis_context"] = {
                        "received_subject": spam_log.received_subject,
                        "spam_classification_result": spam_log.spam_classification_result,
                    }
                    payload["defender_actions"] = self._severity_to_action(
                        alert.severity, domain="spam", decision_hint=xai.get("decision")
                    )
                    return payload
        except Exception as e:
            logger.error(f"Failed to enrich alert detail for {alert_id}: {e}", exc_info=True)

        payload["defender_actions"] = self._severity_to_action(alert.severity, domain="unknown")
        return payload

    def acknowledge_alert(
        self,
        db: Session,
        alert_id: str,
        acknowledge_status: bool,
        tenant_id: Optional[str] = None,
    ) -> Optional[AlertModel]:
        db_alert = self.get_alert_by_id(db, alert_id, tenant_id=tenant_id)
        if db_alert:
            db_alert.acknowledged = acknowledge_status
            db.commit()
            db.refresh(db_alert)
            logger.info(f"Alert {alert_id} acknowledged status set to {acknowledge_status}.")
        return db_alert
