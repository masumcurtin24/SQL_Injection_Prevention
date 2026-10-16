# File: backend/services/dashboard_service.py

from __future__ import annotations

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone, date, time
import json

from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, not_, cast, Integer, Float

from backend.core.models import (
    DEFAULT_TENANT_ID,
    SQLAnalysisLog as SQLAnalysisLogModel,
    SpamAnalysisLog as SpamAnalysisLogModel,
    FileAnalysisLog as FileAnalysisLogModel,
    Alert as AlertModel,
    AuthSession as AuthSessionModel,
    User as UserModel,
    DefenderFeedback as DefenderFeedbackModel,
    DefenderModelRegistry as DefenderModelRegistryModel,
    DefenderTrainingJob as DefenderTrainingJobModel,
)
from backend.server.schemas.responses import (
    DashboardSummaryResponse,
    DashboardStatCard,
    DashboardOverallStats,
    ThreatTrendResponse,
    ThreatTrendDataPoint,
    ThreatsByCategoryResponse,
    ThreatByCategory,
    AlertSeverityDistributionResponse,
    AlertSeverityDistribution,
    DashboardStatsDailyPoint,
    DashboardStatsHistoryResponse,
)
from backend.utils.telemetry import telemetry


class DashboardService:
    _instance: Optional["DashboardService"] = None
    _initialized_flag: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(DashboardService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if DashboardService._initialized_flag:
            return
        DashboardService._initialized_flag = True

    @classmethod
    def get_instance(cls) -> "DashboardService":
        if not cls._initialized_flag or cls._instance is None:
            raise RuntimeError("DashboardService has not been initialized. Call the constructor once at startup.")
        return cls._instance

    @staticmethod
    def _is_sqlite(db: Session) -> bool:
        try:
            bind = db.get_bind()
            return bool(bind and bind.dialect and bind.dialect.name == "sqlite")
        except Exception:
            return False

    @staticmethod
    def _safe_json_dict(raw: Optional[str]) -> Dict[str, Any]:
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _clamp01(value: float) -> float:
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return value

    @classmethod
    def _decision_confidence_from_risk(cls, risk_score: Any, decision: str) -> Optional[float]:
        try:
            risk = cls._clamp01(float(risk_score))
        except Exception:
            return None
        action = str(decision or "").strip().upper().replace("-", "_")
        safe_decision = action.startswith("ALLOW") or action in {"SAFE", "CLEAN", "HAM", "NOT_SPAM", "MONITOR"}
        return round((1.0 - risk) if safe_decision else risk, 4)

    @classmethod
    def _explainability_summary(
        cls,
        *,
        domain: str,
        risk_score: Any,
        decision: str,
        recommended_handling: Optional[str] = None,
        review_required: Optional[bool] = None,
    ) -> Dict[str, Any]:
        confidence = cls._decision_confidence_from_risk(risk_score, decision)
        return {
            "domain": domain,
            "risk_score": float(risk_score) if isinstance(risk_score, (int, float)) else None,
            "decision_confidence": confidence,
            "recommended_handling": recommended_handling or cls._handling_from_decision(decision),
            "review_required": bool(review_required) if review_required is not None else False,
            "score_meaning": (
                "risk_score is threat risk; decision_confidence is confidence in the selected action; "
                "AI Reliability, when present, is review-governance rather than severity."
            ),
        }

    @staticmethod
    def _handling_from_decision(decision: str) -> str:
        action = str(decision or "").strip().lower().replace("-", "_")
        if any(token in action for token in ("block", "deny", "quarantine")):
            return "block" if "block" in action or "deny" in action else "quarantine"
        if any(token in action for token in ("review", "flag", "warn")):
            return "review"
        if "monitor" in action:
            return "monitor"
        return "allow"

    @classmethod
    def _resolve_sql_risk_score(
        cls,
        risk_level: Optional[str],
        combined_json: Optional[str],
    ) -> Optional[float]:
        combined = cls._safe_json_dict(combined_json)
        calibrated = combined.get("calibrated_risk_score")
        if isinstance(calibrated, (int, float)):
            return cls._clamp01(float(calibrated))

        risk = str(risk_level or combined.get("overall_risk_level") or "").strip().lower()
        if risk == "critical":
            return 0.95
        if risk == "high":
            return 0.82
        if risk == "medium":
            return 0.55
        if risk == "low":
            return 0.10
        if risk:
            return 0.50
        return None

    @staticmethod
    def _sanitize_pagination(page: int, page_size: int, max_page_size: int = 2000) -> tuple[int, int, int]:
        normalized_page = 1 if page < 1 else page
        normalized_size = 1 if page_size < 1 else page_size
        if normalized_size > max_page_size:
            normalized_size = max_page_size
        offset = (normalized_page - 1) * normalized_size
        return normalized_page, normalized_size, offset

    @staticmethod
    def _normalize_category(category: Optional[str]) -> Optional[str]:
        value = str(category or "").strip().lower()
        if value in {"safe", "suspicious", "blocked"}:
            return value
        return None

    @staticmethod
    def _to_utc(value: Optional[datetime]) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _resolve_tenant_id(tenant_id: Optional[str]) -> str:
        value = str(tenant_id or "").strip()
        return value or DEFAULT_TENANT_ID

    @classmethod
    def _apply_tenant_scope(cls, query, model, tenant_id: Optional[str]):
        tenant = cls._resolve_tenant_id(tenant_id)
        if hasattr(model, "tenant_id"):
            query = query.filter(getattr(model, "tenant_id") == tenant)
        return query

    @staticmethod
    def _status_rank(status: str) -> int:
        normalized = str(status or "").strip().lower()
        if normalized == "critical":
            return 3
        if normalized == "degraded":
            return 2
        if normalized == "healthy":
            return 1
        return 0

    @staticmethod
    def _rank_status(rank: int) -> str:
        if rank >= 3:
            return "critical"
        if rank == 2:
            return "degraded"
        if rank == 1:
            return "healthy"
        return "unknown"

    @staticmethod
    def _is_false_positive_feedback(domain: str, predicted_label: str, true_label: str) -> bool:
        d = str(domain or "").strip().lower()
        pred = str(predicted_label or "").strip().lower()
        true = str(true_label or "").strip().lower()
        if not pred or not true:
            return False

        if d == "sql":
            predicted_positive = any(token in pred for token in ["mal", "susp", "high", "critical"])
            true_positive = true.startswith("mal")
        elif d == "spam":
            predicted_positive = any(token in pred for token in ["spam", "phish", "junk"])
            true_positive = true == "spam"
        elif d == "file":
            predicted_positive = not any(token in pred for token in ["safe", "benign", "allow"])
            true_positive = not any(token in true for token in ["safe", "benign"])
        else:
            return False
        return bool(predicted_positive and not true_positive)

    def _false_positive_summary(
        self,
        db: Session,
        *,
        days: int = 30,
        analyst_only: bool = True,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        horizon = max(1, min(int(days or 30), 365))
        start_day = datetime.now(timezone.utc).date() - timedelta(days=horizon - 1)
        start_dt = datetime(start_day.year, start_day.month, start_day.day, tzinfo=timezone.utc)
        tenant = self._resolve_tenant_id(tenant_id)

        q = db.query(
            DefenderFeedbackModel.domain,
            DefenderFeedbackModel.predicted_label,
            DefenderFeedbackModel.true_label,
            DefenderFeedbackModel.source,
        ).filter(DefenderFeedbackModel.tenant_id == tenant, DefenderFeedbackModel.timestamp >= start_dt)
        if analyst_only:
            q = q.filter(DefenderFeedbackModel.source == "human")

        by_domain: Dict[str, Dict[str, Any]] = {
            "sql": {"labeled": 0, "false_positives": 0, "false_positive_rate": 0.0},
            "spam": {"labeled": 0, "false_positives": 0, "false_positive_rate": 0.0},
            "file": {"labeled": 0, "false_positives": 0, "false_positive_rate": 0.0},
        }

        labeled_total = 0
        false_positives_total = 0
        for domain, predicted_label, true_label, _source in q.all():
            key = str(domain or "").strip().lower()
            if key not in by_domain:
                continue
            by_domain[key]["labeled"] = int(by_domain[key]["labeled"]) + 1
            labeled_total += 1
            if self._is_false_positive_feedback(key, str(predicted_label or ""), str(true_label or "")):
                by_domain[key]["false_positives"] = int(by_domain[key]["false_positives"]) + 1
                false_positives_total += 1

        for key, vals in by_domain.items():
            labeled = int(vals.get("labeled") or 0)
            fp = int(vals.get("false_positives") or 0)
            by_domain[key]["false_positive_rate"] = (float(fp) / float(labeled)) if labeled else 0.0

        global_rate = (float(false_positives_total) / float(labeled_total)) if labeled_total else 0.0
        return {
            "fp_days": horizon,
            "analyst_only": bool(analyst_only),
            "labeled_total": int(labeled_total),
            "false_positives_total": int(false_positives_total),
            "global_false_positive_rate": float(global_rate),
            "by_domain": by_domain,
        }

    @classmethod
    def _apply_time_window(cls, query, model, start: Optional[datetime], end: Optional[datetime]):
        start_utc = cls._to_utc(start)
        end_utc = cls._to_utc(end)
        if start_utc is not None:
            query = query.filter(model.timestamp >= start_utc)
        if end_utc is not None:
            query = query.filter(model.timestamp < end_utc)
        return query

    def _sql_malicious_condition(self, db: Session):
        structured = SQLAnalysisLogModel.is_malicious.is_(True)
        if self._is_sqlite(db):
            risk = func.lower(
                func.coalesce(
                    func.json_extract(SQLAnalysisLogModel._combined_assessment_json, "$.overall_risk_level"),  # type: ignore[attr-defined]
                    "",
                )
            )
            return or_(structured, risk.in_(["high", "critical"]))

        combined_lc = func.lower(func.coalesce(SQLAnalysisLogModel._combined_assessment_json, ""))  # type: ignore[attr-defined]
        legacy = or_(
            combined_lc.like('%"overall_risk_level"%high%'),
            combined_lc.like('%"overall_risk_level"%critical%'),
        )
        return or_(structured, legacy)

    def _sql_category_condition(self, db: Session, category: Optional[str]):
        cat = self._normalize_category(category)
        if not cat:
            return None
        structured = SQLAnalysisLogModel.category == cat

        if self._is_sqlite(db):
            risk = func.lower(
                func.coalesce(
                    func.json_extract(SQLAnalysisLogModel._combined_assessment_json, "$.overall_risk_level"),  # type: ignore[attr-defined]
                    "",
                )
            )
            action = func.upper(
                func.coalesce(
                    func.json_extract(SQLAnalysisLogModel._combined_assessment_json, "$.suggested_action"),  # type: ignore[attr-defined]
                    "",
                )
            )
            label = func.lower(
                func.coalesce(
                    func.json_extract(SQLAnalysisLogModel._query_validation_result_json, "$.classification_label"),  # type: ignore[attr-defined]
                    "",
                )
            )
            is_anomalous = cast(
                func.coalesce(
                    func.json_extract(SQLAnalysisLogModel._anomaly_detection_result_json, "$.is_anomalous"),  # type: ignore[attr-defined]
                    0,
                ),
                Integer,
            )
            blocked = or_(risk.in_(["high", "critical"]), action.like("%BLOCK%"))
            suspicious_signal = or_(
                risk == "medium",
                is_anomalous == 1,
                action.like("%WARN%"),
                action.like("%FLAG%"),
                label.like("%suspicious%"),
                label.like("%malicious%"),
            )
        else:
            combined_lc = func.lower(func.coalesce(SQLAnalysisLogModel._combined_assessment_json, ""))  # type: ignore[attr-defined]
            anomaly_lc = func.lower(func.coalesce(SQLAnalysisLogModel._anomaly_detection_result_json, ""))  # type: ignore[attr-defined]
            validation_lc = func.lower(func.coalesce(SQLAnalysisLogModel._query_validation_result_json, ""))  # type: ignore[attr-defined]
            blocked = or_(
                combined_lc.like('%"overall_risk_level"%high%'),
                combined_lc.like('%"overall_risk_level"%critical%'),
                combined_lc.like('%"suggested_action"%block%'),
            )
            suspicious_signal = or_(
                combined_lc.like('%"overall_risk_level"%medium%'),
                anomaly_lc.like('%"is_anomalous"%true%'),
                combined_lc.like('%"suggested_action"%warn%'),
                combined_lc.like('%"suggested_action"%flag%'),
                validation_lc.like('%"classification_label"%suspicious%'),
                validation_lc.like('%"classification_label"%malicious%'),
            )

        if cat == "blocked":
            legacy_condition = blocked
            return or_(structured, legacy_condition)
        if cat == "suspicious":
            legacy_condition = and_(not_(blocked), suspicious_signal)
            return or_(structured, legacy_condition)
        legacy_condition = and_(not_(blocked), not_(suspicious_signal))
        return or_(structured, legacy_condition)

    def _spam_detected_condition(self, db: Session):
        structured = SpamAnalysisLogModel.is_spam.is_(True)
        if self._is_sqlite(db):
            is_spam = cast(
                func.coalesce(
                    func.json_extract(SpamAnalysisLogModel._spam_classification_result_json, "$.is_spam"),  # type: ignore[attr-defined]
                    0,
                ),
                Integer,
            )
            return or_(structured, is_spam == 1)

        spam_lc = func.lower(func.coalesce(SpamAnalysisLogModel._spam_classification_result_json, ""))  # type: ignore[attr-defined]
        return or_(structured, spam_lc.like('%"is_spam"%true%'))

    def _spam_category_condition(self, db: Session, category: Optional[str]):
        cat = self._normalize_category(category)
        if not cat:
            return None
        structured = SpamAnalysisLogModel.category == cat

        if self._is_sqlite(db):
            is_spam = cast(
                func.coalesce(
                    func.json_extract(SpamAnalysisLogModel._spam_classification_result_json, "$.is_spam"),  # type: ignore[attr-defined]
                    0,
                ),
                Integer,
            )
            score = cast(
                func.coalesce(
                    func.json_extract(SpamAnalysisLogModel._spam_classification_result_json, "$.spam_score"),  # type: ignore[attr-defined]
                    0.0,
                ),
                Float,
            )
            label = func.lower(
                func.coalesce(
                    func.json_extract(SpamAnalysisLogModel._spam_classification_result_json, "$.classification_label"),  # type: ignore[attr-defined]
                    "",
                )
            )
            blocked = or_(
                and_(is_spam == 1, score >= 0.85),
                label.like("%phish%"),
            )
            suspicious_signal = or_(
                is_spam == 1,
                score >= 0.55,
                label.like("%suspicious%"),
                label.like("%ood%"),
            )
        else:
            spam_lc = func.lower(func.coalesce(SpamAnalysisLogModel._spam_classification_result_json, ""))  # type: ignore[attr-defined]
            blocked = or_(
                spam_lc.like('%"classification_label"%phish%'),
                spam_lc.like('%"spam_score"%0.8%'),
                spam_lc.like('%"spam_score"%0.9%'),
            )
            suspicious_signal = or_(
                spam_lc.like('%"is_spam"%true%'),
                spam_lc.like('%"classification_label"%suspicious%'),
                spam_lc.like('%"classification_label"%ood%'),
            )

        if cat == "blocked":
            legacy_condition = blocked
            return or_(structured, legacy_condition)
        if cat == "suspicious":
            legacy_condition = and_(not_(blocked), suspicious_signal)
            return or_(structured, legacy_condition)
        legacy_condition = and_(not_(blocked), not_(suspicious_signal))
        return or_(structured, legacy_condition)

    def _file_category_condition(self, db: Session, category: Optional[str]):
        cat = self._normalize_category(category)
        if not cat:
            return None
        structured = FileAnalysisLogModel.category == cat

        if self._is_sqlite(db):
            status = func.lower(
                func.coalesce(
                    func.json_extract(FileAnalysisLogModel._overall_assessment_json, "$.overall_status"),  # type: ignore[attr-defined]
                    "",
                )
            )
            action = func.upper(
                func.coalesce(
                    func.json_extract(FileAnalysisLogModel._overall_assessment_json, "$.recommended_action"),  # type: ignore[attr-defined]
                    "",
                )
            )
            risk = cast(
                func.coalesce(
                    func.json_extract(FileAnalysisLogModel._overall_assessment_json, "$.risk_score"),  # type: ignore[attr-defined]
                    0.0,
                ),
                Float,
            )
            yara_malicious = cast(
                func.coalesce(
                    func.json_extract(FileAnalysisLogModel._file_details_json, "$.malware_scan.is_malicious"),  # type: ignore[attr-defined]
                    0,
                ),
                Integer,
            )
            ml_suspicious = cast(
                func.coalesce(
                    func.json_extract(FileAnalysisLogModel._file_details_json, "$.ml_scan.is_suspicious_ml"),  # type: ignore[attr-defined]
                    0,
                ),
                Integer,
            )
            blocked = or_(
                action.like("%BLOCK%"),
                action.like("%QUARANTINE%"),
                status.like("%malicious%"),
                status.like("%blocked%"),
            )
            suspicious_signal = or_(
                status.like("%suspicious%"),
                action.like("%FLAG%"),
                action.like("%WARN%"),
                action.like("%REVIEW%"),
                yara_malicious == 1,
                ml_suspicious == 1,
                risk >= 0.5,
            )
        else:
            overall_lc = func.lower(func.coalesce(FileAnalysisLogModel._overall_assessment_json, ""))  # type: ignore[attr-defined]
            details_lc = func.lower(func.coalesce(FileAnalysisLogModel._file_details_json, ""))  # type: ignore[attr-defined]
            blocked = or_(
                overall_lc.like('%"recommended_action"%block%'),
                overall_lc.like('%"recommended_action"%quarantine%'),
                overall_lc.like('%"overall_status"%malicious%'),
                overall_lc.like('%"overall_status"%blocked%'),
            )
            suspicious_signal = or_(
                overall_lc.like('%"overall_status"%suspicious%'),
                overall_lc.like('%"recommended_action"%flag%'),
                overall_lc.like('%"recommended_action"%warn%'),
                overall_lc.like('%"recommended_action"%review%'),
                details_lc.like('%"is_malicious"%true%'),
                details_lc.like('%"is_suspicious_ml"%true%'),
            )

        if cat == "blocked":
            legacy_condition = blocked
            return or_(structured, legacy_condition)
        if cat == "suspicious":
            legacy_condition = and_(not_(blocked), suspicious_signal)
            return or_(structured, legacy_condition)
        legacy_condition = and_(not_(blocked), not_(suspicious_signal))
        return or_(structured, legacy_condition)

    # --- Simple stats used by /dashboard/stats (legacy frontend) ---
    def get_dashboard_statistics(
        self,
        db: Session,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            sql_q = db.query(SQLAnalysisLogModel.id)
            sql_q = self._apply_tenant_scope(sql_q, SQLAnalysisLogModel, tenant_id)
            if start is not None:
                sql_q = sql_q.filter(SQLAnalysisLogModel.timestamp >= start)
            if end is not None:
                sql_q = sql_q.filter(SQLAnalysisLogModel.timestamp < end)
            total_queries = int(sql_q.with_entities(func.count(SQLAnalysisLogModel.id)).scalar() or 0)
            malicious_queries = int(
                sql_q.filter(self._sql_malicious_condition(db))
                .with_entities(func.count(SQLAnalysisLogModel.id))
                .scalar()
                or 0
            )

            sql_score_q = db.query(
                SQLAnalysisLogModel.risk_level,
                SQLAnalysisLogModel._combined_assessment_json,  # type: ignore[attr-defined]
            )
            sql_score_q = self._apply_tenant_scope(sql_score_q, SQLAnalysisLogModel, tenant_id)
            if start is not None:
                sql_score_q = sql_score_q.filter(SQLAnalysisLogModel.timestamp >= start)
            if end is not None:
                sql_score_q = sql_score_q.filter(SQLAnalysisLogModel.timestamp < end)

            risk_scores: List[float] = []
            for risk_level_col, combined_json_col in sql_score_q.all():
                resolved = self._resolve_sql_risk_score(risk_level_col, combined_json_col)
                if isinstance(resolved, (int, float)):
                    risk_scores.append(self._clamp01(float(resolved)))

            sample_size = len(risk_scores)
            avg_risk = (sum(risk_scores) / sample_size) if sample_size else 0.0
            high_threshold = 0.75
            high_risk_count = len([score for score in risk_scores if score >= high_threshold])
            high_risk_rate = ((high_risk_count / sample_size) * 100.0) if sample_size else 0.0
            risk_posture_score = (1.0 - avg_risk) * 100.0 if sample_size else 0.0
            if risk_posture_score < 0.0:
                risk_posture_score = 0.0
            if risk_posture_score > 100.0:
                risk_posture_score = 100.0

            file_q = db.query(FileAnalysisLogModel.id)
            file_q = self._apply_tenant_scope(file_q, FileAnalysisLogModel, tenant_id)
            if start is not None:
                file_q = file_q.filter(FileAnalysisLogModel.timestamp >= start)
            if end is not None:
                file_q = file_q.filter(FileAnalysisLogModel.timestamp < end)
            files_scanned = int(file_q.with_entities(func.count(FileAnalysisLogModel.id)).scalar() or 0)

            spam_q = db.query(SpamAnalysisLogModel.id)
            spam_q = self._apply_tenant_scope(spam_q, SpamAnalysisLogModel, tenant_id)
            if start is not None:
                spam_q = spam_q.filter(SpamAnalysisLogModel.timestamp >= start)
            if end is not None:
                spam_q = spam_q.filter(SpamAnalysisLogModel.timestamp < end)
            spam_detected = int(
                spam_q.filter(self._spam_detected_condition(db))
                .with_entities(func.count(SpamAnalysisLogModel.id))
                .scalar()
                or 0
            )

            return {
                "total_queries": total_queries,
                "malicious_queries": malicious_queries,
                "files_scanned": files_scanned,
                "spam_detected": spam_detected,
                "sql_risk_posture_score": round(risk_posture_score, 1),
                "sql_precision_score": round(risk_posture_score, 1),  # Deprecated compatibility alias; not statistical precision.
                "sql_avg_calibrated_risk": round(avg_risk, 4),
                "sql_high_risk_rate": round(high_risk_rate, 2),
                "sql_precision_sample_size": sample_size,
            }
        except Exception:
            return {
                "total_queries": 0,
                "malicious_queries": 0,
                "files_scanned": 0,
                "spam_detected": 0,
                "sql_risk_posture_score": 0.0,
                "sql_precision_score": 0.0,
                "sql_avg_calibrated_risk": 0.0,
                "sql_high_risk_rate": 0.0,
                "sql_precision_sample_size": 0,
            }

    def get_executive_overview(
        self,
        db: Session,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now_utc = datetime.now(timezone.utc)
        start_utc = self._to_utc(start)
        end_utc = self._to_utc(end)

        base_payload: Dict[str, Any] = {
            "as_of": now_utc.isoformat(),
            "window_start": start_utc.isoformat() if start_utc else None,
            "window_end": end_utc.isoformat() if end_utc else None,
            "security_posture": "stable",
            "posture_score": 100,
            "totals": {
                "events": 0,
                "analysis_events": 0,
                "safe": 0,
                "suspicious": 0,
                "blocked": 0,
                "alerts": 0,
                "critical_alerts": 0,
            },
            "rates": {
                "detection_rate": 0.0,
                "block_rate": 0.0,
                "alert_rate_per_100_events": 0.0,
            },
            "latency": {
                "latest_event_at": None,
                "ingestion_lag_seconds": None,
            },
            "domains": {
                "sql": {"total": 0, "safe": 0, "suspicious": 0, "blocked": 0},
                "file": {"total": 0, "safe": 0, "suspicious": 0, "blocked": 0},
                "spam": {"total": 0, "safe": 0, "suspicious": 0, "blocked": 0},
            },
            "alerts_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0},
            "top_risks": [],
        }

        def _count(model, condition=None) -> int:
            q = db.query(model.id)
            q = self._apply_tenant_scope(q, model, tenant_id)
            q = self._apply_time_window(q, model, start_utc, end_utc)
            if condition is not None:
                q = q.filter(condition)
            return int(q.with_entities(func.count(model.id)).scalar() or 0)

        def _max_timestamp(model) -> Optional[datetime]:
            q = db.query(func.max(model.timestamp))
            q = self._apply_tenant_scope(q, model, tenant_id)
            q = self._apply_time_window(q, model, start_utc, end_utc)
            raw = q.scalar()
            if raw is None:
                return None
            return self._to_utc(raw)

        try:
            sql_total = _count(SQLAnalysisLogModel)
            sql_safe = _count(SQLAnalysisLogModel, self._sql_category_condition(db, "safe"))
            sql_suspicious = _count(SQLAnalysisLogModel, self._sql_category_condition(db, "suspicious"))
            sql_blocked = _count(SQLAnalysisLogModel, self._sql_category_condition(db, "blocked"))

            file_total = _count(FileAnalysisLogModel)
            file_safe = _count(FileAnalysisLogModel, self._file_category_condition(db, "safe"))
            file_suspicious = _count(FileAnalysisLogModel, self._file_category_condition(db, "suspicious"))
            file_blocked = _count(FileAnalysisLogModel, self._file_category_condition(db, "blocked"))

            spam_total = _count(SpamAnalysisLogModel)
            spam_safe = _count(SpamAnalysisLogModel, self._spam_category_condition(db, "safe"))
            spam_suspicious = _count(SpamAnalysisLogModel, self._spam_category_condition(db, "suspicious"))
            spam_blocked = _count(SpamAnalysisLogModel, self._spam_category_condition(db, "blocked"))

            alerts_q = db.query(AlertModel.severity, func.count(AlertModel.id))
            alerts_q = self._apply_tenant_scope(alerts_q, AlertModel, tenant_id)
            alerts_q = self._apply_time_window(alerts_q, AlertModel, start_utc, end_utc)
            alert_rows = alerts_q.group_by(AlertModel.severity).all()
            alert_counts: Dict[str, int] = {}
            for sev, count in alert_rows:
                key = str(sev or "").strip().lower()
                if key:
                    alert_counts[key] = alert_counts.get(key, 0) + int(count or 0)
                else:
                    alert_counts["other"] = alert_counts.get("other", 0) + int(count or 0)

            alert_critical = int(alert_counts.get("critical", 0))
            alert_high = int(alert_counts.get("high", 0))
            alert_medium = int(alert_counts.get("medium", 0))
            alert_low = int(alert_counts.get("low", 0))
            alert_other = int(
                sum(
                    count
                    for sev, count in alert_counts.items()
                    if sev not in {"critical", "high", "medium", "low"}
                )
            )
            alerts_total = alert_critical + alert_high + alert_medium + alert_low + alert_other

            analysis_events = sql_total + file_total + spam_total
            safe_total = sql_safe + file_safe + spam_safe
            suspicious_total = sql_suspicious + file_suspicious + spam_suspicious
            blocked_total = sql_blocked + file_blocked + spam_blocked
            total_events = analysis_events + alerts_total

            detection_rate = ((suspicious_total + blocked_total) / analysis_events) if analysis_events else 0.0
            block_rate = (blocked_total / analysis_events) if analysis_events else 0.0
            alert_rate_per_100 = ((alerts_total / total_events) * 100.0) if total_events else 0.0

            latest_candidates = [
                _max_timestamp(SQLAnalysisLogModel),
                _max_timestamp(FileAnalysisLogModel),
                _max_timestamp(SpamAnalysisLogModel),
                _max_timestamp(AlertModel),
            ]
            latest_event = max((candidate for candidate in latest_candidates if candidate is not None), default=None)
            lag_seconds = None
            if latest_event is not None:
                lag_seconds = int(max(0.0, (now_utc - latest_event).total_seconds()))

            score = 100.0
            score -= block_rate * 70.0
            score -= detection_rate * 30.0
            score -= min(alert_critical, 10) * 2.0
            score -= min(alert_high, 10) * 1.0
            posture_score = int(max(0.0, min(100.0, round(score))))

            if posture_score < 60 or block_rate >= 0.20 or alert_critical > 0:
                posture = "critical"
            elif posture_score < 80 or detection_rate >= 0.25:
                posture = "watch"
            else:
                posture = "stable"

            risk_candidates = [
                {"label": "Blocked SQL analyses", "count": sql_blocked},
                {"label": "Blocked file scans", "count": file_blocked},
                {"label": "Blocked spam detections", "count": spam_blocked},
                {"label": "Critical alerts", "count": alert_critical},
                {"label": "High alerts", "count": alert_high},
                {"label": "Suspicious SQL analyses", "count": sql_suspicious},
                {"label": "Suspicious file scans", "count": file_suspicious},
                {"label": "Suspicious spam detections", "count": spam_suspicious},
            ]
            top_risks = sorted(
                [candidate for candidate in risk_candidates if int(candidate.get("count") or 0) > 0],
                key=lambda item: int(item.get("count") or 0),
                reverse=True,
            )[:5]

            return {
                "as_of": now_utc.isoformat(),
                "window_start": start_utc.isoformat() if start_utc else None,
                "window_end": end_utc.isoformat() if end_utc else None,
                "security_posture": posture,
                "posture_score": posture_score,
                "totals": {
                    "events": total_events,
                    "analysis_events": analysis_events,
                    "safe": safe_total,
                    "suspicious": suspicious_total,
                    "blocked": blocked_total,
                    "alerts": alerts_total,
                    "critical_alerts": alert_critical,
                },
                "rates": {
                    "detection_rate": round(detection_rate, 4),
                    "block_rate": round(block_rate, 4),
                    "alert_rate_per_100_events": round(alert_rate_per_100, 2),
                },
                "latency": {
                    "latest_event_at": latest_event.isoformat() if latest_event else None,
                    "ingestion_lag_seconds": lag_seconds,
                },
                "domains": {
                    "sql": {"total": sql_total, "safe": sql_safe, "suspicious": sql_suspicious, "blocked": sql_blocked},
                    "file": {"total": file_total, "safe": file_safe, "suspicious": file_suspicious, "blocked": file_blocked},
                    "spam": {"total": spam_total, "safe": spam_safe, "suspicious": spam_suspicious, "blocked": spam_blocked},
                },
                "alerts_by_severity": {
                    "critical": alert_critical,
                    "high": alert_high,
                    "medium": alert_medium,
                    "low": alert_low,
                    "other": alert_other,
                },
                "top_risks": top_risks,
            }
        except Exception:
            return base_payload

    def get_platform_health(
        self,
        db: Session,
        *,
        queue_stats: Optional[Dict[str, Any]] = None,
        top_endpoints: int = 20,
        fp_days: int = 30,
        analyst_only: bool = True,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant = self._resolve_tenant_id(tenant_id)
        now_utc = datetime.now(timezone.utc)
        issues: List[str] = []
        warnings: List[str] = []

        top_n = max(1, min(int(top_endpoints or 20), 200))
        fp_horizon = max(1, min(int(fp_days or 30), 365))

        # HTTP + websocket telemetry.
        telemetry_overview = telemetry.snapshot_overview(top=top_n) or {}
        http_totals = dict(telemetry_overview.get("http_totals") or {})
        ws_snapshot = dict(telemetry_overview.get("websocket") or telemetry.snapshot_ws() or {})
        http_endpoints = list(telemetry_overview.get("http_top_endpoints") or [])

        http_requests_total = int(http_totals.get("requests_total") or 0)
        http_errors_total = int(http_totals.get("errors_total") or 0)
        http_error_rate = float(http_totals.get("error_rate") or 0.0)
        http_avg_latency_ms = float(http_totals.get("avg_latency_ms") or 0.0)

        top_error_endpoints = sorted(
            http_endpoints,
            key=lambda row: (
                float(row.get("error_rate") or 0.0),
                int(row.get("errors_total") or 0),
            ),
            reverse=True,
        )[:5]
        top_slow_endpoints = sorted(
            http_endpoints,
            key=lambda row: float(row.get("latency_ms_avg") or 0.0),
            reverse=True,
        )[:5]

        http_status = "healthy"
        if http_error_rate >= 0.05 or http_avg_latency_ms >= 1500.0:
            http_status = "critical"
            issues.append("HTTP telemetry shows critical error/latency levels.")
        elif http_error_rate >= 0.02 or http_avg_latency_ms >= 800.0:
            http_status = "degraded"
            warnings.append("HTTP telemetry shows elevated error rate or latency.")

        ws_active = int(ws_snapshot.get("active_connections") or 0)
        ws_total = int(ws_snapshot.get("connections_total") or 0)
        ws_broadcast_failure_rate = float(ws_snapshot.get("broadcast_failure_rate") or 0.0)
        ws_status = "healthy"
        if ws_broadcast_failure_rate >= 0.05:
            ws_status = "critical"
            issues.append("Websocket broadcast failures are above critical threshold.")
        elif ws_broadcast_failure_rate >= 0.01:
            ws_status = "degraded"
            warnings.append("Websocket broadcast failures are elevated.")
        if ws_total > 0 and ws_active <= 0 and ws_status == "healthy":
            ws_status = "degraded"
            warnings.append("No active websocket clients are connected.")

        # Queue health (passed from router app-state queue service).
        queue_payload = dict(queue_stats or {})
        queue_status = "unknown"
        queue_size = int(queue_payload.get("queue_size") or 0)
        queue_max = int(queue_payload.get("queue_max_size") or 0)
        queue_utilization = (float(queue_size) / float(queue_max)) if queue_max > 0 else 0.0
        queue_status_counts = dict(queue_payload.get("status_counts") or {})
        dead_letter_count = int(queue_status_counts.get("dead_letter") or 0)
        failed_count = int(queue_status_counts.get("failed") or 0)
        queue_running = bool(queue_payload.get("running", False))
        processor_enabled = queue_payload.get("processor_enabled")

        if queue_payload:
            queue_status = "healthy"
            if dead_letter_count > 0:
                queue_status = "critical"
                issues.append(f"File scan queue has dead-letter jobs ({dead_letter_count}).")
            elif queue_utilization >= 0.85 or failed_count > 0:
                queue_status = "degraded"
                warnings.append("File scan queue utilization/failures are elevated.")
            if (not queue_running or processor_enabled is False) and queue_status != "critical":
                queue_status = "degraded"
                warnings.append("File scan processor is not fully active.")
        else:
            warnings.append("File scan queue stats are unavailable.")

        # Model registry and retraining pipeline health.
        models_status = "healthy"
        required_domains = ["sql", "spam", "file"]
        active_by_domain: Dict[str, Dict[str, Any]] = {}
        try:
            active_rows = (
                db.query(DefenderModelRegistryModel)
                .filter(
                    DefenderModelRegistryModel.tenant_id == tenant,
                    DefenderModelRegistryModel.stage == "active",
                )
                .order_by(DefenderModelRegistryModel.timestamp.desc())
                .all()
            )
            for row in active_rows:
                domain = str(row.domain or "").strip().lower()
                if not domain or domain in active_by_domain:
                    continue
                active_by_domain[domain] = {
                    "version": row.version,
                    "model_name": row.model_name,
                    "promoted_at": row.promoted_at.isoformat() if row.promoted_at else None,
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                }
        except Exception:
            active_by_domain = {}
            warnings.append("Unable to load active model registry state.")

        missing_active_domains = [d for d in required_domains if d not in active_by_domain]
        if missing_active_domains:
            models_status = "degraded"
            warnings.append(f"Missing active models for domains: {', '.join(missing_active_domains)}.")

        latest_job: Optional[Dict[str, Any]] = None
        try:
            job_row = (
                db.query(DefenderTrainingJobModel)
                .filter(DefenderTrainingJobModel.tenant_id == tenant)
                .order_by(DefenderTrainingJobModel.timestamp.desc())
                .first()
            )
            if job_row is not None:
                latest_job = {
                    "id": job_row.id,
                    "status": str(job_row.status or "unknown"),
                    "domain": job_row.domain,
                    "timestamp": job_row.timestamp.isoformat() if job_row.timestamp else None,
                    "started_at": job_row.started_at.isoformat() if job_row.started_at else None,
                    "finished_at": job_row.finished_at.isoformat() if job_row.finished_at else None,
                }
                if str(job_row.status or "").strip().lower() in {"failed", "error"} and models_status != "critical":
                    models_status = "degraded"
                    warnings.append("Latest model retraining job ended in a failed state.")
        except Exception:
            warnings.append("Unable to load latest retraining job status.")

        job_status_counts: Dict[str, int] = {}
        try:
            rows = (
                db.query(DefenderTrainingJobModel.status, func.count(DefenderTrainingJobModel.id))
                .filter(DefenderTrainingJobModel.tenant_id == tenant)
                .group_by(DefenderTrainingJobModel.status)
                .all()
            )
            for status, count in rows:
                key = str(status or "unknown").strip().lower() or "unknown"
                job_status_counts[key] = int(count or 0)
        except Exception:
            job_status_counts = {}

        pending_feedback = 0
        try:
            pending_feedback = int(
                db.query(DefenderFeedbackModel)
                .filter(
                    DefenderFeedbackModel.tenant_id == tenant,
                    DefenderFeedbackModel.processed.is_(False),
                )
                .count()
            )
            if pending_feedback >= 500 and models_status == "healthy":
                models_status = "degraded"
                warnings.append("Defender feedback backlog is high.")
        except Exception:
            pending_feedback = 0

        # Data quality (false positive trend) health.
        quality_summary = self._false_positive_summary(
            db=db,
            days=fp_horizon,
            analyst_only=bool(analyst_only),
            tenant_id=tenant,
        )
        fp_rate = float(quality_summary.get("global_false_positive_rate") or 0.0)
        labeled_total = int(quality_summary.get("labeled_total") or 0)
        quality_status = "healthy"
        if fp_rate >= 0.25:
            quality_status = "critical"
            issues.append("False-positive rate is critically high.")
        elif fp_rate >= 0.12:
            quality_status = "degraded"
            warnings.append("False-positive rate is above target.")
        if labeled_total < 30:
            warnings.append("Limited analyst feedback volume for strong quality confidence.")

        # Overall status and score.
        status_rank = max(
            self._status_rank(http_status),
            self._status_rank(ws_status),
            self._status_rank(queue_status),
            self._status_rank(models_status),
            self._status_rank(quality_status),
        )
        if queue_status == "unknown" and status_rank < self._status_rank("degraded"):
            status_rank = self._status_rank("degraded")
        overall_status = self._rank_status(status_rank)

        score = 100.0
        score -= min(http_error_rate * 200.0, 40.0)
        score -= min(max(0.0, (http_avg_latency_ms - 250.0) / 25.0), 25.0)
        score -= min(ws_broadcast_failure_rate * 300.0, 20.0)
        score -= min(queue_utilization * 20.0, 20.0)
        score -= min(float(dead_letter_count) * 10.0, 20.0)
        score -= min(float(len(missing_active_domains)) * 8.0, 24.0)
        score -= min(fp_rate * 100.0, 30.0)
        if queue_status == "unknown":
            score -= 5.0
        if labeled_total < 30:
            score -= 5.0
        if score < 0.0:
            score = 0.0
        if score > 100.0:
            score = 100.0

        return {
            "as_of": now_utc.isoformat(),
            "overall_status": overall_status,
            "score": int(round(score)),
            "issues": issues,
            "warnings": warnings,
            "components": {
                "http": {
                    "status": http_status,
                    "requests_total": http_requests_total,
                    "errors_total": http_errors_total,
                    "error_rate": round(http_error_rate, 6),
                    "avg_latency_ms": round(http_avg_latency_ms, 3),
                    "top_error_endpoints": top_error_endpoints,
                    "top_slow_endpoints": top_slow_endpoints,
                },
                "websocket": {
                    "status": ws_status,
                    "active_connections": ws_active,
                    "connections_total": ws_total,
                    "disconnects_total": int(ws_snapshot.get("disconnects_total") or 0),
                    "auth_failures_total": int(ws_snapshot.get("auth_failures_total") or 0),
                    "messages_broadcast_total": int(ws_snapshot.get("messages_broadcast_total") or 0),
                    "broadcast_send_failures_total": int(ws_snapshot.get("broadcast_send_failures_total") or 0),
                    "broadcast_failure_rate": round(ws_broadcast_failure_rate, 6),
                    "last_event_at": ws_snapshot.get("last_event_at"),
                },
                "queue": {
                    "status": queue_status,
                    "running": queue_running if queue_payload else None,
                    "processor_enabled": processor_enabled if queue_payload else None,
                    "queue_size": queue_size if queue_payload else None,
                    "queue_max_size": queue_max if queue_payload else None,
                    "utilization": round(queue_utilization, 4) if queue_payload else None,
                    "jobs_total": int(queue_payload.get("jobs_total") or 0) if queue_payload else None,
                    "dead_letter": dead_letter_count if queue_payload else None,
                    "failed": failed_count if queue_payload else None,
                    "status_counts": queue_status_counts if queue_payload else None,
                    "backend": queue_payload.get("backend") if queue_payload else None,
                    "redis_url": queue_payload.get("redis_url") if queue_payload else None,
                    "namespace": queue_payload.get("namespace") if queue_payload else None,
                },
                "models": {
                    "status": models_status,
                    "required_domains": required_domains,
                    "active_by_domain": active_by_domain,
                    "missing_active_domains": missing_active_domains,
                    "pending_feedback": pending_feedback,
                    "latest_job": latest_job,
                    "job_status_counts": job_status_counts,
                },
                "quality": {
                    "status": quality_status,
                    **quality_summary,
                },
            },
        }

    def get_access_feed(
        self,
        db: Session,
        *,
        limit: int = 50,
        active_only: bool = False,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant = self._resolve_tenant_id(tenant_id)
        now_utc = datetime.now(timezone.utc)
        safe_limit = max(1, min(int(limit or 50), 500))

        q = (
            db.query(AuthSessionModel, UserModel)
            .join(UserModel, UserModel.id == AuthSessionModel.user_id)
            .filter(AuthSessionModel.tenant_id == tenant, UserModel.tenant_id == tenant)
            .order_by(
                AuthSessionModel.last_used_at.desc(),
                AuthSessionModel.created_at.desc(),
            )
        )
        if active_only:
            q = q.filter(AuthSessionModel.status == "active")

        rows = q.limit(safe_limit).all()

        items: List[Dict[str, Any]] = []
        active_count = 0
        for session, user in rows:
            created_at = self._to_utc(session.created_at)
            last_used_at = self._to_utc(session.last_used_at) or created_at
            revoked_at = self._to_utc(session.revoked_at)
            status = str(session.status or "unknown").strip().lower() or "unknown"
            if status == "active":
                active_count += 1

            end_at = revoked_at or now_utc
            duration_seconds = None
            if created_at is not None:
                duration_seconds = max(int((end_at - created_at).total_seconds()), 0)
            active_seconds = None
            if created_at is not None and last_used_at is not None:
                active_seconds = max(int((last_used_at - created_at).total_seconds()), 0)
            idle_seconds = None
            if last_used_at is not None:
                idle_seconds = max(int((now_utc - last_used_at).total_seconds()), 0)

            items.append(
                {
                    "session_id": session.id,
                    "user_id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role,
                    "status": status,
                    "ip": session.ip,
                    "user_agent": session.user_agent,
                    "started_at": created_at.isoformat() if created_at else None,
                    "last_used_at": last_used_at.isoformat() if last_used_at else None,
                    "ended_at": revoked_at.isoformat() if revoked_at else None,
                    "duration_seconds": duration_seconds,
                    "active_seconds": active_seconds,
                    "idle_seconds": idle_seconds,
                    "revoke_reason": session.revoke_reason,
                }
            )

        return {
            "as_of": now_utc.isoformat(),
            "active_only": bool(active_only),
            "count": len(items),
            "active_sessions": active_count,
            "items": items,
        }

    def get_dashboard_statistics_history(
        self,
        db: Session,
        days: int = 30,
        tenant_id: Optional[str] = None,
    ) -> DashboardStatsHistoryResponse:
        """Return per-day stats for the last N days (inclusive), in UTC."""
        tenant = self._resolve_tenant_id(tenant_id)
        if days < 1:
            days = 1
        if days > 365:
            days = 365

        today = datetime.now(timezone.utc).date()
        start_day = today - timedelta(days=days - 1)
        dates: List[date] = [start_day + timedelta(days=i) for i in range(days)]
        by_day: Dict[str, Dict[str, int]] = {
            str(d): {"total_queries": 0, "malicious_queries": 0, "files_scanned": 0, "spam_detected": 0}
            for d in dates
        }

        start_dt = datetime.combine(start_day, time.min, tzinfo=timezone.utc)
        end_dt = datetime.combine(today + timedelta(days=1), time.min, tzinfo=timezone.utc)

        sql_date_col = func.date(SQLAnalysisLogModel.timestamp)
        spam_date_col = func.date(SpamAnalysisLogModel.timestamp)
        file_date_col = func.date(FileAnalysisLogModel.timestamp)

        # SQL totals by day
        try:
            rows = (
                db.query(sql_date_col.label("d"), func.count(SQLAnalysisLogModel.id))
                .filter(SQLAnalysisLogModel.tenant_id == tenant)
                .filter(SQLAnalysisLogModel.timestamp >= start_dt)
                .filter(SQLAnalysisLogModel.timestamp < end_dt)
                .group_by(sql_date_col)
                .all()
            )
            for day_value, count in rows:
                key = str(day_value)
                bucket = by_day.get(key)
                if bucket is not None:
                    bucket["total_queries"] = int(count or 0)
        except Exception:
            pass

        # SQL malicious by day
        try:
            rows = (
                db.query(sql_date_col.label("d"), func.count(SQLAnalysisLogModel.id))
                .filter(SQLAnalysisLogModel.tenant_id == tenant)
                .filter(SQLAnalysisLogModel.timestamp >= start_dt)
                .filter(SQLAnalysisLogModel.timestamp < end_dt)
                .filter(self._sql_malicious_condition(db))
                .group_by(sql_date_col)
                .all()
            )
            for day_value, count in rows:
                key = str(day_value)
                bucket = by_day.get(key)
                if bucket is not None:
                    bucket["malicious_queries"] = int(count or 0)
        except Exception:
            pass

        # Files scanned by day
        try:
            rows = (
                db.query(file_date_col.label("d"), func.count(FileAnalysisLogModel.id))
                .filter(FileAnalysisLogModel.tenant_id == tenant)
                .filter(FileAnalysisLogModel.timestamp >= start_dt)
                .filter(FileAnalysisLogModel.timestamp < end_dt)
                .group_by(file_date_col)
                .all()
            )
            for day_value, count in rows:
                key = str(day_value)
                bucket = by_day.get(key)
                if bucket is not None:
                    bucket["files_scanned"] = int(count or 0)
        except Exception:
            pass

        # Spam/phishing events flagged by day
        try:
            rows = (
                db.query(spam_date_col.label("d"), func.count(SpamAnalysisLogModel.id))
                .filter(SpamAnalysisLogModel.tenant_id == tenant)
                .filter(SpamAnalysisLogModel.timestamp >= start_dt)
                .filter(SpamAnalysisLogModel.timestamp < end_dt)
                .filter(self._spam_detected_condition(db))
                .group_by(spam_date_col)
                .all()
            )
            for day_value, count in rows:
                key = str(day_value)
                bucket = by_day.get(key)
                if bucket is not None:
                    bucket["spam_detected"] = int(count or 0)
        except Exception:
            pass

        points: List[DashboardStatsDailyPoint] = []
        for d in dates:
            b = by_day.get(str(d)) or {}
            points.append(DashboardStatsDailyPoint(
                date=d,
                total_queries=int(b.get("total_queries", 0) or 0),
                malicious_queries=int(b.get("malicious_queries", 0) or 0),
                files_scanned=int(b.get("files_scanned", 0) or 0),
                spam_detected=int(b.get("spam_detected", 0) or 0),
            ))

        return DashboardStatsHistoryResponse(time_period=f"last_{days}_days", data=points)

    # --- Newer rich dashboard methods ---
    def get_dashboard_summary(self, db: Session, *, tenant_id: Optional[str] = None) -> DashboardSummaryResponse:
        tenant = self._resolve_tenant_id(tenant_id)
        stats = self.get_dashboard_statistics(db, tenant_id=tenant)

        # Additional derived metrics
        # Actions taken approximated as total alerts
        total_alerts = (
            db.query(func.count(AlertModel.id))
            .filter(AlertModel.tenant_id == tenant)
            .scalar()
            or 0
        )
        overall_stats = DashboardOverallStats(
            commands=stats["total_queries"],
            events=stats["total_queries"] + stats["files_scanned"] + stats["spam_detected"],
            detections=stats["malicious_queries"] + stats["spam_detected"],
            actions_taken=total_alerts,
        )

        stat_cards: List[DashboardStatCard] = [
            DashboardStatCard(title="Total Queries", value=str(stats["total_queries"]), icon_name="database"),
            DashboardStatCard(title="Malicious Queries", value=str(stats["malicious_queries"]), icon_name="shield-alert", trend_color_class="text-accent-red"),
            DashboardStatCard(title="Files Scanned", value=str(stats["files_scanned"]), icon_name="file-search"),
            DashboardStatCard(title="Spam/Phishing Flagged", value=str(stats["spam_detected"]), icon_name="mail-warning"),
        ]

        return DashboardSummaryResponse(
            last_updated=datetime.utcnow(),
            stat_cards=stat_cards,
            overall_stats=overall_stats,
        )

    def get_threat_trends(self, db: Session, days: int = 7, *, tenant_id: Optional[str] = None) -> ThreatTrendResponse:
        tenant = self._resolve_tenant_id(tenant_id)
        # Build last N days list
        today = datetime.utcnow().date()
        dates = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]

        def count_by_date(model) -> Dict[str, int]:
            try:
                date_col = func.date(model.timestamp)
                rows = (
                    db.query(date_col.label("d"), func.count(model.id))
                    .filter(model.tenant_id == tenant)
                    .group_by(date_col)
                    .all()
                )
                return {str(r[0]): int(r[1]) for r in rows if r[0]}
            except Exception:
                return {}

        sql_counts = count_by_date(SQLAnalysisLogModel)
        spam_counts = count_by_date(SpamAnalysisLogModel)
        file_counts = count_by_date(FileAnalysisLogModel)

        trend_data: List[ThreatTrendDataPoint] = []
        for d in dates:
            key = str(d)
            trend_data.append(
                ThreatTrendDataPoint(
                    name=key,
                    SQL_Injection=sql_counts.get(key, 0),
                    Spam=spam_counts.get(key, 0),
                    Files=file_counts.get(key, 0),
                    Other=0,
                )
            )

        return ThreatTrendResponse(time_period=f"last_{days}_days", trend_data=trend_data)

    def get_threats_by_category(self, db: Session, *, tenant_id: Optional[str] = None) -> ThreatsByCategoryResponse:
        tenant = self._resolve_tenant_id(tenant_id)
        sql_total = db.query(func.count(SQLAnalysisLogModel.id)).filter(SQLAnalysisLogModel.tenant_id == tenant).scalar() or 0
        spam_total = db.query(func.count(SpamAnalysisLogModel.id)).filter(SpamAnalysisLogModel.tenant_id == tenant).scalar() or 0
        file_total = db.query(func.count(FileAnalysisLogModel.id)).filter(FileAnalysisLogModel.tenant_id == tenant).scalar() or 0

        data = [
            ThreatByCategory(name="SQL Injection", count=sql_total, fill_color="#10b981"),
            ThreatByCategory(name="Spam", count=spam_total, fill_color="#3b82f6"),
            ThreatByCategory(name="Files", count=file_total, fill_color="#f59e0b"),
        ]
        return ThreatsByCategoryResponse(data=data)

    def get_alert_severity_distribution(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
    ) -> AlertSeverityDistributionResponse:
        tenant = self._resolve_tenant_id(tenant_id)
        try:
            rows = (
                db.query(AlertModel.severity, func.count(AlertModel.id))
                .filter(AlertModel.tenant_id == tenant)
                .group_by(AlertModel.severity)
                .all()
            )
            color_map = {
                "Critical": "#ef4444",
                "High": "#f97316",
                "Medium": "#eab308",
                "Low": "#10b981",
                None: "#6b7280",
            }
            data = [
                AlertSeverityDistribution(
                    name=str(sev) if sev else "Unknown",
                    value=int(cnt),
                    fill_color=color_map.get(str(sev), "#6b7280"),
                )
                for sev, cnt in rows
            ]
            return AlertSeverityDistributionResponse(data=data)
        except Exception:
            return AlertSeverityDistributionResponse(data=[])

    @staticmethod
    def classify_file_category(item: Dict[str, Any]) -> str:
        action = str(item.get("recommended_action") or "").upper()
        status = str(item.get("overall_status") or "").lower()
        risk = item.get("risk_score")
        yara_malicious = bool(item.get("yara_malicious", False))
        ml_suspicious = bool(item.get("ml_suspicious", False))

        if (
            "BLOCK" in action
            or "QUARANTINE" in action
            or "malicious" in status
            or "blocked" in status
        ):
            return "blocked"
        if (
            "suspicious" in status
            or "FLAG" in action
            or "WARN" in action
            or "REVIEW" in action
            or yara_malicious
            or ml_suspicious
            or (isinstance(risk, (int, float)) and float(risk) >= 0.5)
        ):
            return "suspicious"
        return "safe"

    @staticmethod
    def classify_sql_category(item: Dict[str, Any]) -> str:
        risk = str(item.get("risk_level") or "").lower()
        action = str(item.get("suggested_action") or "").upper()
        label = str(item.get("classification_label") or "").lower()
        is_anomalous = bool(item.get("is_anomalous", False))

        if risk in {"high", "critical"} or "BLOCK" in action:
            return "blocked"
        if (
            risk == "medium"
            or is_anomalous
            or "WARN" in action
            or "FLAG" in action
            or "suspicious" in label
            or "malicious" in label
        ):
            return "suspicious"
        return "safe"

    @staticmethod
    def classify_spam_category(item: Dict[str, Any]) -> str:
        score_raw = item.get("spam_score")
        score = float(score_raw) if isinstance(score_raw, (int, float)) else 0.0
        is_spam = bool(item.get("is_spam", False))
        label = str(item.get("classification_label") or "").lower()

        if (is_spam and score >= 0.85) or ("phish" in label):
            return "blocked"
        if is_spam or score >= 0.55 or "suspicious" in label or "ood" in label:
            return "suspicious"
        return "safe"

    def get_live_event_detail(
        self,
        db: Session,
        event_type: str,
        event_id: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Return a detailed payload for a single live-feed event."""
        tenant = self._resolve_tenant_id(tenant_id)
        if not event_type or not event_id:
            return None

        et = str(event_type).strip().lower()
        eid = str(event_id).strip()
        if not eid:
            return None

        try:
            if et == "query":
                row = (
                    db.query(SQLAnalysisLogModel)
                    .filter(SQLAnalysisLogModel.tenant_id == tenant, SQLAnalysisLogModel.id == eid)
                    .first()
                )
                if not row:
                    return None
                combined = row.combined_assessment or {}
                anomaly = row.anomaly_detection_result or {}
                validation = row.query_validation_result or {}
                risk = str(combined.get("overall_risk_level") or "").lower()
                risk_score = combined.get("calibrated_risk_score")
                decision = str(combined.get("suggested_action") or "ALLOW")
                return {
                    "id": row.id,
                    "type": "query",
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                    "summary": "SQL query analysis event",
                    "isMalicious": risk in {"high", "critical"},
                    "details": {
                        "query_received": row.query_received,
                        "combined_assessment": combined,
                        "anomaly_detection_result": anomaly,
                        "query_validation_result": validation,
                        "explainability_summary": self._explainability_summary(
                            domain="sql",
                            risk_score=risk_score,
                            decision=decision,
                        ),
                    },
                }

            if et == "file_scan":
                row = (
                    db.query(FileAnalysisLogModel)
                    .filter(FileAnalysisLogModel.tenant_id == tenant, FileAnalysisLogModel.id == eid)
                    .first()
                )
                if not row:
                    return None
                overall = row.overall_assessment or {}
                status = str(overall.get("overall_status") or "").lower()
                rec_action = str(overall.get("recommended_action") or "").upper()
                risk_score = overall.get("risk_score")
                is_malicious = (
                    "malicious" in status
                    or "suspicious" in status
                    or rec_action.startswith("BLOCK")
                    or rec_action.startswith("QUARANTINE")
                )
                return {
                    "id": row.id,
                    "type": "file_scan",
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                    "summary": f"File scan event for '{row.filename}'",
                    "isMalicious": is_malicious,
                    "details": {
                        "filename": row.filename,
                        "filesize_kb": row.filesize_kb,
                        "file_details": row.file_details or {},
                        "overall_assessment": overall,
                        "explainability_summary": self._explainability_summary(
                            domain="file",
                            risk_score=risk_score,
                            decision=rec_action,
                            recommended_handling=self._handling_from_decision(rec_action),
                        ),
                    },
                }

            if et == "spam_check":
                row = (
                    db.query(SpamAnalysisLogModel)
                    .filter(SpamAnalysisLogModel.tenant_id == tenant, SpamAnalysisLogModel.id == eid)
                    .first()
                )
                if not row:
                    return None
                cls = row.spam_classification_result or {}
                is_spam = bool(cls.get("is_spam", False))
                spam_score = cls.get("spam_score")
                decision_confidence = cls.get("decision_confidence")
                review_required = bool(
                    isinstance(spam_score, (int, float)) and 0.45 <= float(spam_score) <= 0.65
                ) or bool(isinstance(decision_confidence, (int, float)) and float(decision_confidence) < 0.70)
                decision = "FLAG_FOR_REVIEW" if review_required else ("BLOCK_OR_QUARANTINE" if is_spam else "ALLOW_WITH_MONITORING")
                return {
                    "id": row.id,
                    "type": "spam_check",
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                    "summary": "Spam check event",
                    "isMalicious": is_spam,
                    "details": {
                        "received_subject": row.received_subject,
                        "spam_classification_result": cls,
                        "explainability_summary": self._explainability_summary(
                            domain="spam",
                            risk_score=spam_score,
                            decision=decision,
                            recommended_handling="review" if review_required else ("block" if is_spam else "allow"),
                            review_required=review_required,
                        ),
                    },
                }

            if et == "alert":
                # Prefer enriched alert payload from AlertsService.
                try:
                    from backend.services.alerts_service import AlertsService
                    payload = AlertsService.get_instance().get_alert_detail_payload(db=db, alert_id=eid, tenant_id=tenant)
                    if payload:
                        return {
                            "id": payload.get("id"),
                            "type": "alert",
                            "timestamp": payload.get("timestamp"),
                            "summary": payload.get("title") or payload.get("message") or "Alert event",
                            "isMalicious": True,
                            "details": payload,
                        }
                except Exception:
                    pass

                alert = db.query(AlertModel).filter(AlertModel.tenant_id == tenant, AlertModel.id == eid).first()
                if not alert:
                    return None
                return {
                    "id": alert.id,
                    "type": "alert",
                    "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                    "summary": alert.title or alert.message or "Alert event",
                    "isMalicious": True,
                    "details": {
                        "id": alert.id,
                        "severity": alert.severity,
                        "title": alert.title,
                        "message": alert.message,
                        "source_ip": alert.source_ip,
                        "target": alert.target,
                        "query": alert.query,
                        "acknowledged": bool(alert.acknowledged),
                        "tags": alert.tags,
                    },
                }
        except Exception:
            return None

        return None

    def get_files_scanned_page(
        self,
        db: Session,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
        search: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return paged file scan entries with optional text search and category filtering."""
        page, page_size, offset = self._sanitize_pagination(page=page, page_size=page_size)
        try:
            q = db.query(
                FileAnalysisLogModel.id,
                FileAnalysisLogModel.timestamp,
                FileAnalysisLogModel.filename,
                FileAnalysisLogModel.filesize_kb,
                FileAnalysisLogModel.overall_status,
                FileAnalysisLogModel.recommended_action,
                FileAnalysisLogModel.risk_score_value,
                FileAnalysisLogModel.category,
                FileAnalysisLogModel._overall_assessment_json,  # type: ignore[attr-defined]
                FileAnalysisLogModel._file_details_json,  # type: ignore[attr-defined]
            )
            q = self._apply_tenant_scope(q, FileAnalysisLogModel, tenant_id)
            if start is not None:
                q = q.filter(FileAnalysisLogModel.timestamp >= start)
            if end is not None:
                q = q.filter(FileAnalysisLogModel.timestamp < end)
            if search and search.strip():
                term = f"%{search.strip()}%"
                q = q.filter(
                    or_(
                        FileAnalysisLogModel.filename.ilike(term),
                        FileAnalysisLogModel.id.ilike(term),
                    )
                )
            category_condition = self._file_category_condition(db, category)
            if category_condition is not None:
                q = q.filter(category_condition)

            total = int(q.with_entities(func.count(FileAnalysisLogModel.id)).scalar() or 0)
            rows = (
                q.order_by(FileAnalysisLogModel.timestamp.desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )

            items: List[Dict[str, Any]] = []
            for (
                analysis_id,
                ts,
                filename,
                filesize_kb,
                overall_status_col,
                recommended_action_col,
                risk_score_col,
                category_col,
                overall_json,
                details_json,
            ) in rows:
                overall = self._safe_json_dict(overall_json)
                details = self._safe_json_dict(details_json)
                type_validation = details.get("type_validation") if isinstance(details, dict) else {}
                malware_scan = details.get("malware_scan") if isinstance(details, dict) else {}
                ml_scan = details.get("ml_scan") if isinstance(details, dict) else {}
                type_validation = type_validation if isinstance(type_validation, dict) else {}
                malware_scan = malware_scan if isinstance(malware_scan, dict) else {}
                ml_scan = ml_scan if isinstance(ml_scan, dict) else {}

                resolved_status = str(overall_status_col or overall.get("overall_status") or "Unknown")
                resolved_action = str(recommended_action_col or overall.get("recommended_action") or "N/A")
                if isinstance(risk_score_col, (int, float)):
                    resolved_risk: Any = float(risk_score_col)
                else:
                    resolved_risk = overall.get("risk_score")

                item = {
                    "analysis_id": analysis_id,
                    "timestamp": ts.isoformat() if ts else None,
                    "filename": filename,
                    "filesize_kb": filesize_kb,
                    "overall_status": resolved_status,
                    "risk_score": resolved_risk,
                    "recommended_action": resolved_action,
                    "reasoning": overall.get("reasoning") or [],
                    "detected_mime_type": type_validation.get("detected_mime_type"),
                    "is_allowed_type": type_validation.get("is_allowed_type"),
                    "yara_malicious": bool(malware_scan.get("is_malicious", False)),
                    "yara_threat_name": malware_scan.get("threat_name"),
                    "ml_suspicious": bool(ml_scan.get("is_suspicious_ml", False)),
                    "ml_prediction_label": ml_scan.get("prediction_label_ml"),
                    "ml_prediction_score": ml_scan.get("prediction_score_ml"),
                }
                item["category"] = str(category_col or "").lower() or self.classify_file_category(item)
                items.append(item)

            total_pages = (total + page_size - 1) // page_size if total > 0 else 0
            return {"items": items, "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}
        except Exception:
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}

    def get_sql_queries_page(
        self,
        db: Session,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
        malicious_only: bool = False,
        search: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return paged SQL analysis rows with optional filtering by risk/category and search."""
        page, page_size, offset = self._sanitize_pagination(page=page, page_size=page_size)
        try:
            q = db.query(
                SQLAnalysisLogModel.id,
                SQLAnalysisLogModel.timestamp,
                SQLAnalysisLogModel.query_received,
                SQLAnalysisLogModel.risk_level,
                SQLAnalysisLogModel.suggested_action,
                SQLAnalysisLogModel.category,
                SQLAnalysisLogModel.is_malicious,
                SQLAnalysisLogModel._combined_assessment_json,  # type: ignore[attr-defined]
                SQLAnalysisLogModel._anomaly_detection_result_json,  # type: ignore[attr-defined]
                SQLAnalysisLogModel._query_validation_result_json,  # type: ignore[attr-defined]
            )
            q = self._apply_tenant_scope(q, SQLAnalysisLogModel, tenant_id)
            if start is not None:
                q = q.filter(SQLAnalysisLogModel.timestamp >= start)
            if end is not None:
                q = q.filter(SQLAnalysisLogModel.timestamp < end)
            if malicious_only:
                q = q.filter(self._sql_malicious_condition(db))
            if search and search.strip():
                term = f"%{search.strip()}%"
                q = q.filter(
                    or_(
                        SQLAnalysisLogModel.query_received.ilike(term),
                        SQLAnalysisLogModel.id.ilike(term),
                    )
                )
            category_condition = self._sql_category_condition(db, category)
            if category_condition is not None:
                q = q.filter(category_condition)

            total = int(q.with_entities(func.count(SQLAnalysisLogModel.id)).scalar() or 0)
            rows = (
                q.order_by(SQLAnalysisLogModel.timestamp.desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )

            items: List[Dict[str, Any]] = []
            for (
                analysis_id,
                ts,
                query_received,
                risk_level_col,
                suggested_action_col,
                category_col,
                is_malicious_col,
                combined_json,
                anomaly_json,
                validation_json,
            ) in rows:
                combined = self._safe_json_dict(combined_json)
                anomaly = self._safe_json_dict(anomaly_json)
                validation = self._safe_json_dict(validation_json)
                risk_level = str(risk_level_col or combined.get("overall_risk_level") or "Unknown")
                suggested_action = str(suggested_action_col or combined.get("suggested_action") or "")
                is_malicious = bool(is_malicious_col) or risk_level.lower() in {"high", "critical"} or suggested_action.upper().startswith("BLOCK")
                item = {
                    "analysis_id": analysis_id,
                    "timestamp": ts.isoformat() if ts else None,
                    "query_received": query_received,
                    "risk_level": risk_level,
                    "suggested_action": suggested_action or None,
                    "reasoning": combined.get("reasoning") or [],
                    "is_malicious": is_malicious,
                    "anomaly_score": anomaly.get("score"),
                    "anomaly_label": anomaly.get("prediction_label"),
                    "is_anomalous": bool(anomaly.get("is_anomalous", False)),
                    "classification_label": validation.get("classification_label"),
                    "classification_score": validation.get("classification_score"),
                }
                item["category"] = str(category_col or "").lower() or self.classify_sql_category(item)
                items.append(item)

            total_pages = (total + page_size - 1) // page_size if total > 0 else 0
            return {"items": items, "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}
        except Exception:
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}

    def get_spam_checks_page(
        self,
        db: Session,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
        detected_only: bool = True,
        search: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return paged spam analysis rows with optional detection/category filters and search."""
        page, page_size, offset = self._sanitize_pagination(page=page, page_size=page_size)
        try:
            q = db.query(
                SpamAnalysisLogModel.id,
                SpamAnalysisLogModel.timestamp,
                SpamAnalysisLogModel.received_subject,
                SpamAnalysisLogModel.is_spam,
                SpamAnalysisLogModel.spam_score,
                SpamAnalysisLogModel.classification_label,
                SpamAnalysisLogModel.category,
                SpamAnalysisLogModel._spam_classification_result_json,  # type: ignore[attr-defined]
            )
            q = self._apply_tenant_scope(q, SpamAnalysisLogModel, tenant_id)
            if start is not None:
                q = q.filter(SpamAnalysisLogModel.timestamp >= start)
            if end is not None:
                q = q.filter(SpamAnalysisLogModel.timestamp < end)
            if detected_only:
                q = q.filter(self._spam_detected_condition(db))
            if search and search.strip():
                term = f"%{search.strip()}%"
                q = q.filter(
                    or_(
                        SpamAnalysisLogModel.received_subject.ilike(term),
                        SpamAnalysisLogModel.id.ilike(term),
                    )
                )
            category_condition = self._spam_category_condition(db, category)
            if category_condition is not None:
                q = q.filter(category_condition)

            total = int(q.with_entities(func.count(SpamAnalysisLogModel.id)).scalar() or 0)
            rows = (
                q.order_by(SpamAnalysisLogModel.timestamp.desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )

            items: List[Dict[str, Any]] = []
            for (
                analysis_id,
                ts,
                received_subject,
                is_spam_col,
                spam_score_col,
                classification_label_col,
                category_col,
                cls_json,
            ) in rows:
                cls = self._safe_json_dict(cls_json)
                is_spam = bool(is_spam_col) or bool(cls.get("is_spam", False))
                spam_score = float(spam_score_col) if isinstance(spam_score_col, (int, float)) else cls.get("spam_score")
                classification_label = str(classification_label_col or cls.get("classification_label") or "")
                item = {
                    "analysis_id": analysis_id,
                    "timestamp": ts.isoformat() if ts else None,
                    "received_subject": received_subject,
                    "is_spam": is_spam,
                    "spam_score": spam_score,
                    "classification_label": classification_label or None,
                }
                item["category"] = str(category_col or "").lower() or self.classify_spam_category(item)
                items.append(item)

            total_pages = (total + page_size - 1) // page_size if total > 0 else 0
            return {"items": items, "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}
        except Exception:
            return {"items": [], "total": 0, "page": page, "page_size": page_size, "total_pages": 0}

    def get_files_scanned(
        self,
        db: Session,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
        limit: int = 500,
        search: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Backward-compatible non-paged wrapper."""
        result = self.get_files_scanned_page(
            db=db,
            start=start,
            end=end,
            tenant_id=tenant_id,
            page=1,
            page_size=limit,
            search=search,
            category=category,
        )
        return result.get("items", [])

    def get_sql_queries(
        self,
        db: Session,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
        limit: int = 500,
        malicious_only: bool = False,
        search: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Backward-compatible non-paged wrapper."""
        result = self.get_sql_queries_page(
            db=db,
            start=start,
            end=end,
            tenant_id=tenant_id,
            page=1,
            page_size=limit,
            malicious_only=malicious_only,
            search=search,
            category=category,
        )
        return result.get("items", [])

    def get_spam_checks(
        self,
        db: Session,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
        limit: int = 500,
        detected_only: bool = True,
        search: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Backward-compatible non-paged wrapper."""
        result = self.get_spam_checks_page(
            db=db,
            start=start,
            end=end,
            tenant_id=tenant_id,
            page=1,
            page_size=limit,
            detected_only=detected_only,
            search=search,
            category=category,
        )
        return result.get("items", [])


# Backwards-compatible function used by legacy router endpoint /dashboard/stats
def get_dashboard_statistics(db: Session, tenant_id: Optional[str] = None) -> Dict[str, int]:
    return DashboardService.get_instance().get_dashboard_statistics(db, tenant_id=tenant_id)


def _normalize_event_types(event_types: Optional[str]) -> List[str]:
    allowed = {"query", "file_scan", "spam_check", "alert"}
    if not event_types:
        return ["query", "file_scan", "spam_check", "alert"]

    requested = [
        token.strip().lower()
        for token in str(event_types).split(",")
        if token and token.strip()
    ]
    filtered = [token for token in requested if token in allowed]
    return filtered if filtered else ["query", "file_scan", "spam_check", "alert"]


def _to_utc_datetime(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def get_recent_events(
    db: Session,
    limit: int = 50,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    before: Optional[datetime] = None,
    event_types: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Return recent mixed events for live feed with bounded, index-friendly queries.

    Notes:
    - `start`/`end` define a UTC time window (end-exclusive)
    - `before` is a cursor timestamp (exclusive upper bound)
    - `event_types` is a CSV: query,file_scan,spam_check,alert
    """
    events: List[Dict[str, Any]] = []
    normalized_limit = max(1, min(int(limit or 50), 500))
    types_requested = _normalize_event_types(event_types)
    tenant = DashboardService._resolve_tenant_id(tenant_id)

    window_start = _to_utc_datetime(start)
    window_end = _to_utc_datetime(end)
    cursor_before = _to_utc_datetime(before)
    if cursor_before is not None:
        if window_end is None or cursor_before < window_end:
            window_end = cursor_before
    if window_start is not None and window_end is not None and window_start >= window_end:
        return []

    # Pull a bounded window from each selected source, then merge/sort/trim.
    source_limit = max(normalized_limit, min(500, normalized_limit * 2))

    def _apply_window_filters(query, model):
        if window_start is not None:
            query = query.filter(model.timestamp >= window_start)
        if window_end is not None:
            query = query.filter(model.timestamp < window_end)
        return query

    try:
        if "query" in types_requested:
            sql_q = db.query(
                SQLAnalysisLogModel.id,
                SQLAnalysisLogModel.timestamp,
                SQLAnalysisLogModel.risk_level,
                SQLAnalysisLogModel.is_malicious,
                SQLAnalysisLogModel._combined_assessment_json,  # type: ignore[attr-defined]
            )
            sql_q = sql_q.filter(SQLAnalysisLogModel.tenant_id == tenant)
            sql_rows = (
                _apply_window_filters(sql_q, SQLAnalysisLogModel)
                .order_by(SQLAnalysisLogModel.timestamp.desc())
                .limit(source_limit)
                .all()
            )
            for analysis_id, ts, risk_level_col, is_malicious_col, combined_json in sql_rows:
                risk_level = str(risk_level_col or "")
                mal = bool(is_malicious_col) or risk_level.lower() in {"high", "critical"}
                if not risk_level and combined_json:
                    try:
                        combined = json.loads(combined_json)
                        if isinstance(combined, dict):
                            mal = mal or str(combined.get("overall_risk_level") or "").lower() in {"high", "critical"}
                    except Exception:
                        pass
                event_ts = _to_utc_datetime(ts) or datetime.now(timezone.utc)
                events.append(
                    {
                        "id": analysis_id,
                        "type": "query",
                        "message": f"SQL query {'malicious' if mal else 'analyzed'}",
                        "timestamp": event_ts.isoformat(),
                        "isMalicious": mal,
                        "tenant_id": tenant,
                        "_sort_ts": event_ts,
                    }
                )

        if "file_scan" in types_requested:
            file_q = db.query(
                FileAnalysisLogModel.id,
                FileAnalysisLogModel.timestamp,
                FileAnalysisLogModel.filename,
                FileAnalysisLogModel.overall_status,
                FileAnalysisLogModel.recommended_action,
                FileAnalysisLogModel.category,
                FileAnalysisLogModel._overall_assessment_json,  # type: ignore[attr-defined]
            )
            file_q = file_q.filter(FileAnalysisLogModel.tenant_id == tenant)
            file_rows = (
                _apply_window_filters(file_q, FileAnalysisLogModel)
                .order_by(FileAnalysisLogModel.timestamp.desc())
                .limit(source_limit)
                .all()
            )
            for analysis_id, ts, filename, overall_status_col, recommended_action_col, category_col, overall_json in file_rows:
                status = str(overall_status_col or "").lower()
                action = str(recommended_action_col or "").upper()
                category = str(category_col or "").lower()
                mal = (
                    category in {"blocked", "suspicious"}
                    or ("malicious" in status)
                    or ("suspicious" in status)
                    or action.startswith("BLOCK")
                )
                if not status and overall_json:
                    try:
                        overall = json.loads(overall_json)
                        if isinstance(overall, dict):
                            status = str(overall.get("overall_status") or "").lower()
                            action = str(overall.get("recommended_action") or "").upper()
                            mal = mal or ("malicious" in status) or ("suspicious" in status) or action.startswith("BLOCK")
                    except Exception:
                        pass
                event_ts = _to_utc_datetime(ts) or datetime.now(timezone.utc)
                events.append(
                    {
                        "id": analysis_id,
                        "type": "file_scan",
                        "message": f"File '{filename}' {'flagged' if mal else 'scanned ok'}",
                        "timestamp": event_ts.isoformat(),
                        "isMalicious": mal,
                        "tenant_id": tenant,
                        "_sort_ts": event_ts,
                    }
                )

        if "spam_check" in types_requested:
            spam_q = db.query(
                SpamAnalysisLogModel.id,
                SpamAnalysisLogModel.timestamp,
                SpamAnalysisLogModel.is_spam,
                SpamAnalysisLogModel.classification_label,
                SpamAnalysisLogModel._spam_classification_result_json,  # type: ignore[attr-defined]
            )
            spam_q = spam_q.filter(SpamAnalysisLogModel.tenant_id == tenant)
            spam_rows = (
                _apply_window_filters(spam_q, SpamAnalysisLogModel)
                .order_by(SpamAnalysisLogModel.timestamp.desc())
                .limit(source_limit)
                .all()
            )
            for analysis_id, ts, is_spam_col, classification_label_col, cls_json in spam_rows:
                is_spam = bool(is_spam_col)
                label = str(classification_label_col or "")
                if not label and cls_json:
                    try:
                        cls = json.loads(cls_json)
                        if isinstance(cls, dict):
                            is_spam = is_spam or bool(cls.get("is_spam", False))
                            label = str(cls.get("classification_label") or "")
                    except Exception:
                        pass
                event_ts = _to_utc_datetime(ts) or datetime.now(timezone.utc)
                events.append(
                    {
                        "id": analysis_id,
                        "type": "spam_check",
                        "message": f"Spam check: {label or ('spam' if is_spam else 'not spam')}",
                        "timestamp": event_ts.isoformat(),
                        "isMalicious": is_spam,
                        "tenant_id": tenant,
                        "_sort_ts": event_ts,
                    }
                )

        if "alert" in types_requested:
            alert_q = db.query(
                AlertModel.id,
                AlertModel.timestamp,
                AlertModel.title,
            )
            alert_q = alert_q.filter(AlertModel.tenant_id == tenant)
            alert_rows = (
                _apply_window_filters(alert_q, AlertModel)
                .order_by(AlertModel.timestamp.desc())
                .limit(source_limit)
                .all()
            )
            for alert_id, ts, title in alert_rows:
                event_ts = _to_utc_datetime(ts) or datetime.now(timezone.utc)
                events.append(
                    {
                        "id": alert_id,
                        "type": "alert",
                        "message": title or "New alert",
                        "timestamp": event_ts.isoformat(),
                        "isMalicious": True,
                        "tenant_id": tenant,
                        "_sort_ts": event_ts,
                    }
                )

        events.sort(
            key=lambda event: (
                event.get("_sort_ts") or datetime.min.replace(tzinfo=timezone.utc),
                str(event.get("id") or ""),
            ),
            reverse=True,
        )
        trimmed = events[:normalized_limit]
        for event in trimmed:
            event.pop("_sort_ts", None)
        return trimmed
    except Exception:
        return []
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    


    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    

    
    

    
    
    
    
    
    
    

    
    

    

    
    
    
    
    

    
    
    
    

    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    


    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    


    
    
    
    
    
    
    
    

    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    

    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    

    
    

    
    
    
    
    
    

    
    

    
    

    

    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    

    
    
    
    
    

    
    

    
    
    
    
    

    
    
    
    

    
    
    
    
    
    

    
    
    
    
    

    
    
    
    
    
    
    
    
    

    
    
    
    
    
    

    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    

    
    
    
    
    
    

    
    
    
    
    
    
    

    
    
    
    
    

    
    

    
    
    

    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    

    
    
    
    
    
    
    

    
    
    
    
    
    
    

    
    

    
    
    
    

    
    
    
    
    
    
    
    
    

    
    
    
    

    
    

    
    
    
    

    
    
    

    

    
    
    

    
    
    
    
    
    
    
    
    
    

    
    
    
    

    
    
    
    
    
    
    

    
    
    
    

    
    
    
    

    
    
    
    
    
    
    

    
    
    
    
    
    

    
    
    
    
    
    
    
    

    
    
    
    
    
    

    
    

    
    
    
    
    

    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    

    
    
    
    
    
    
    

    
    
    
    
    

    
    
    
    

    
    
    
    
    
    
    

    
    
    
    
    
    

    
    

    
    

    

    

    
    

    

    
    

    

    
    
    
    

    
    
    
    
    
    
