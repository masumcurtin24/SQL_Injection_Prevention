from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import pandas as pd
from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.core.models import DEFAULT_TENANT_ID, DefenderFeedback, DefenderModelRegistry, DefenderTrainingJob
from backend.services.file_analysis_service import FileAnalysisService
from backend.services.query_analysis_service import QueryAnalysisService
from backend.services.spam_detection_service import SpamDetectionService
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


class DefenderAIService:
    _instance: Optional["DefenderAIService"] = None
    _initialized_flag: bool = False
    _PROMOTION_DEFAULTS: Dict[str, Dict[str, float]] = {
        "sql": {
            "MIN_PRECISION": 0.85,
            "MIN_RECALL": 0.60,
            "MIN_F1": 0.70,
            "MAX_FPR": 0.05,
            "MIN_EVAL_SAMPLES": 20.0,
            "MIN_POSITIVE_EVAL_SAMPLES": 5.0,
            "MIN_NEGATIVE_EVAL_SAMPLES": 5.0,
            "MAX_RECALL_DROP": 0.05,
        },
        "spam": {
            "MIN_PRECISION": 0.95,
            "MIN_RECALL": 0.90,
            "MIN_F1": 0.92,
            "MAX_FPR": 0.05,
            "MIN_EVAL_SAMPLES": 20.0,
            "MIN_POSITIVE_EVAL_SAMPLES": 5.0,
            "MIN_NEGATIVE_EVAL_SAMPLES": 5.0,
            "MAX_RECALL_DROP": 0.03,
            "MAX_RECALL_DROP_FOR_FPR_WIN": 0.01,
        },
        "file": {
            "MIN_PRECISION": 0.55,
            "MIN_RECALL": 0.65,
            "MIN_F1": 0.60,
            "MAX_FPR": 0.25,
            "MIN_EVAL_SAMPLES": 20.0,
            "MIN_POSITIVE_EVAL_SAMPLES": 5.0,
            "MIN_NEGATIVE_EVAL_SAMPLES": 5.0,
            "MAX_RECALL_DROP": 0.05,
        },
    }

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(DefenderAIService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized_flag:
            return
        self._backend_dir = Path(__file__).resolve().parents[1]
        self._raw_dir = self._backend_dir / "data" / "raw"
        self._models_dir = self._backend_dir / "data" / "models_store"
        self._pipeline_dir = self._backend_dir / "data" / "pipelines"
        self._jobs_dir = self._backend_dir / "data" / "retrain_jobs"
        self._corpus_dir = self._backend_dir / "data" / "corpus"
        self._models_dir.mkdir(parents=True, exist_ok=True)
        self._pipeline_dir.mkdir(parents=True, exist_ok=True)
        self._jobs_dir.mkdir(parents=True, exist_ok=True)
        self._corpus_dir.mkdir(parents=True, exist_ok=True)
        self._initialized_flag = True
        logger.info("DefenderAIService initialized.")

    @classmethod
    def get_instance(cls) -> "DefenderAIService":
        if cls._instance is None:
            raise RuntimeError("DefenderAIService has not been initialized.")
        return cls._instance

    @staticmethod
    def _resolve_tenant_id(tenant_id: Optional[str]) -> str:
        value = str(tenant_id or "").strip()
        return value or DEFAULT_TENANT_ID

    @staticmethod
    def _callable_accepts_kwarg(fn: Any, name: str) -> bool:
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            return True
        params = sig.parameters
        if name in params:
            return True
        return any(param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values())

    def _invoke_with_optional_tenant(self, fn: Any, *, tenant_id: Optional[str], **kwargs: Any) -> Any:
        if tenant_id and self._callable_accepts_kwarg(fn, "tenant_id"):
            return fn(**kwargs, tenant_id=tenant_id)
        return fn(**kwargs)

    @staticmethod
    def _tenant_scope_clause(model: Any, tenant_id: str):
        column = getattr(model, "tenant_id")
        return or_(column == tenant_id, column.is_(None), column == "")

    def _persist_feedback(
        self,
        *,
        db: Session,
        tenant_id: Optional[str],
        domain: str,
        true_label: str,
        payload: Dict[str, Any],
        predicted_label: Optional[str] = None,
        confidence: Optional[float] = None,
        analysis_id: Optional[str] = None,
        source: str = "human",
        notes: Optional[str] = None,
    ) -> DefenderFeedback:
        effective_tenant_id = self._resolve_tenant_id(tenant_id)
        model = DefenderFeedback(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            tenant_id=effective_tenant_id,
            domain=domain,
            analysis_id=analysis_id,
            predicted_label=predicted_label,
            true_label=true_label,
            confidence=confidence,
            source=source,
            notes=notes,
            processed=False,
        )
        model.sample_payload = payload
        db.add(model)
        db.commit()
        db.refresh(model)
        return model

    def submit_sql_feedback(
        self,
        *,
        db: Session,
        tenant_id: Optional[str] = None,
        query: str,
        true_label: str,
        predicted_label: Optional[str] = None,
        confidence: Optional[float] = None,
        analysis_id: Optional[str] = None,
        source: str = "human",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        model = self._persist_feedback(
            db=db,
            tenant_id=tenant_id,
            domain="sql",
            true_label=true_label,
            payload={"query": query},
            predicted_label=predicted_label,
            confidence=confidence,
            analysis_id=analysis_id,
            source=source,
            notes=notes,
        )
        return {"feedback_id": model.id, "domain": "sql", "status": "accepted"}

    def submit_file_feedback(
        self,
        *,
        db: Session,
        tenant_id: Optional[str] = None,
        filename: str,
        true_label: str,
        observed_text: Optional[str] = None,
        predicted_label: Optional[str] = None,
        recommended_action: Optional[str] = None,
        confidence: Optional[float] = None,
        analysis_id: Optional[str] = None,
        source: str = "human",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"filename": filename}
        if observed_text:
            payload["observed_text"] = observed_text[:20000]
        if recommended_action:
            payload["recommended_action"] = recommended_action

        model = self._persist_feedback(
            db=db,
            tenant_id=tenant_id,
            domain="file",
            true_label=true_label,
            payload=payload,
            predicted_label=predicted_label,
            confidence=confidence,
            analysis_id=analysis_id,
            source=source,
            notes=notes,
        )
        return {"feedback_id": model.id, "domain": "file", "status": "accepted"}

    def submit_spam_feedback(
        self,
        *,
        db: Session,
        tenant_id: Optional[str] = None,
        body_text: str,
        true_label: str,
        subject: Optional[str] = None,
        sender_email: Optional[str] = None,
        predicted_label: Optional[str] = None,
        confidence: Optional[float] = None,
        analysis_id: Optional[str] = None,
        source: str = "human",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {"subject": subject, "body_text": body_text, "sender_email": sender_email}
        model = self._persist_feedback(
            db=db,
            tenant_id=tenant_id,
            domain="spam",
            true_label=true_label,
            payload=payload,
            predicted_label=predicted_label,
            confidence=confidence,
            analysis_id=analysis_id,
            source=source,
            notes=notes,
        )

        online_learner = self._maybe_update_spam_online_learner(
            subject=subject,
            body_text=body_text,
            true_label=true_label,
            source=source,
        )

        auto_retrain = self._maybe_auto_retrain_spam_false_negatives(
            db=db,
            latest_feedback=model,
        )
        return {
            "feedback_id": model.id,
            "domain": "spam",
            "status": "accepted",
            "online_learner": online_learner,
            "auto_retrain": auto_retrain,
        }

    def _spam_online_feedback_sources(self) -> set:
        raw = os.getenv("DEFENDER_SPAM_ONLINE_LEARN_SOURCES", "human").strip()
        return {item.strip().lower() for item in raw.split(",") if item.strip()}

    def _maybe_update_spam_online_learner(
        self,
        *,
        subject: Optional[str],
        body_text: str,
        true_label: str,
        source: str,
    ) -> Dict[str, Any]:
        allowed_sources = self._spam_online_feedback_sources()
        source_token = str(source or "").strip().lower() or "unknown"
        if "all" not in allowed_sources and source_token not in allowed_sources:
            return {
                "attempted": False,
                "updated": False,
                "reason": "source_not_allowed",
                "source": source_token,
                "allowed_sources": sorted(allowed_sources),
            }
        if not (self._is_positive_spam_label(true_label) or self._is_negative_spam_label(true_label)):
            return {
                "attempted": False,
                "updated": False,
                "reason": "unsupported_label",
                "source": source_token,
            }

        try:
            spam_service = SpamDetectionService.get_instance()
            result = spam_service.submit_feedback(
                text=f"{subject or ''} {body_text}".strip(),
                label=true_label,
            )
            return {
                "attempted": True,
                "updated": bool((result or {}).get("online_updated")),
                "reason": "updated" if bool((result or {}).get("online_updated")) else "not_updated",
                "source": source_token,
            }
        except Exception as exc:
            logger.warning(f"Online spam learner update skipped: {exc}")
            return {
                "attempted": True,
                "updated": False,
                "reason": "update_failed",
                "source": source_token,
                "error": str(exc),
            }

    @staticmethod
    def _is_positive_spam_label(value: Optional[str]) -> bool:
        token = str(value or "").strip().lower()
        return token in {"spam", "phishing", "malicious", "suspicious", "blocked", "junk"}

    @staticmethod
    def _is_negative_spam_label(value: Optional[str]) -> bool:
        token = str(value or "").strip().lower()
        return token in {"ham", "safe", "benign", "allow", "not spam", "legitimate", "clean"}

    def _maybe_auto_retrain_spam_false_negatives(
        self,
        *,
        db: Session,
        latest_feedback: DefenderFeedback,
    ) -> Dict[str, Any]:
        enabled = str(os.getenv("DEFENDER_SPAM_AUTO_RETRAIN_ENABLED", "true")).strip().lower() in {"1", "true", "yes", "on"}
        if not enabled:
            return {"enabled": False, "triggered": False, "reason": "disabled"}

        if str(latest_feedback.domain or "").lower() != "spam":
            return {"enabled": True, "triggered": False, "reason": "not_spam_domain"}
        if str(latest_feedback.source or "").lower() != "human":
            return {"enabled": True, "triggered": False, "reason": "non_human_feedback"}
        if not self._is_positive_spam_label(latest_feedback.true_label):
            return {"enabled": True, "triggered": False, "reason": "feedback_not_positive_spam"}
        if not self._is_negative_spam_label(latest_feedback.predicted_label):
            return {"enabled": True, "triggered": False, "reason": "not_false_negative_pattern"}

        min_samples = int(self._safe_int_env("DEFENDER_SPAM_AUTO_RETRAIN_MIN_FALSE_NEGATIVE_SAMPLES", 5))
        cooldown_minutes = int(self._safe_int_env("DEFENDER_SPAM_AUTO_RETRAIN_COOLDOWN_MINUTES", 30))
        promote_if_better = str(os.getenv("DEFENDER_SPAM_AUTO_RETRAIN_PROMOTE_IF_BETTER", "true")).strip().lower() in {"1", "true", "yes", "on"}

        pending_false_negatives = (
            db.query(DefenderFeedback)
            .filter(
                DefenderFeedback.tenant_id == latest_feedback.tenant_id,
                DefenderFeedback.domain == "spam",
                DefenderFeedback.processed.is_(False),
                DefenderFeedback.source == "human",
            )
            .all()
        )
        fn_candidates = [
            row
            for row in pending_false_negatives
            if self._is_positive_spam_label(row.true_label) and self._is_negative_spam_label(row.predicted_label)
        ]
        fn_count = len(fn_candidates)
        if fn_count < min_samples:
            return {
                "enabled": True,
                "triggered": False,
                "reason": "insufficient_false_negatives",
                "false_negative_count": fn_count,
                "required": min_samples,
            }

        running_job = (
            db.query(DefenderTrainingJob)
            .filter(
                DefenderTrainingJob.tenant_id == latest_feedback.tenant_id,
                DefenderTrainingJob.domain == "spam",
                DefenderTrainingJob.status.in_(["queued", "running"]),
                DefenderTrainingJob.notes.like("%auto_false_negative%"),
            )
            .order_by(DefenderTrainingJob.timestamp.desc())
            .first()
        )
        if running_job is not None:
            return {
                "enabled": True,
                "triggered": False,
                "reason": "auto_job_in_progress",
                "job_id": running_job.id,
                "false_negative_count": fn_count,
            }

        latest_auto_job = (
            db.query(DefenderTrainingJob)
            .filter(
                DefenderTrainingJob.tenant_id == latest_feedback.tenant_id,
                DefenderTrainingJob.domain == "spam",
                DefenderTrainingJob.notes.like("%auto_false_negative%"),
            )
            .order_by(DefenderTrainingJob.timestamp.desc())
            .first()
        )
        if latest_auto_job is not None and latest_auto_job.timestamp is not None:
            now = datetime.now(timezone.utc)
            latest_ts = latest_auto_job.timestamp
            if latest_ts.tzinfo is None:
                latest_ts = latest_ts.replace(tzinfo=timezone.utc)
            age = now - latest_ts
            if age < timedelta(minutes=max(1, cooldown_minutes)):
                return {
                    "enabled": True,
                    "triggered": False,
                    "reason": "cooldown_active",
                    "cooldown_minutes": cooldown_minutes,
                    "last_job_id": latest_auto_job.id,
                    "false_negative_count": fn_count,
                }

        notes = (
            "auto_false_negative "
            f"trigger_count={fn_count} "
            f"source_feedback_id={latest_feedback.id}"
        )
        try:
            job = self._invoke_with_optional_tenant(
                self.create_training_job,
                tenant_id=latest_feedback.tenant_id,
                db=db,
                domain="spam",
                min_feedback_samples=max(1, min_samples),
                promote_if_better=promote_if_better,
                requested_by=None,
                notes=notes,
            )
            job = self._invoke_with_optional_tenant(
                self.run_training_job,
                tenant_id=latest_feedback.tenant_id,
                db=db,
                job_id=job.id,
            )
            return {
                "enabled": True,
                "triggered": True,
                "reason": "auto_false_negative_retrain",
                "job_id": job.id,
                "job_status": job.status,
                "false_negative_count": fn_count,
            }
        except Exception as exc:
            logger.error(f"Auto spam retraining failed: {exc}", exc_info=True)
            return {
                "enabled": True,
                "triggered": False,
                "reason": "auto_retrain_failed",
                "error": str(exc),
                "false_negative_count": fn_count,
            }

    @staticmethod
    def _safe_int_env(key: str, default: int) -> int:
        raw = os.getenv(key)
        if raw is None:
            return default
        try:
            return int(raw)
        except Exception:
            return default

    def get_status(self, db: Session, *, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        tenant = self._resolve_tenant_id(tenant_id)
        counts: Dict[str, int] = {}
        for d in ("sql", "spam", "file"):
            counts[d] = int(
                db.query(DefenderFeedback)
                .filter(DefenderFeedback.tenant_id == tenant, DefenderFeedback.domain == d)
                .count()
            )
        pending = int(
            db.query(DefenderFeedback)
            .filter(DefenderFeedback.tenant_id == tenant, DefenderFeedback.processed.is_(False))
            .count()
        )

        models_by_domain: Dict[str, List[DefenderModelRegistry]] = {}
        for d in ("sql", "spam", "file"):
            rows = (
                db.query(DefenderModelRegistry)
                .filter(DefenderModelRegistry.tenant_id == tenant, DefenderModelRegistry.domain == d)
                .order_by(DefenderModelRegistry.timestamp.desc())
                .limit(10)
                .all()
            )
            models_by_domain[d] = rows

        recent_jobs = (
            db.query(DefenderTrainingJob)
            .filter(DefenderTrainingJob.tenant_id == tenant)
            .order_by(DefenderTrainingJob.timestamp.desc())
            .limit(10)
            .all()
        )
        jobs_by_status: Dict[str, int] = {}
        for row in recent_jobs:
            key = str(row.status or "unknown")
            jobs_by_status[key] = jobs_by_status.get(key, 0) + 1

        return {
            "feedback_counts": counts,
            "pending_feedback": pending,
            "models": models_by_domain,
            "recent_jobs": recent_jobs,
            "job_status_counts": jobs_by_status,
        }

    def list_models(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        domain: Optional[str] = None,
        stage: Optional[str] = None,
        limit: int = 50,
    ) -> List[DefenderModelRegistry]:
        tenant = self._resolve_tenant_id(tenant_id)
        q = db.query(DefenderModelRegistry).filter(DefenderModelRegistry.tenant_id == tenant)
        if domain:
            q = q.filter(DefenderModelRegistry.domain == domain)
        if stage:
            q = q.filter(DefenderModelRegistry.stage == stage)
        return q.order_by(DefenderModelRegistry.timestamp.desc()).limit(max(1, min(limit, 200))).all()

    def _register_candidate(
        self,
        *,
        db: Session,
        tenant_id: Optional[str],
        domain: str,
        model_name: str,
        version: str,
        artifact_path: str,
        metrics: Dict[str, Any],
        notes: Optional[str] = None,
    ) -> DefenderModelRegistry:
        tenant = self._resolve_tenant_id(tenant_id)
        model = DefenderModelRegistry(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            tenant_id=tenant,
            domain=domain,
            model_name=model_name,
            version=version,
            stage="candidate",
            artifact_path=artifact_path,
            notes=notes,
        )
        model.metrics = metrics
        db.add(model)
        db.commit()
        db.refresh(model)
        return model

    def _promote_candidate(self, db: Session, candidate: DefenderModelRegistry, notes: Optional[str] = None) -> DefenderModelRegistry:
        now = datetime.now(timezone.utc)
        active = (
            db.query(DefenderModelRegistry)
            .filter(
                DefenderModelRegistry.tenant_id == candidate.tenant_id,
                DefenderModelRegistry.domain == candidate.domain,
                DefenderModelRegistry.stage == "active",
            )
            .all()
        )
        for row in active:
            row.stage = "retired"
        candidate.stage = "active"
        candidate.promoted_at = now
        if notes:
            candidate.notes = f"{candidate.notes or ''}\n{notes}".strip()
        db.commit()
        db.refresh(candidate)

        self._apply_model_runtime(candidate.domain, candidate.artifact_path)
        return candidate

    def promote_model(
        self,
        db: Session,
        registry_id: str,
        notes: Optional[str] = None,
        force: bool = False,
        tenant_id: Optional[str] = None,
    ) -> DefenderModelRegistry:
        tenant = self._resolve_tenant_id(tenant_id)
        candidate = (
            db.query(DefenderModelRegistry)
            .filter(DefenderModelRegistry.tenant_id == tenant, DefenderModelRegistry.id == registry_id)
            .first()
        )
        if not candidate:
            raise ValueError(f"Model registry entry not found: {registry_id}")

        if candidate.stage == "active":
            return candidate

        metrics = candidate.metrics or {}
        gate = metrics.get("promotion_gate")
        if not force:
            if not isinstance(gate, dict):
                gate = self._evaluate_promotion_gate(
                    db=db,
                    domain=candidate.domain,
                    candidate_metrics=metrics,
                    tenant_id=tenant,
                )
            if not bool(gate.get("passed", False)):
                reasons = gate.get("reasons") or ["promotion gate rejected candidate"]
                raise ValueError(f"Promotion gate failed: {', '.join(str(r) for r in reasons)}")

        return self._promote_candidate(db, candidate, notes=notes)

    def rollback_model(
        self,
        db: Session,
        *,
        domain: str,
        target_registry_id: Optional[str] = None,
        notes: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant = self._resolve_tenant_id(tenant_id)
        if domain not in {"sql", "spam", "file"}:
            raise ValueError(f"Unsupported domain for rollback: {domain}")

        current_active = (
            db.query(DefenderModelRegistry)
            .filter(
                DefenderModelRegistry.tenant_id == tenant,
                DefenderModelRegistry.domain == domain,
                DefenderModelRegistry.stage == "active",
            )
            .order_by(DefenderModelRegistry.promoted_at.desc(), DefenderModelRegistry.timestamp.desc())
            .first()
        )

        if target_registry_id:
            target = (
                db.query(DefenderModelRegistry)
                .filter(
                    DefenderModelRegistry.tenant_id == tenant,
                    DefenderModelRegistry.id == target_registry_id,
                    DefenderModelRegistry.domain == domain,
                )
                .first()
            )
            if not target:
                raise ValueError(f"Rollback target not found in domain '{domain}': {target_registry_id}")
        else:
            q = (
                db.query(DefenderModelRegistry)
                .filter(
                    DefenderModelRegistry.tenant_id == tenant,
                    DefenderModelRegistry.domain == domain,
                    DefenderModelRegistry.stage.in_(["retired", "candidate"]),
                )
                .order_by(DefenderModelRegistry.promoted_at.desc(), DefenderModelRegistry.timestamp.desc())
            )
            if current_active is not None:
                q = q.filter(DefenderModelRegistry.id != current_active.id)
            target = q.first()
            if not target:
                raise ValueError(f"No rollback target found for domain '{domain}'")

        if current_active is not None and current_active.id != target.id:
            current_active.stage = "retired"

        target.stage = "active"
        target.promoted_at = datetime.now(timezone.utc)
        if notes:
            target.notes = f"{target.notes or ''}\nrollback_note: {notes}".strip()

        db.commit()
        db.refresh(target)
        self._apply_model_runtime(domain=domain, artifact_path=target.artifact_path)
        return {
            "domain": domain,
            "rolled_back_from_registry_id": current_active.id if current_active is not None else None,
            "active_registry": target,
        }

    def activate_active_models(
        self,
        *,
        db: Session,
        domains: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant = self._resolve_tenant_id(tenant_id)
        target_domains = domains or ["sql", "spam", "file"]
        out: Dict[str, Any] = {}
        for domain in target_domains:
            if domain not in {"sql", "spam", "file"}:
                out[domain] = {"applied": False, "reason": "unsupported_domain"}
                continue

            active_candidates = (
                db.query(DefenderModelRegistry)
                .filter(
                    self._tenant_scope_clause(DefenderModelRegistry, tenant),
                    DefenderModelRegistry.domain == domain,
                    DefenderModelRegistry.stage == "active",
                )
                .order_by(DefenderModelRegistry.promoted_at.desc(), DefenderModelRegistry.timestamp.desc())
                .all()
            )
            if not active_candidates:
                out[domain] = {"applied": False, "reason": "no_active_registry"}
                continue
            active = None
            for candidate in active_candidates:
                artifact_path = str(getattr(candidate, "artifact_path", "") or "")
                if artifact_path and os.path.exists(artifact_path):
                    active = candidate
                    break
            if active is None:
                active = active_candidates[0]

            applied = self._apply_model_runtime(domain=domain, artifact_path=str(active.artifact_path))
            out[domain] = {
                "applied": bool(applied),
                "registry_id": active.id,
                "version": active.version,
                "artifact_path": active.artifact_path,
                "reason": "applied" if applied else "runtime_apply_failed",
            }
        return out

    def _apply_model_runtime(self, domain: str, artifact_path: str) -> bool:
        if not artifact_path or not os.path.exists(artifact_path):
            logger.warning(f"Runtime model activation skipped (artifact missing): {artifact_path}")
            return False
        if domain == "sql":
            try:
                query_service = QueryAnalysisService.get_instance()
                query_service._query_validation_pipeline = joblib.load(artifact_path)  # type: ignore[attr-defined]
                return True
            except Exception as exc:
                logger.warning(f"Runtime SQL model swap skipped: {exc}")
                return False
        elif domain == "spam":
            try:
                spam_service = SpamDetectionService.get_instance()
                spam_service._spam_detection_pipeline = joblib.load(artifact_path)  # type: ignore[attr-defined]
                return True
            except Exception as exc:
                logger.warning(f"Runtime spam model swap skipped: {exc}")
                return False
        elif domain == "file":
            try:
                file_service = FileAnalysisService.get_instance()
                file_service._ml_model = joblib.load(artifact_path)  # type: ignore[attr-defined]
                return True
            except Exception as exc:
                logger.warning(f"Runtime file model swap skipped: {exc}")
                return False
        return False

    def _normalize_text(self, text: str) -> str:
        return re.sub(r"\s+", " ", str(text or "").lower()).strip()

    def _merge_binary_samples(self, datasets: List[Tuple[List[str], List[int]]]) -> Tuple[List[str], List[int]]:
        merged: Dict[str, int] = {}
        for X, y in datasets:
            for text, label in zip(X, y):
                norm = self._normalize_text(text)
                if not norm:
                    continue
                label_int = 1 if int(label) > 0 else 0
                if norm in merged:
                    merged[norm] = max(merged[norm], label_int)
                else:
                    merged[norm] = label_int
        if not merged:
            return [], []
        X_out = list(merged.keys())
        y_out = [int(merged[t]) for t in X_out]
        return X_out, y_out

    def _load_curated_corpus(self, domain: str) -> Tuple[List[str], List[int]]:
        mapping = {
            "sql": ("sql", "sql_corpus_latest.csv"),
            "file": ("file", "file_corpus_latest.csv"),
            "spam": ("phishing", "phishing_corpus_latest.csv"),
        }
        subdir_file = mapping.get(domain)
        if subdir_file is None:
            return [], []
        subdir, filename = subdir_file
        latest = self._corpus_dir / subdir / "processed" / filename
        if not latest.exists():
            return [], []
        try:
            df = pd.read_csv(latest)
        except Exception as exc:
            logger.warning(f"Failed to read curated {domain} corpus ({latest}): {exc}")
            return [], []
        if "text" not in df.columns or "label" not in df.columns:
            logger.warning(f"Curated {domain} corpus missing required columns text/label: {latest}")
            return [], []
        rows = df.dropna(subset=["text", "label"]).copy()
        X: List[str] = []
        y: List[int] = []
        for _, row in rows.iterrows():
            text = self._normalize_text(str(row.get("text") or ""))
            if not text:
                continue
            try:
                label = 1 if int(row.get("label")) > 0 else 0
            except Exception:
                continue
            X.append(text)
            y.append(label)
        if X:
            logger.info(f"Loaded curated {domain} corpus: {latest} ({len(X)} samples)")
        return X, y

    def _load_sql_base_dataset(self) -> Tuple[List[str], List[int]]:
        curated_X, curated_y = self._load_curated_corpus("sql")
        normal_file = self._raw_dir / "normal_queries.csv"
        malicious_file = self._raw_dir / "malicious_queries.csv"

        def read_lines(path: Path) -> List[str]:
            if not path.exists():
                return []
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            out: List[str] = []
            for raw in lines[1:]:
                s = (raw or "").strip()
                if not s:
                    continue
                if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
                    s = s[1:-1]
                out.append(s)
            return out

        normal = read_lines(normal_file)
        malicious = read_lines(malicious_file)
        legacy_X = [self._normalize_text(x) for x in (normal + malicious)]
        legacy_y = [0] * len(normal) + [1] * len(malicious)
        return self._merge_binary_samples([(curated_X, curated_y), (legacy_X, legacy_y)])

    def _load_spam_base_dataset(self) -> Tuple[List[str], List[int]]:
        curated_X, curated_y = self._load_curated_corpus("spam")
        emails_file = self._raw_dir / "emails" / "emails.csv"
        if not emails_file.exists():
            return self._merge_binary_samples([(curated_X, curated_y)])
        df = pd.read_csv(emails_file)
        if "text" not in df.columns or "spam" not in df.columns:
            return self._merge_binary_samples([(curated_X, curated_y)])
        df = df.dropna(subset=["text"]).copy()
        legacy_X = [self._normalize_text(str(x)) for x in df["text"].tolist()]
        legacy_y = [int(x) for x in df["spam"].astype(int).tolist()]
        return self._merge_binary_samples([(curated_X, curated_y), (legacy_X, legacy_y)])

    def _load_file_base_dataset(self) -> Tuple[List[str], List[int]]:
        curated_X, curated_y = self._load_curated_corpus("file")
        roots = [
            self._raw_dir / "files_for_analysis_training" / "malicious_samples",
            self._raw_dir / "files_for_analysis_training" / "benign_samples",
        ]
        malicious_root = roots[0]
        benign_root = roots[1]

        max_bytes = int(os.getenv("DEFENDER_FILE_MAX_BYTES_PER_SAMPLE", "1000000"))

        def collect(root: Path, label: int) -> Tuple[List[str], List[int]]:
            X_local: List[str] = []
            y_local: List[int] = []
            if not root.exists():
                return X_local, y_local
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                try:
                    raw = p.read_bytes()[: max(1024, max_bytes)]
                    text = raw.decode("utf-8", errors="ignore")
                    norm = self._normalize_text(text)
                    if not norm:
                        continue
                    X_local.append(norm)
                    y_local.append(label)
                except Exception:
                    continue
            return X_local, y_local

        mal_X, mal_y = collect(malicious_root, 1)
        ben_X, ben_y = collect(benign_root, 0)
        return self._merge_binary_samples([(curated_X, curated_y), (mal_X + ben_X, mal_y + ben_y)])

    def _load_feedback_records(self, db: Session, domain: str, *, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        tenant = self._resolve_tenant_id(tenant_id)
        rows = (
            db.query(DefenderFeedback)
            .filter(DefenderFeedback.tenant_id == tenant, DefenderFeedback.domain == domain)
            .order_by(DefenderFeedback.timestamp.desc())
            .all()
        )
        records: List[Dict[str, Any]] = []
        dedup: set[str] = set()
        for row in rows:
            payload = row.sample_payload or {}
            raw = ""
            if domain == "sql":
                raw = str(payload.get("query") or "")
                label = 1 if str(row.true_label).lower().startswith("mal") else 0
            elif domain == "spam":
                raw = f"{payload.get('subject') or ''} {payload.get('body_text') or ''}".strip()
                label = 1 if str(row.true_label).lower() == "spam" else 0
            elif domain == "file":
                observed = str(payload.get("observed_text") or "").strip()
                filename = str(payload.get("filename") or "").strip()
                action = str(payload.get("recommended_action") or "").strip()
                raw = observed or f"filename:{filename} action:{action} notes:{row.notes or ''}".strip()
                label = 0 if str(row.true_label).lower() == "safe" else 1
            else:
                continue

            text = self._normalize_text(raw)
            if not text:
                continue

            key = f"{domain}:{label}:{text[:512]}"
            if key in dedup:
                continue
            dedup.add(key)

            records.append(
                {
                    "feedback_id": row.id,
                    "analysis_id": row.analysis_id,
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                    "source": row.source or "human",
                    "predicted_label": row.predicted_label,
                    "true_label": row.true_label,
                    "confidence": row.confidence,
                    "text": text,
                    "label": int(label),
                }
            )

        return records

    def _load_feedback_samples(
        self,
        db: Session,
        domain: str,
        *,
        tenant_id: Optional[str] = None,
    ) -> Tuple[List[str], List[int], List[str]]:
        records = self._load_feedback_records(db=db, domain=domain, tenant_id=tenant_id)
        return (
            [r["text"] for r in records],
            [int(r["label"]) for r in records],
            [str(r["feedback_id"]) for r in records],
        )

    def _compute_binary_metrics(self, y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
        from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

        if not y_true:
            return {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "tn": 0,
                "fp": 0,
                "fn": 0,
                "tp": 0,
                "false_positive_rate": 0.0,
                "sample_size": 0,
            }

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
        fpr = float(fp) / float(fp + tn) if (fp + tn) else 0.0
        return {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "false_positive_rate": fpr,
            "sample_size": len(y_true),
        }

    def _train_text_binary_classifier(self, X: List[str], y: List[int]) -> Tuple[Any, Dict[str, Any]]:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline

        min_records = int(os.getenv("DEFENDER_MIN_TRAIN_RECORDS", "8"))
        if len(X) < min_records:
            raise ValueError(f"Insufficient samples: at least {min_records} records required.")
        if len(set(y)) < 2:
            raise ValueError("Insufficient class diversity for training.")

        idx = list(range(len(X)))
        idx_train, idx_test, y_train, y_test = train_test_split(
            idx,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y,
        )
        X_train = [X[i] for i in idx_train]
        X_test = [X[i] for i in idx_test]

        pipe = Pipeline(
            steps=[
                ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=75000)),
                ("clf", LogisticRegression(max_iter=500, class_weight="balanced")),
            ]
        )
        pipe.fit(X_train, y_train)
        y_pred = [int(v) for v in pipe.predict(X_test).tolist()]
        metrics = self._compute_binary_metrics([int(v) for v in y_test], y_pred)
        metrics["train_size"] = len(X_train)
        metrics["test_size"] = len(X_test)
        metrics["total_size"] = len(X)
        return pipe, metrics

    def _evaluate_feedback_metrics(self, model: Any, feedback_records: List[Dict[str, Any]], source: Optional[str] = None) -> Dict[str, Any]:
        subset = [r for r in feedback_records if source is None or str(r.get("source") or "").lower() == source.lower()]
        if not subset:
            return {
                "sample_size": 0,
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "false_positive_rate": 0.0,
                "tn": 0,
                "fp": 0,
                "fn": 0,
                "tp": 0,
            }
        X = [str(r["text"]) for r in subset]
        y = [int(r["label"]) for r in subset]
        y_pred = [int(v) for v in model.predict(X).tolist()]
        return self._compute_binary_metrics(y, y_pred)

    def _save_labeled_dataset_artifact(
        self,
        *,
        domain: str,
        base_X: List[str],
        base_y: List[int],
        feedback_records: List[Dict[str, Any]],
        job_id: Optional[str] = None,
    ) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        tag = (job_id or str(uuid.uuid4())[:8]).replace("-", "")[:12]
        out_dir = self._pipeline_dir / domain
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"labeled_{domain}_{ts}_{tag}.csv"

        rows: List[Dict[str, Any]] = []
        for text, label in zip(base_X, base_y):
            rows.append(
                {
                    "domain": domain,
                    "text": text,
                    "label": int(label),
                    "source": "base",
                    "feedback_id": None,
                    "analysis_id": None,
                    "feedback_source": None,
                    "true_label": None,
                    "predicted_label": None,
                    "timestamp": None,
                }
            )

        for rec in feedback_records:
            rows.append(
                {
                    "domain": domain,
                    "text": rec.get("text"),
                    "label": int(rec.get("label", 0)),
                    "source": "feedback",
                    "feedback_id": rec.get("feedback_id"),
                    "analysis_id": rec.get("analysis_id"),
                    "feedback_source": rec.get("source"),
                    "true_label": rec.get("true_label"),
                    "predicted_label": rec.get("predicted_label"),
                    "timestamp": rec.get("timestamp"),
                }
            )

        df = pd.DataFrame(rows)
        df.to_csv(out_path, index=False)
        return str(out_path)

    def _save_candidate_model(self, domain: str, model: Any) -> Tuple[str, str]:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        version = f"defender-{domain}-{ts}"
        path = self._models_dir / f"{domain}_detector_{version}.joblib"
        joblib.dump(model, str(path))
        return str(path), version

    def _mark_feedback_processed(self, db: Session, feedback_ids: List[str], *, tenant_id: Optional[str] = None) -> None:
        if not feedback_ids:
            return
        tenant = self._resolve_tenant_id(tenant_id)
        rows = (
            db.query(DefenderFeedback)
            .filter(DefenderFeedback.tenant_id == tenant, DefenderFeedback.id.in_(feedback_ids))
            .all()
        )
        for row in rows:
            row.processed = True
        db.commit()

    def _get_threshold(self, domain: str, name: str, default: float) -> float:
        domain_key = f"DEFENDER_{domain.upper()}_PROMOTION_{name}"
        global_key = f"DEFENDER_PROMOTION_{name}"
        domain_default = self._PROMOTION_DEFAULTS.get(str(domain or "").lower(), {}).get(name)
        effective_default = float(domain_default if domain_default is not None else default)
        raw = os.getenv(domain_key)
        if raw is None:
            raw = os.getenv(global_key, str(effective_default))
        try:
            return float(raw)
        except Exception:
            return effective_default

    def _get_gate_bool(self, domain: str, name: str, default: bool) -> bool:
        domain_key = f"DEFENDER_{domain.upper()}_PROMOTION_{name}"
        global_key = f"DEFENDER_PROMOTION_{name}"
        raw = os.getenv(domain_key)
        if raw is None:
            raw = os.getenv(global_key)
        if raw is None:
            return bool(default)
        token = str(raw).strip().lower()
        if token in {"1", "true", "yes", "on"}:
            return True
        if token in {"0", "false", "no", "off"}:
            return False
        return bool(default)

    def _evaluate_promotion_gate(
        self,
        db: Session,
        domain: str,
        candidate_metrics: Dict[str, Any],
        *,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant = self._resolve_tenant_id(tenant_id)
        thresholds = {
            "min_precision": self._get_threshold(domain, "MIN_PRECISION", 0.60),
            "min_recall": self._get_threshold(domain, "MIN_RECALL", 0.60),
            "min_f1": self._get_threshold(domain, "MIN_F1", 0.60),
            "max_fpr": self._get_threshold(domain, "MAX_FPR", 0.35 if domain != "file" else 0.25),
            "min_f1_delta": self._get_threshold(domain, "MIN_F1_DELTA", 0.0),
            "max_fpr_delta": self._get_threshold(domain, "MAX_FPR_DELTA", 1.0),
            "max_recall_drop": self._get_threshold(domain, "MAX_RECALL_DROP", 1.0),
            "min_eval_samples": self._get_threshold(domain, "MIN_EVAL_SAMPLES", 0.0),
            "min_positive_eval_samples": self._get_threshold(domain, "MIN_POSITIVE_EVAL_SAMPLES", 0.0),
            "min_negative_eval_samples": self._get_threshold(domain, "MIN_NEGATIVE_EVAL_SAMPLES", 0.0),
            "allow_fpr_win_near_tie": self._get_gate_bool(
                domain, "ALLOW_FPR_WIN_NEAR_TIE", domain == "spam"
            ),
            "f1_tie_tolerance": self._get_threshold(
                domain, "F1_TIE_TOLERANCE", 0.001 if domain == "spam" else 0.0
            ),
            "min_fpr_improvement": self._get_threshold(
                domain, "MIN_FPR_IMPROVEMENT", 0.001 if domain == "spam" else 0.0
            ),
            "max_recall_drop_for_fpr_win": self._get_threshold(
                domain, "MAX_RECALL_DROP_FOR_FPR_WIN", 0.03 if domain == "spam" else 0.0
            ),
        }

        reasons: List[str] = []
        cand_precision = float(candidate_metrics.get("precision") or 0.0)
        cand_recall = float(candidate_metrics.get("recall") or 0.0)
        cand_f1 = float(candidate_metrics.get("f1") or 0.0)
        cand_fpr = float(candidate_metrics.get("false_positive_rate") or 0.0)
        eval_sample_size = candidate_metrics.get("sample_size")
        if not isinstance(eval_sample_size, (int, float)):
            eval_sample_size = candidate_metrics.get("test_size")
        positive_eval_samples = None
        negative_eval_samples = None
        if all(isinstance(candidate_metrics.get(k), (int, float)) for k in ("tp", "fn")):
            positive_eval_samples = float(candidate_metrics.get("tp") or 0.0) + float(candidate_metrics.get("fn") or 0.0)
        if all(isinstance(candidate_metrics.get(k), (int, float)) for k in ("tn", "fp")):
            negative_eval_samples = float(candidate_metrics.get("tn") or 0.0) + float(candidate_metrics.get("fp") or 0.0)
        override = {
            "applied": False,
            "reason": None,
            "checks": {},
        }

        if cand_precision < thresholds["min_precision"]:
            reasons.append(f"precision<{thresholds['min_precision']:.3f}")
        if cand_recall < thresholds["min_recall"]:
            reasons.append(f"recall<{thresholds['min_recall']:.3f}")
        if cand_f1 < thresholds["min_f1"]:
            reasons.append(f"f1<{thresholds['min_f1']:.3f}")
        if cand_fpr > thresholds["max_fpr"]:
            reasons.append(f"fpr>{thresholds['max_fpr']:.3f}")
        if isinstance(eval_sample_size, (int, float)) and float(eval_sample_size) < thresholds["min_eval_samples"]:
            reasons.append(f"eval_samples<{thresholds['min_eval_samples']:.0f}")
        if (
            positive_eval_samples is not None
            and positive_eval_samples < thresholds["min_positive_eval_samples"]
        ):
            reasons.append(f"positive_eval_samples<{thresholds['min_positive_eval_samples']:.0f}")
        if (
            negative_eval_samples is not None
            and negative_eval_samples < thresholds["min_negative_eval_samples"]
        ):
            reasons.append(f"negative_eval_samples<{thresholds['min_negative_eval_samples']:.0f}")

        current = (
            db.query(DefenderModelRegistry)
            .filter(
                DefenderModelRegistry.tenant_id == tenant,
                DefenderModelRegistry.domain == domain,
                DefenderModelRegistry.stage == "active",
            )
            .order_by(DefenderModelRegistry.promoted_at.desc(), DefenderModelRegistry.timestamp.desc())
            .first()
        )
        baseline = None
        if current is not None:
            current_metrics = current.metrics or {}
            curr_f1 = current_metrics.get("f1")
            curr_fpr = current_metrics.get("false_positive_rate")
            curr_recall = current_metrics.get("recall")
            if isinstance(curr_f1, (int, float)) and cand_f1 < (float(curr_f1) + thresholds["min_f1_delta"]):
                reasons.append(f"f1_delta<{thresholds['min_f1_delta']:.3f}")
            if isinstance(curr_fpr, (int, float)) and cand_fpr > (float(curr_fpr) + thresholds["max_fpr_delta"]):
                reasons.append(f"fpr_delta>{thresholds['max_fpr_delta']:.3f}")
            if isinstance(curr_recall, (int, float)) and cand_recall < (float(curr_recall) - thresholds["max_recall_drop"]):
                reasons.append(f"recall_delta<-{thresholds['max_recall_drop']:.3f}")

            if (
                bool(thresholds["allow_fpr_win_near_tie"])
                and isinstance(curr_f1, (int, float))
                and isinstance(curr_fpr, (int, float))
            ):
                curr_f1_val = float(curr_f1)
                curr_fpr_val = float(curr_fpr)
                curr_recall_val = float(curr_recall) if isinstance(curr_recall, (int, float)) else None
                f1_gap = curr_f1_val - cand_f1
                fpr_improvement = curr_fpr_val - cand_fpr
                recall_delta = cand_recall - curr_recall_val if curr_recall_val is not None else None
                f1_near_tie = cand_f1 >= (curr_f1_val - float(thresholds["f1_tie_tolerance"]))
                fpr_win = fpr_improvement >= float(thresholds["min_fpr_improvement"])
                recall_ok = (
                    True
                    if curr_recall_val is None
                    else recall_delta >= -float(thresholds["max_recall_drop_for_fpr_win"])
                )

                f1_delta_reasons = [r for r in reasons if str(r).startswith("f1_delta<")]
                if f1_delta_reasons and f1_near_tie and fpr_win and recall_ok:
                    reasons = [r for r in reasons if not str(r).startswith("f1_delta<")]
                    override = {
                        "applied": True,
                        "reason": "fpr_win_with_near_f1_tie",
                        "checks": {
                            "f1_gap": f1_gap,
                            "f1_tie_tolerance": float(thresholds["f1_tie_tolerance"]),
                            "fpr_improvement": fpr_improvement,
                            "min_fpr_improvement": float(thresholds["min_fpr_improvement"]),
                            "recall_delta": recall_delta,
                            "max_recall_drop_for_fpr_win": float(thresholds["max_recall_drop_for_fpr_win"]),
                        },
                    }
                else:
                    override = {
                        "applied": False,
                        "reason": None,
                        "checks": {
                            "f1_gap": f1_gap,
                            "f1_tie_tolerance": float(thresholds["f1_tie_tolerance"]),
                            "fpr_improvement": fpr_improvement,
                            "min_fpr_improvement": float(thresholds["min_fpr_improvement"]),
                            "recall_delta": recall_delta,
                            "max_recall_drop_for_fpr_win": float(thresholds["max_recall_drop_for_fpr_win"]),
                            "f1_near_tie": bool(f1_near_tie),
                            "fpr_win": bool(fpr_win),
                            "recall_ok": bool(recall_ok),
                        },
                    }
            baseline = {
                "registry_id": current.id,
                "f1": float(curr_f1) if isinstance(curr_f1, (int, float)) else None,
                "recall": float(curr_recall) if isinstance(curr_recall, (int, float)) else None,
                "false_positive_rate": float(curr_fpr) if isinstance(curr_fpr, (int, float)) else None,
            }

        return {
            "passed": len(reasons) == 0,
            "reasons": reasons,
            "thresholds": thresholds,
            "override": override,
            "candidate": {
                "precision": cand_precision,
                "recall": cand_recall,
                "f1": cand_f1,
                "false_positive_rate": cand_fpr,
                "eval_sample_size": float(eval_sample_size) if isinstance(eval_sample_size, (int, float)) else None,
                "positive_eval_samples": positive_eval_samples,
                "negative_eval_samples": negative_eval_samples,
            },
            "baseline_active": baseline,
        }

    def create_training_job(
        self,
        db: Session,
        *,
        domain: str,
        min_feedback_samples: int,
        promote_if_better: bool,
        requested_by: Optional[str] = None,
        notes: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> DefenderTrainingJob:
        tenant = self._resolve_tenant_id(tenant_id)
        job = DefenderTrainingJob(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            tenant_id=tenant,
            status="queued",
            domain=domain,
            requested_by=requested_by,
            min_feedback_samples=min_feedback_samples,
            promote_if_better=promote_if_better,
            notes=notes,
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def list_training_jobs(
        self,
        db: Session,
        *,
        limit: int = 50,
        domain: Optional[str] = None,
        status: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[DefenderTrainingJob]:
        tenant = self._resolve_tenant_id(tenant_id)
        q = db.query(DefenderTrainingJob).filter(DefenderTrainingJob.tenant_id == tenant)
        if domain:
            q = q.filter(DefenderTrainingJob.domain == domain)
        if status:
            q = q.filter(DefenderTrainingJob.status == status)
        return q.order_by(DefenderTrainingJob.timestamp.desc()).limit(max(1, min(limit, 200))).all()

    def get_training_job(self, db: Session, job_id: str, *, tenant_id: Optional[str] = None) -> Optional[DefenderTrainingJob]:
        tenant = self._resolve_tenant_id(tenant_id)
        return (
            db.query(DefenderTrainingJob)
            .filter(DefenderTrainingJob.tenant_id == tenant, DefenderTrainingJob.id == job_id)
            .first()
        )

    def run_training_job(self, db: Session, job_id: str, *, tenant_id: Optional[str] = None) -> DefenderTrainingJob:
        tenant = self._resolve_tenant_id(tenant_id)
        job = self.get_training_job(db=db, job_id=job_id, tenant_id=tenant)
        if not job:
            raise ValueError(f"Training job not found: {job_id}")

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(job)

        try:
            results = self.retrain_and_register_candidates(
                db=db,
                domain=job.domain,
                min_feedback_samples=int(job.min_feedback_samples),
                promote_if_better=bool(job.promote_if_better),
                notes=job.notes,
                job_id=job.id,
                tenant_id=tenant,
            )
            has_errors = any(str(r.get("status") or "").lower() == "error" for r in results)
            job.status = "failed" if has_errors else "succeeded"
            job.finished_at = datetime.now(timezone.utc)
            job.result = {"results": results}
            db.commit()
            db.refresh(job)
            return job
        except Exception as exc:
            job.status = "failed"
            job.finished_at = datetime.now(timezone.utc)
            job.result = {"error": str(exc)}
            db.commit()
            db.refresh(job)
            raise

    def retrain_and_register_candidates(
        self,
        *,
        db: Session,
        domain: str = "all",
        min_feedback_samples: int = 5,
        promote_if_better: bool = False,
        notes: Optional[str] = None,
        job_id: Optional[str] = None,
        allow_corpus_only: Optional[bool] = None,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        tenant = self._resolve_tenant_id(tenant_id)
        if allow_corpus_only is None:
            allow_corpus_only = str(os.getenv("DEFENDER_ALLOW_CORPUS_ONLY", "false")).strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
        targets = ["sql", "spam", "file"] if domain == "all" else [domain]
        results: List[Dict[str, Any]] = []

        for d in targets:
            if d not in {"sql", "spam", "file"}:
                results.append({"domain": d, "status": "skipped", "details": {"reason": "unsupported_domain"}})
                continue
            try:
                if d == "sql":
                    base_X, base_y = self._load_sql_base_dataset()
                elif d == "spam":
                    base_X, base_y = self._load_spam_base_dataset()
                else:
                    base_X, base_y = self._load_file_base_dataset()

                feedback_records = self._load_feedback_records(db=db, domain=d, tenant_id=tenant)
                feedback_ids = [str(r["feedback_id"]) for r in feedback_records if r.get("feedback_id")]
                corpus_only_bootstrap = len(feedback_records) < min_feedback_samples and bool(allow_corpus_only)
                if len(feedback_records) < min_feedback_samples and not corpus_only_bootstrap:
                    results.append(
                        {
                            "domain": d,
                            "status": "skipped",
                            "details": {
                                "reason": "insufficient_feedback",
                                "feedback_samples": len(feedback_records),
                                "required": min_feedback_samples,
                            },
                        }
                    )
                    continue

                dataset_artifact = self._save_labeled_dataset_artifact(
                    domain=d,
                    base_X=base_X,
                    base_y=base_y,
                    feedback_records=feedback_records,
                    job_id=job_id,
                )

                X = base_X + [str(r["text"]) for r in feedback_records]
                y = base_y + [int(r["label"]) for r in feedback_records]
                model, metrics = self._train_text_binary_classifier(X, y)
                artifact_path, version = self._save_candidate_model(d, model)
                model_name = f"{d}_detector_logreg_tfidf"
                if d == "file":
                    model_name = "file_text_detector_logreg_tfidf"

                feedback_eval = {
                    "all_feedback": self._evaluate_feedback_metrics(model=model, feedback_records=feedback_records, source=None),
                    "analyst_feedback": self._evaluate_feedback_metrics(model=model, feedback_records=feedback_records, source="human"),
                    "system_feedback": self._evaluate_feedback_metrics(model=model, feedback_records=feedback_records, source="system"),
                }
                metrics["feedback_evaluation"] = feedback_eval
                metrics["dataset"] = {
                    "base_samples": len(base_X),
                    "feedback_samples": len(feedback_records),
                    "total_samples": len(X),
                    "artifact_path": dataset_artifact,
                    "job_id": job_id,
                }

                gate = self._evaluate_promotion_gate(db=db, domain=d, candidate_metrics=metrics, tenant_id=tenant)
                metrics["promotion_gate"] = gate

                candidate = self._register_candidate(
                    db=db,
                    tenant_id=tenant,
                    domain=d,
                    model_name=model_name,
                    version=version,
                    artifact_path=artifact_path,
                    metrics=metrics,
                    notes=notes,
                )
                self._mark_feedback_processed(db, feedback_ids, tenant_id=tenant)

                promoted = False
                if promote_if_better and bool(gate.get("passed", False)):
                    self._promote_candidate(db, candidate, notes="Auto-promoted by DefenderAIService.")
                    promoted = True

                results.append(
                    {
                        "domain": d,
                        "status": "trained",
                        "details": {
                            "feedback_samples": len(feedback_records),
                            "required_feedback_samples": min_feedback_samples,
                            "allow_corpus_only": bool(allow_corpus_only),
                            "corpus_only_bootstrap": corpus_only_bootstrap,
                            "dataset_size": len(X),
                            "dataset_artifact": dataset_artifact,
                            "version": version,
                            "artifact_path": artifact_path,
                            "metrics": metrics,
                            "promoted": promoted,
                            "registry_id": candidate.id,
                            "promotion_gate_passed": bool(gate.get("passed", False)),
                        },
                    }
                )
            except Exception as exc:
                logger.error(f"Defender retraining failed for domain '{d}': {exc}", exc_info=True)
                results.append({"domain": d, "status": "error", "details": {"error": str(exc)}})

        return results
