from __future__ import annotations

import uuid
from datetime import datetime, timezone

from backend.core.database import SessionLocal, create_db_tables, ensure_runtime_schema_compatibility
from backend.core.models import DefenderModelRegistry
from backend.services.defender_ai_service import DefenderAIService
from backend.services.spam_detection_service import SpamDetectionService


def _defender_service() -> DefenderAIService:
    try:
        return DefenderAIService.get_instance()
    except Exception:
        return DefenderAIService()


def _insert_active_spam_registry(*, f1: float, recall: float, fpr: float) -> str:
    create_db_tables()
    ensure_runtime_schema_compatibility()
    registry_id = str(uuid.uuid4())
    now = datetime(2099, 1, 1, tzinfo=timezone.utc)
    with SessionLocal() as db:
        row = DefenderModelRegistry(
            id=registry_id,
            timestamp=now,
            domain="spam",
            model_name="spam_detector_logreg_tfidf",
            version=f"active-{registry_id[:8]}",
            stage="active",
            artifact_path=f"C:\\tmp\\spam-active-{registry_id[:8]}.joblib",
            promoted_at=now,
            notes="test baseline",
        )
        row.metrics = {
            "precision": 0.99,
            "recall": float(recall),
            "f1": float(f1),
            "false_positive_rate": float(fpr),
        }
        db.add(row)
        db.commit()
    return registry_id


def test_spam_gate_allows_near_f1_tie_when_fpr_improves(monkeypatch):
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_ALLOW_FPR_WIN_NEAR_TIE", "true")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MIN_F1_DELTA", "0.0")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_F1_TIE_TOLERANCE", "0.001")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MIN_FPR_IMPROVEMENT", "0.001")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MAX_RECALL_DROP_FOR_FPR_WIN", "0.010")

    _insert_active_spam_registry(f1=0.9858, recall=0.9820, fpr=0.0096)
    service = _defender_service()

    with SessionLocal() as db:
        gate = service._evaluate_promotion_gate(
            db=db,
            domain="spam",
            candidate_metrics={
                "precision": 0.9884,
                "recall": 0.9817,
                "f1": 0.9851,
                "false_positive_rate": 0.0056,
            },
        )

    assert gate["passed"] is True
    assert gate["override"]["applied"] is True
    assert gate["override"]["reason"] == "fpr_win_with_near_f1_tie"
    assert not any(str(r).startswith("f1_delta<") for r in gate["reasons"])


def test_spam_gate_keeps_f1_delta_block_when_recall_drop_too_large(monkeypatch):
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_ALLOW_FPR_WIN_NEAR_TIE", "true")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MIN_F1_DELTA", "0.0")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_F1_TIE_TOLERANCE", "0.001")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MIN_FPR_IMPROVEMENT", "0.001")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MAX_RECALL_DROP_FOR_FPR_WIN", "0.010")

    _insert_active_spam_registry(f1=0.9858, recall=0.9820, fpr=0.0096)
    service = _defender_service()

    with SessionLocal() as db:
        gate = service._evaluate_promotion_gate(
            db=db,
            domain="spam",
            candidate_metrics={
                "precision": 0.9884,
                "recall": 0.9300,
                "f1": 0.9851,
                "false_positive_rate": 0.0056,
            },
        )

    assert gate["passed"] is False
    assert gate["override"]["applied"] is False
    assert any(str(r).startswith("f1_delta<") for r in gate["reasons"])


def test_spam_gate_rejects_tiny_eval_set_even_with_perfect_scores(monkeypatch):
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MIN_EVAL_SAMPLES", "10")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MIN_POSITIVE_EVAL_SAMPLES", "3")
    monkeypatch.setenv("DEFENDER_SPAM_PROMOTION_MIN_NEGATIVE_EVAL_SAMPLES", "3")

    service = _defender_service()
    with SessionLocal() as db:
        gate = service._evaluate_promotion_gate(
            db=db,
            domain="spam",
            candidate_metrics={
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "false_positive_rate": 0.0,
                "sample_size": 4,
                "tp": 2,
                "fn": 0,
                "tn": 2,
                "fp": 0,
            },
        )

    assert gate["passed"] is False
    assert "eval_samples<10" in gate["reasons"]
    assert "positive_eval_samples<3" in gate["reasons"]
    assert "negative_eval_samples<3" in gate["reasons"]


def test_spam_online_learner_ignores_non_human_feedback_by_default(monkeypatch):
    create_db_tables()
    ensure_runtime_schema_compatibility()
    service = _defender_service()
    calls = {"submit": 0}

    class _SpamService:
        def submit_feedback(self, *, text: str, label: str):
            calls["submit"] += 1
            return {"online_updated": True}

    monkeypatch.setattr(SpamDetectionService, "get_instance", classmethod(lambda cls: _SpamService()))
    monkeypatch.delenv("DEFENDER_SPAM_ONLINE_LEARN_SOURCES", raising=False)

    with SessionLocal() as db:
        result = service.submit_spam_feedback(
            db=db,
            subject="System correction notice",
            body_text="Automated low-confidence spam label",
            sender_email="system@example.org",
            true_label="Spam",
            predicted_label="Ham",
            source="system",
            notes="Synthetic feedback should not train online learner directly.",
        )

    online = result.get("online_learner") or {}
    assert calls["submit"] == 0
    assert online.get("attempted") is False
    assert online.get("reason") == "source_not_allowed"
