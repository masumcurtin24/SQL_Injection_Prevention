import pytest

from backend.server.schemas.responses import (
    AIReliabilityAssessment,
    XAIExplanation,
    XAIExplanationEvidence,
)
from backend.services.explainability_contract import complete_explainability_contract


def test_unified_explainability_contract_populates_score_semantics_and_rationale():
    reliability = AIReliabilityAssessment(
        reliability_score=0.033,
        reliability_status="low_confidence",
        review_required=True,
        review_reasons=["Decision confidence is below the operational threshold."],
        signal_conflicts=[],
        policy_override=False,
        adversarial_suspicion=False,
        recommended_handling="review",
        reliability_factors={"risk_score": 0.5062, "decision_confidence": 0.5062},
    )
    explanation = XAIExplanation(
        decision="FLAG_FOR_REVIEW",
        threat_category="Spam/Phishing",
        risk_score=0.5062,
        spam_risk=0.5062,
        decision_confidence=0.5062,
        confidence=0.5062,
        uncertainty_score=0.969,
        uncertainty_components={
            "threshold_margin_uncertainty": 0.969,
            "component_disagreement_uncertainty": 0.08,
            "missing_component_uncertainty": 0.1,
            "ood_score": 0.1,
        },
        fidelity_score=0.625,
        ood_score=0.1,
        ai_reliability=reliability,
        model_attributions=[
            {"component": "classical", "score": 0.48, "weight": 0.40},
            {"component": "heuristic", "score": 0.54, "weight": 0.30},
            {"component": "reputation", "score": 0.45, "weight": 0.30},
        ],
        evidence=[
            XAIExplanationEvidence(
                id="threshold_review",
                label="Near spam threshold",
                severity="medium",
                description="Risk is close to the review threshold.",
                source="policy",
                score=0.5062,
            )
        ],
        thresholds={"suspicious": 0.50, "block": 0.80},
    )

    completed = complete_explainability_contract(explanation, domain="spam")
    payload = completed.model_dump()

    assert payload["score_semantics"]["risk_label"] == "Spam/Phishing Risk"
    assert payload["score_semantics"]["risk_score"] == pytest.approx(0.5062)
    assert payload["score_semantics"]["decision_confidence"] == pytest.approx(0.5062)
    assert payload["decision_rationale"]["review_required"] is True
    assert payload["decision_rationale"]["recommended_handling"] == "review"
    assert payload["decision_rationale"]["hard_decision"] is False
    assert payload["evidence_contributions"]
    weighted = [item for item in payload["evidence_contributions"] if item["weight"] is not None]
    assert weighted[0]["normalized_contribution"] == pytest.approx(0.192)
    assert "guaranteed probability" in " ".join(payload["limitations"])
    assert "deterministic decision-governance" in " ".join(payload["limitations"])


def test_contract_does_not_mutate_risk_or_decision_confidence():
    explanation = XAIExplanation(
        decision="ALLOW_UPLOAD",
        threat_category="File upload scanning",
        risk_score=0.10,
        decision_confidence=0.90,
        confidence=0.90,
    )

    completed = complete_explainability_contract(explanation, domain="file")

    assert completed.risk_score == pytest.approx(0.10)
    assert completed.decision_confidence == pytest.approx(0.90)
    assert completed.confidence == pytest.approx(0.90)
    assert completed.score_semantics.risk_label == "File Risk"
    assert completed.decision_rationale.recommended_handling == "allow"
