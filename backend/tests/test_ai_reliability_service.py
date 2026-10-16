import pytest

from backend.server.schemas.responses import AIReliabilityAssessment, XAIExplanation
from backend.services.ai_reliability_service import assess_ai_reliability


def test_reliable_safe_decision_does_not_require_review():
    assessment = assess_ai_reliability(
        domain="sql",
        risk_score=0.05,
        decision_confidence=0.95,
        uncertainty_score=0.05,
        ood_score=0.02,
        fidelity_score=0.95,
        final_action="ALLOW",
    )

    assert assessment.reliability_status == "reliable"
    assert assessment.review_required is False
    assert assessment.reliability_score > 0.85
    assert assessment.recommended_handling == "allow"


def test_low_confidence_requires_review():
    assessment = assess_ai_reliability(
        domain="sql",
        risk_score=0.20,
        decision_confidence=0.62,
        final_action="ALLOW",
    )

    assert assessment.review_required is True
    assert assessment.reliability_status == "low_confidence"
    assert "Decision confidence is below the operational threshold." in assessment.review_reasons


def test_low_confidence_block_action_is_review_first_without_policy_override():
    assessment = assess_ai_reliability(
        domain="spam",
        risk_score=0.62,
        decision_confidence=0.62,
        uncertainty_score=0.45,
        final_action="BLOCK_EMAIL",
    )

    assert assessment.review_required is True
    assert assessment.recommended_handling == "review"


def test_grey_zone_risk_requires_review():
    assessment = assess_ai_reliability(
        domain="spam",
        risk_score=0.52,
        decision_confidence=0.76,
        final_action="MONITOR",
    )

    assert assessment.review_required is True
    assert assessment.reliability_status == "needs_review"
    assert any("grey-zone" in reason for reason in assessment.review_reasons)


def test_high_ood_routes_to_out_of_distribution_review():
    assessment = assess_ai_reliability(
        domain="file",
        risk_score=0.80,
        decision_confidence=0.80,
        ood_score=0.70,
        fidelity_score=0.90,
        final_action="MONITOR",
    )

    assert assessment.review_required is True
    assert assessment.reliability_status == "out_of_distribution"
    assert any("OOD score" in reason for reason in assessment.review_reasons)


def test_low_fidelity_requires_review():
    assessment = assess_ai_reliability(
        domain="sql",
        risk_score=0.20,
        decision_confidence=0.85,
        fidelity_score=0.45,
        final_action="ALLOW",
    )

    assert assessment.review_required is True
    assert assessment.reliability_status == "needs_review"
    assert any("fidelity" in reason.lower() for reason in assessment.review_reasons)


def test_conflicting_signals_are_reported():
    assessment = assess_ai_reliability(
        domain="sql",
        risk_score=0.82,
        decision_confidence=0.82,
        score_breakdown={"heuristic_score": 0.92, "model_score": 0.12},
        final_action="BLOCK_IMMEDIATE",
    )

    assert assessment.review_required is True
    assert assessment.reliability_status == "conflicting_signals"
    assert assessment.signal_conflicts
    assert "model_low_rule_high" in assessment.signal_conflicts


def test_policy_override_has_highest_status_priority():
    assessment = assess_ai_reliability(
        domain="sql",
        risk_score=0.94,
        decision_confidence=0.94,
        rule_hits=["yaml_critical_pattern"],
        final_action="BLOCK_IMMEDIATE",
    )

    assert assessment.policy_override is True
    assert assessment.reliability_status == "policy_override"
    assert assessment.review_required is True


def test_original_scores_and_breakdown_are_not_mutated():
    risk_score = 0.08
    decision_confidence = 0.92
    score_breakdown = {"heuristic_score": 0.0, "model_score": 0.1}
    original_breakdown = dict(score_breakdown)

    assessment = assess_ai_reliability(
        domain="sql",
        risk_score=risk_score,
        decision_confidence=decision_confidence,
        score_breakdown=score_breakdown,
        final_action="ALLOW",
    )

    assert risk_score == pytest.approx(0.08)
    assert decision_confidence == pytest.approx(0.92)
    assert score_breakdown == original_breakdown
    assert assessment.reliability_factors["risk_score"] == pytest.approx(0.08)
    assert assessment.reliability_factors["decision_confidence"] == pytest.approx(0.92)
    assert "does not modify risk_score" in assessment.reliability_factors["explanation"]


def test_ai_reliability_schema_serializes_in_explanation_payload():
    assessment = assess_ai_reliability(
        domain="file",
        risk_score=0.10,
        decision_confidence=0.90,
        final_action="ALLOW_UPLOAD",
    )
    payload = AIReliabilityAssessment.model_validate(assessment.model_dump()).model_dump()

    explanation = XAIExplanation(
        decision="ALLOW_UPLOAD",
        threat_category="File upload scanning",
        risk_score=0.10,
        decision_confidence=0.90,
        confidence=0.90,
        ai_reliability=assessment,
    )
    explanation_payload = explanation.model_dump()

    assert payload["reliability_status"] == "reliable"
    assert explanation_payload["ai_reliability"]["recommended_handling"] == "allow"
