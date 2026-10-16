import pytest

from backend.services.ai_reliability_service import assess_ai_reliability
from backend.services.incident_response_service import IncidentResponseService
from backend.services.spam_detection_service import SpamDetectionService


def test_grey_zone_spam_display_routes_to_review():
    risk = 0.5062
    confidence = 0.5062
    uncertainty, components, _missing = SpamDetectionService._compute_spam_uncertainty(
        spam_score=risk,
        suspicious_threshold=0.50,
        ood_score=0.10,
        component_scores={
            "classical": 0.48,
            "transformer": 0.54,
            "heuristic": 0.51,
            "reputation": 0.45,
        },
        transformer_available=True,
        reputation_available=True,
        headers_available=True,
    )
    reliability = assess_ai_reliability(
        domain="spam",
        risk_score=risk,
        decision_confidence=confidence,
        uncertainty_score=uncertainty,
        ood_score=0.10,
        fidelity_score=0.625,
        final_action="FLAG_FOR_REVIEW",
    )
    display = SpamDetectionService._classify_spam_decision_display(
        spam_score=risk,
        decision_confidence=confidence,
        uncertainty_score=uncertainty,
        ood_score=0.10,
        ai_reliability=reliability,
        category="suspicious",
        suspicious_threshold=0.50,
    )

    assert components["threshold_margin_uncertainty"] > 0.90
    assert uncertainty > 0.40
    assert reliability.review_required is True
    assert reliability.recommended_handling == "review"
    assert display.status_label == "Needs Review — Possible Spam/Phishing"
    assert display.hard_detection is False
    assert "Spam detected" not in display.status_label


def test_safe_email_display_is_not_spam_when_reliable():
    reliability = assess_ai_reliability(
        domain="spam",
        risk_score=0.08,
        decision_confidence=0.92,
        uncertainty_score=0.08,
        ood_score=0.02,
        fidelity_score=0.95,
        final_action="ALLOW",
    )
    display = SpamDetectionService._classify_spam_decision_display(
        spam_score=0.08,
        decision_confidence=0.92,
        uncertainty_score=0.08,
        ood_score=0.02,
        ai_reliability=reliability,
        category="safe",
        suspicious_threshold=0.50,
    )

    assert reliability.review_required is False
    assert reliability.recommended_handling == "allow"
    assert display.status_label == "Not Spam"
    assert display.status_color == "green"


def test_high_risk_phishing_display_can_be_hard_detection():
    reliability = assess_ai_reliability(
        domain="spam",
        risk_score=0.91,
        decision_confidence=0.91,
        uncertainty_score=0.10,
        ood_score=0.05,
        fidelity_score=0.90,
        final_action="BLOCK_EMAIL",
    )
    display = SpamDetectionService._classify_spam_decision_display(
        spam_score=0.91,
        decision_confidence=0.91,
        uncertainty_score=0.10,
        ood_score=0.05,
        ai_reliability=reliability,
        category="blocked",
        suspicious_threshold=0.50,
    )

    assert reliability.review_required is False
    assert reliability.recommended_handling == "block"
    assert display.status_label == "High-Risk Phishing Detected"
    assert display.hard_detection is True


def test_high_risk_courier_phishing_review_gate_keeps_specific_status():
    reliability = assess_ai_reliability(
        domain="spam",
        risk_score=0.85,
        decision_confidence=0.85,
        uncertainty_score=0.45,
        ood_score=0.05,
        fidelity_score=0.72,
        final_action="BLOCK_EMAIL",
        rule_hits=["courier_customs_fee_phishing", "courier_brand_domain_mismatch"],
    )
    display = SpamDetectionService._classify_spam_decision_display(
        spam_score=0.85,
        decision_confidence=0.85,
        uncertainty_score=0.45,
        ood_score=0.05,
        ai_reliability=reliability,
        category="blocked",
        suspicious_threshold=0.50,
        fraud_category="courier_customs_fee_phishing",
    )

    assert reliability.review_required is True
    assert display.status_label == "High-Risk Courier/Customs Fee Phishing - Review Required"
    assert display.hard_detection is False
    assert display.review_required is True


def test_high_risk_payroll_phishing_is_not_forced_to_review_by_missing_header():
    risk = 0.81
    confidence = 0.81
    uncertainty, components, missing = SpamDetectionService._compute_spam_uncertainty(
        spam_score=risk,
        suspicious_threshold=0.50,
        ood_score=0.0,
        component_scores={
            "classical": 0.9995,
            "transformer": 0.6749,
            "online": 0.1087,
            "heuristic": 0.4956,
            "reputation": 0.98,
            "campaign": 0.99,
            "header": None,
            "fraud_pattern": 0.26,
        },
        component_weights={
            "classical": 0.20,
            "transformer": 0.32,
            "online": 0.10,
            "heuristic": 0.20,
            "reputation": 0.12,
            "campaign": 0.24,
            "fraud_pattern": 0.22,
        },
        transformer_available=True,
        reputation_available=True,
        headers_available=False,
        fidelity_score=0.6667,
    )
    reliability = assess_ai_reliability(
        domain="spam",
        risk_score=risk,
        decision_confidence=confidence,
        uncertainty_score=uncertainty,
        ood_score=0.0,
        fidelity_score=0.6667,
        final_action="BLOCK_EMAIL",
    )
    display = SpamDetectionService._classify_spam_decision_display(
        spam_score=risk,
        decision_confidence=confidence,
        uncertainty_score=uncertainty,
        ood_score=0.0,
        ai_reliability=reliability,
        category="blocked",
        suspicious_threshold=0.50,
    )

    assert missing == ["headers"]
    assert components["missing_component_uncertainty"] == pytest.approx(0.10)
    assert components["component_disagreement_uncertainty"] < 0.40
    assert uncertainty < 0.40
    assert reliability.review_required is False
    assert reliability.recommended_handling == "block"
    assert display.status_label == "High-Risk Phishing Detected"
    assert display.hard_detection is True


def test_block_email_action_maps_to_block_request():
    actions = IncidentResponseService().plan_actions(
        domain="spam",
        suggested_action="BLOCK_EMAIL",
        risk_level="High",
    )

    assert "block_request" in actions
    assert "notify_soc" in actions
    assert "domain_block_request" in actions
    assert "url_block_request" in actions
    assert "queue_review" not in actions


def test_adversarial_spam_signal_forces_review_display():
    reliability = assess_ai_reliability(
        domain="spam",
        risk_score=0.72,
        decision_confidence=0.72,
        uncertainty_score=0.20,
        ood_score=0.10,
        fidelity_score=0.90,
        final_action="FLAG_AS_SPAM",
        rule_hits=["sender_punycode"],
    )
    display = SpamDetectionService._classify_spam_decision_display(
        spam_score=0.72,
        decision_confidence=0.72,
        uncertainty_score=0.20,
        ood_score=0.10,
        ai_reliability=reliability,
        category="suspicious",
        suspicious_threshold=0.50,
    )

    assert reliability.adversarial_suspicion is True
    assert reliability.review_required is True
    assert reliability.recommended_handling == "review"
    assert display.status_label == "Needs Review — Possible Spam/Phishing"
    assert display.hard_detection is False


def test_review_actions_do_not_recommend_automatic_sender_blocking():
    actions = SpamDetectionService._spam_suggested_actions(
        recommended_handling="review",
        review_required=True,
    )

    assert actions[0] == "Route to analyst review before blocking."
    assert any("Do not automatically block sender/domain" in item for item in actions)
    assert not any(item.startswith("Block sender") for item in actions)


def test_uncertainty_and_reliability_do_not_mutate_scores():
    spam_score = 0.5062
    decision_confidence = 0.5062
    uncertainty, _components, _missing = SpamDetectionService._compute_spam_uncertainty(
        spam_score=spam_score,
        suspicious_threshold=0.50,
        ood_score=0.10,
        component_scores={"classical": 0.48, "transformer": 0.54},
        transformer_available=True,
        reputation_available=True,
        headers_available=True,
    )
    _ = assess_ai_reliability(
        domain="spam",
        risk_score=spam_score,
        decision_confidence=decision_confidence,
        uncertainty_score=uncertainty,
        ood_score=0.10,
        fidelity_score=0.75,
        final_action="FLAG_FOR_REVIEW",
    )

    assert spam_score == pytest.approx(0.5062)
    assert decision_confidence == pytest.approx(0.5062)
