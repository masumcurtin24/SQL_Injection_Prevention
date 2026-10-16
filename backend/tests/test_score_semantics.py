from backend.server.schemas.responses import XAIExplanation
from backend.services.explainability_contract import complete_explainability_contract
from backend.services.file_analysis_service import FileAnalysisService
from backend.services.query_analysis_service import QueryAnalysisService


def test_sql_allowed_low_risk_confidence_inverts_risk():
    risk = 0.08
    confidence = QueryAnalysisService._decision_confidence_from_risk(
        risk_score=risk,
        decision="ALLOW",
    )
    assert risk == 0.08
    assert confidence == 0.92


def test_sql_blocked_high_risk_confidence_stays_separate_from_ood():
    risk = 0.94
    confidence = QueryAnalysisService._decision_confidence_from_risk(
        risk_score=risk,
        decision="BLOCK_IMMEDIATE",
    )
    penalized = QueryAnalysisService._decision_confidence_from_risk(
        risk_score=risk,
        decision="BLOCK_IMMEDIATE",
        ood_score=0.5,
    )
    assert confidence == 0.94
    assert penalized == confidence
    assert risk == 0.94


def test_file_allowed_low_risk_confidence_inverts_risk():
    risk = 0.10
    confidence = FileAnalysisService._decision_confidence_from_file_risk(
        risk_score=risk,
        recommended_action="ALLOW_UPLOAD",
        overall_status="Safe",
    )
    assert risk == 0.10
    assert confidence == 0.90


def test_file_quarantine_high_risk_confidence_stays_separate_from_ood():
    risk = 0.95
    confidence = FileAnalysisService._decision_confidence_from_file_risk(
        risk_score=risk,
        recommended_action="BLOCK_AND_QUARANTINE",
        overall_status="Malicious",
    )
    penalized = FileAnalysisService._decision_confidence_from_file_risk(
        risk_score=risk,
        recommended_action="BLOCK_AND_QUARANTINE",
        overall_status="Malicious",
        ood_score=0.4,
    )
    assert confidence == 0.95
    assert penalized == confidence
    assert risk == 0.95


def test_explanation_payload_separates_risk_from_decision_confidence_alias():
    explanation = XAIExplanation(
        decision="ALLOW_UPLOAD",
        threat_category="File upload scanning",
        risk_score=0.10,
        decision_confidence=0.90,
        confidence=0.90,
    )
    complete_explainability_contract(explanation, domain="file")
    payload = explanation.model_dump()
    assert payload["risk_score"] == 0.10
    assert payload["decision_confidence"] == 0.90
    assert payload["confidence"] == 0.90
    assert payload["score_semantics"]["risk_label"] == "File Risk"
    assert payload["score_semantics"]["decision_confidence"] == 0.90
