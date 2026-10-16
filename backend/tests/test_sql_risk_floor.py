from __future__ import annotations

from backend.server.schemas.responses import QueryValidationResult, SQLHeuristicsResult
from backend.services.query_analysis_service import QueryAnalysisService


def _svc() -> QueryAnalysisService:
    # _combine_assessments is pure logic and does not require model initialization.
    return QueryAnalysisService.__new__(QueryAnalysisService)


def test_calibrated_path_applies_nlp_malicious_review_floor():
    svc = _svc()
    nlp = QueryValidationResult(classification_label="Malicious Signature", classification_score=0.61)
    heur = SQLHeuristicsResult(suspected=False, hits=[], heuristic_score=0.0)

    combined = svc._combine_assessments(
        anomaly_result=None,
        nlp_result=nlp,
        heuristics=heur,
        calibrated_risk_score=0.15,
        signal_contributions={"nlp": 0.1525},
        ast_features={"statement_count": 1, "has_union": False, "has_stacked_statements": False, "has_ddl": False},
    )

    assert combined.overall_risk_level == "Medium"
    assert combined.suggested_action == "FLAG_FOR_REVIEW"
    assert any("NLP malicious review floor applied" in str(r) for r in list(combined.reasoning or []))


def test_calibrated_path_applies_review_floor_at_point_fifty_boundary():
    svc = _svc()
    nlp = QueryValidationResult(classification_label="Malicious Signature", classification_score=0.50)
    heur = SQLHeuristicsResult(suspected=False, hits=[], heuristic_score=0.0)

    combined = svc._combine_assessments(
        anomaly_result=None,
        nlp_result=nlp,
        heuristics=heur,
        calibrated_risk_score=0.15,
        signal_contributions={"nlp": 0.125},
        ast_features={"statement_count": 1, "has_union": False, "has_stacked_statements": False, "has_ddl": False},
    )

    assert combined.overall_risk_level == "Medium"
    assert combined.suggested_action == "FLAG_FOR_REVIEW"


def test_calibrated_path_keeps_low_allow_below_review_floor():
    svc = _svc()
    nlp = QueryValidationResult(classification_label="Malicious Signature", classification_score=0.49)
    heur = SQLHeuristicsResult(suspected=False, hits=[], heuristic_score=0.0)

    combined = svc._combine_assessments(
        anomaly_result=None,
        nlp_result=nlp,
        heuristics=heur,
        calibrated_risk_score=0.15,
        signal_contributions={"nlp": 0.1225},
        ast_features={"statement_count": 1, "has_union": False, "has_stacked_statements": False, "has_ddl": False},
    )

    assert combined.overall_risk_level == "Low"
    assert combined.suggested_action == "ALLOW"
