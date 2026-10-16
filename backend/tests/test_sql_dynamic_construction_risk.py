from __future__ import annotations

from backend.server.schemas.responses import SQLHeuristicsResult
from backend.services.query_analysis_service import QueryAnalysisService


def _svc() -> QueryAnalysisService:
    return QueryAnalysisService.__new__(QueryAnalysisService)


def test_heuristics_detect_dynamic_identifier_concatenation():
    svc = _svc()
    snippet = 'SELECT id FROM " + user_supplied_table + " ORDER BY " + user_supplied_sort + " DESC'
    heur = svc._heuristics_scan(snippet)
    hits = set(list(heur.hits or []))
    assert "dynamic_identifier_concatenation" in hits or "query_builder_concat_fragment" in hits
    assert bool(heur.suspected) is True


def test_dynamic_construction_floor_blocks_allow_downgrade():
    svc = _svc()
    heur = SQLHeuristicsResult(
        suspected=True,
        hits=["query_builder_concat_fragment", "dynamic_identifier_concatenation"],
        heuristic_score=0.25,
    )
    combined = svc._combine_assessments(
        anomaly_result=None,
        nlp_result=None,
        heuristics=heur,
        calibrated_risk_score=0.15,
        signal_contributions={"heuristics": 0.1125},
        ast_features={"statement_count": 1, "has_union": False, "has_stacked_statements": False, "has_ddl": False},
    )
    assert combined.overall_risk_level == "High"
    assert combined.suggested_action == "FLAG_FOR_REVIEW_BLOCK"
    assert any("Dynamic SQL construction floor applied" in str(r) for r in list(combined.reasoning or []))
