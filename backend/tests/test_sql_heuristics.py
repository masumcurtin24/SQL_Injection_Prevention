"""
Simple unit-style tests for SQL heuristics (no external framework).
Run: backend/.venv/Scripts/python.exe backend/tests/test_sql_heuristics.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.query_analysis_service import QueryAnalysisService
from backend.services.alerts_service import AlertsService


def _svc():
    # No models required to exercise _heuristics_scan
    AlertsService()  # ensure singleton
    # Fake init without model paths by bypassing constructor is tricky; instead create and ignore models by providing dummy paths
    # We'll instantiate minimally by tapping the class without reinitializing if already initialized elsewhere.
    try:
        return QueryAnalysisService.get_instance()
    except Exception:
        return QueryAnalysisService(
            anomaly_model_path=str(ROOT / "backend" / "data" / "models_store" / "anomaly_detection_model.joblib"),
            anomaly_scaler_path=str(ROOT / "backend" / "data" / "models_store" / "anomaly_query_scaler.joblib"),
            query_validation_model_path=str(ROOT / "backend" / "data" / "models_store" / "query_validation_model.joblib"),
            alerts_service=AlertsService(),
        )


def test_cases():
    svc = _svc()
    h = svc._heuristics_scan  # type: ignore

    benign = "SELECT id, name FROM users WHERE id = 1"
    r = h(benign)
    assert not r.suspected, f"Unexpected suspicion for benign: {r}"

    inj1 = "SELECT * FROM users WHERE '1'='1' --"
    r = h(inj1)
    assert r.suspected and ("quoted_tautology" in r.hits or "comment_sequence" in r.hits)

    inj2 = "SELECT 1; DROP TABLE users;"
    r = h(inj2)
    assert r.suspected and "stacked_query_dml" in r.hits

    inj3 = "UNION SELECT username, password FROM users"
    r = h(inj3)
    assert r.suspected and "union_select" in r.hits

    inj4 = "; WAITFOR DELAY '00:00:05'"
    r = h(inj4)
    assert r.suspected and "time_waitfor_delay" in r.hits

    inj5 = "SELECT pg_sleep(5)"
    r = h(inj5)
    assert r.suspected and "time_pg_sleep" in r.hits

    inj6 = "SELECT 1 FROM sqlite_master WHERE type='table'"
    r = h(inj6)
    assert "sqlite_master" in r.hits

    inj7 = "SELECT * FROM dual WHERE 1=1 OR 1=1"
    r = h(inj7)
    assert r.suspected and ("tautology_or_1eq1" in r.hits or "boolean_true" in r.hits)

    print("All heuristic tests passed.")


if __name__ == "__main__":
    test_cases()

