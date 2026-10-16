"""Baseline smoke test for QueryAnalysisService.

This script exits non-zero on regression.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services.query_analysis_service import QueryAnalysisService
from backend.services.alerts_service import AlertsService


class FakeSession:
    def add(self, obj):
        pass
    def commit(self):
        pass
    def refresh(self, obj):
        pass


def init_service():
    models_store = ROOT / "backend" / "data" / "models_store"
    alerts = AlertsService()
    QueryAnalysisService(
        anomaly_model_path=str(models_store / "anomaly_detection_model.joblib"),
        anomaly_scaler_path=str(models_store / "anomaly_query_scaler.joblib"),
        query_validation_model_path=str(models_store / "query_validation_model.joblib"),
        alerts_service=alerts,
    )
    return QueryAnalysisService.get_instance()


def main():
    svc = init_service()
    db = FakeSession()

    benign = "SELECT id, name FROM users WHERE id = 42"
    inj = "SELECT * FROM users WHERE name = 'admin' OR '1'='1'; DROP TABLE users; --"

    res1 = svc.analyze_query(db, benign)
    res2 = svc.analyze_query(db, inj)

    def to_dict(obj):
        try:
            if hasattr(obj, 'model_dump'):
                return obj.model_dump()
        except Exception:
            pass
        return obj if isinstance(obj, dict) else {}

    def summarize(res):
        ca = to_dict(res.get("combined_assessment"))
        heur = to_dict(res.get("heuristics_detection"))
        return {
            "risk": ca.get("overall_risk_level"),
            "action": ca.get("suggested_action"),
            "reasons": ca.get("reasoning"),
            "heur_hits": heur.get("hits"),
            "heur_score": heur.get("heuristic_score"),
        }

    benign_summary = summarize(res1)
    injection_summary = summarize(res2)

    print("-- Benign summary --", benign_summary)
    print("-- Injection summary --", injection_summary)

    benign_ok = (
        str(benign_summary.get("risk") or "").lower() == "low"
        and str(benign_summary.get("action") or "").upper() == "ALLOW"
    )
    injection_ok = (
        str(injection_summary.get("risk") or "").lower() in {"high", "critical"}
        and str(injection_summary.get("action") or "").upper() in {"FLAG_FOR_REVIEW_BLOCK", "BLOCK_IMMEDIATE"}
    )

    if not benign_ok:
        raise SystemExit("SQL smoke failed: benign query did not remain low risk/allow.")
    if not injection_ok:
        raise SystemExit("SQL smoke failed: malicious query did not escalate to review/block.")


if __name__ == "__main__":
    main()
