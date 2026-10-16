"""Baseline smoke test for the SQL enforcement hook.

This script exits non-zero on regression.
"""
import os
import sys
from pathlib import Path

from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.core.database import engine
from backend.services.alerts_service import AlertsService
from backend.services.query_analysis_service import QueryAnalysisService

def run():
    # Initialize analysis service so enforcement heuristics are available
    from pathlib import Path
    models_store = Path(__file__).resolve().parents[2] / 'backend' / 'data' / 'models_store'
    QueryAnalysisService(
        anomaly_model_path=str(models_store / 'anomaly_detection_model.joblib'),
        anomaly_scaler_path=str(models_store / 'anomaly_query_scaler.joblib'),
        query_validation_model_path=str(models_store / 'query_validation_model.joblib'),
        alerts_service=AlertsService(),
    )
    with engine.connect() as conn:
        print("-- benign --")
        conn.execute(text("SELECT 1 as x"))
        print("benign ok")
        print("-- malicious --")
        try:
            conn.execute(text("SELECT 1; DROP TABLE users; --"))
            raise SystemExit("SQL enforcement smoke failed: malicious query executed.")
        except Exception as e:
            print("blocked as expected:", str(e)[:200])

if __name__ == "__main__":
    print("SQL_ENFORCEMENT_MODE=", os.getenv("SQL_ENFORCEMENT_MODE", "block_critical"))
    run()
