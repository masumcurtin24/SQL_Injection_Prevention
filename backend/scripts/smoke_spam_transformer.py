"""
Smoke test for transformer-based spam scoring + url indicators.
Requires network to download model on first run.
"""
import os
from pathlib import Path
from sqlalchemy.orm import Session

os.environ.setdefault("SPAM_TRANSFORMER_MODEL", "mrm8488/bert-tiny-finetuned-sms-spam-detection")
os.environ.setdefault("SPAM_FINAL_THRESHOLD", "0.8")

from backend.services.spam_detection_service import SpamDetectionService
from backend.services.alerts_service import AlertsService
from backend.server.schemas.requests import EmailAnalysisRequest


class FakeSession:
    def add(self, obj):
        pass
    def commit(self):
        pass
    def refresh(self, obj):
        pass


def main():
    alerts = AlertsService()
    models_store = Path(__file__).resolve().parents[2] / 'backend' / 'data' / 'models_store'
    svc = SpamDetectionService(model_path=str(models_store / 'spam_detector_v1.joblib'), alerts_service=alerts)

    benign = EmailAnalysisRequest(subject="Meeting Tomorrow", body_text="Let's meet at 10am tomorrow at the office.")
    spammy = EmailAnalysisRequest(subject="WIN BIG $$$", body_text="Claim your prize now: http://free-win.zip Click fast!")

    res1 = svc.analyze_email(FakeSession(), benign)
    res2 = svc.analyze_email(FakeSession(), spammy)

    print("-- Benign --", res1.get('spam_classification'))
    print("-- Spammy --", res2.get('spam_classification'))
    print("Indicators:", res2.get('url_indicators'))

if __name__ == "__main__":
    main()

