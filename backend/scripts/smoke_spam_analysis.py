"""Baseline smoke test for SpamDetectionService.

This script avoids transformer downloads and exits non-zero on regression.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SPAM_TRANSFORMER_MODEL", "")

from backend.services.alerts_service import AlertsService
from backend.services.spam_detection_service import SpamDetectionService
from backend.server.schemas.requests import EmailAnalysisRequest


class FakeSession:
    def add(self, obj):
        pass

    def commit(self):
        pass

    def refresh(self, obj):
        pass


def init_service() -> SpamDetectionService:
    models_store = ROOT / "backend" / "data" / "models_store"
    alerts = AlertsService()
    return SpamDetectionService(
        model_path=str(models_store / "spam_detector_v1.joblib"),
        alerts_service=alerts,
    )


def main() -> None:
    svc = init_service()
    svc.set_settings(
        thresholds={"allow": 0.40, "suspicious": 0.50, "block": 0.80, "ood": 0.68}
    )

    benign = EmailAnalysisRequest(
        subject="Meeting rescheduled",
        body_text="The weekly project meeting is now at 10:30am in the main room.",
        sender_email="Project Office <office@example.com>",
    )
    suspicious = EmailAnalysisRequest(
        subject="Suspicious Transfer Detected",
        body_text=(
            "A transfer of AUD 4,980 was initiated from your account. "
            "If unauthorized, cancel now: "
            "https://secure-bank-alerts.co/reverse "
            "If no action is taken within 15 minutes, transfer will be processed."
        ),
    )

    benign_result = svc.analyze_email(FakeSession(), benign)
    suspicious_result = svc.analyze_email(FakeSession(), suspicious)

    benign_classification = benign_result.get("spam_classification") or {}
    suspicious_classification = suspicious_result.get("spam_classification") or {}
    suspicious_meta = suspicious_result.get("meta_features") or {}
    campaign_ids = {str(item) for item in (suspicious_meta.get("campaign_match_ids") or [])}

    print("-- Benign --", benign_classification)
    print("-- Suspicious --", suspicious_classification)
    print("-- Campaign IDs --", sorted(campaign_ids))

    benign_ok = bool(benign_classification.get("is_spam")) is False
    suspicious_ok = bool(suspicious_classification.get("is_spam")) is True and (
        "bank_transfer_fraud_alert" in campaign_ids or "urgency_pressure" in campaign_ids
    )

    if not benign_ok:
        raise SystemExit("Spam smoke failed: benign message was classified as spam.")
    if not suspicious_ok:
        raise SystemExit("Spam smoke failed: fraud message did not trigger spam/phishing detection.")


if __name__ == "__main__":
    main()
