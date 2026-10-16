from __future__ import annotations

import csv

from backend.scripts.update_spam_threat_corpus import REQUIRED_SCENARIOS, refresh_spam_threat_corpus


def test_refresh_spam_threat_corpus_generates_required_scenarios(tmp_path, monkeypatch):
    import backend.scripts.update_spam_threat_corpus as builder

    monkeypatch.setattr(
        builder,
        "_collect_online_domains",
        lambda max_domains=1800: ["secure-bank-alerts.co", "teams-files-share.work"],
    )
    monkeypatch.setattr(
        builder,
        "_load_domains_from_reputation_scores",
        lambda path, min_score=0.80, max_domains=2000: ["parcel-redelivery-notice.top"],
    )
    monkeypatch.setattr(
        builder,
        "_load_domain_list",
        lambda path: {"microsoft.com", "google.com", "amazon.com"},
    )
    monkeypatch.setattr(
        builder,
        "_load_false_negative_feedback",
        lambda limit=500: [
            {
                "subject": "Suspicious transfer detected",
                "body_text": "Cancel now via https://secure-bank-alerts.co/reverse",
                "sender_email": "alerts@secure-bank-alerts.co",
            }
        ],
    )

    out_csv = tmp_path / "phishing_online_weaklabels.csv"
    out_report = tmp_path / "phishing_online_weaklabels_report.json"
    report = refresh_spam_threat_corpus(
        output_path=out_csv,
        report_path=out_report,
        max_phish_rows=60,
        max_ham_rows=30,
        feedback_limit=50,
        seed=17,
    )

    assert out_csv.exists()
    assert out_report.exists()
    assert report["status"] == "ok"
    assert report["stats"]["missing_required_scenarios"] == []

    with open(out_csv, "r", encoding="utf-8", newline="") as fp:
        rows = list(csv.DictReader(fp))
    assert len(rows) >= 50
    scenarios = {str(r.get("scenario") or "") for r in rows}
    assert set(REQUIRED_SCENARIOS).issubset(scenarios)
