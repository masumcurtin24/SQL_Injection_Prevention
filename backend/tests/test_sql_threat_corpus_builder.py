from __future__ import annotations

import csv

from backend.scripts.update_sql_threat_corpus import REQUIRED_SCENARIOS, refresh_sql_threat_corpus


def test_refresh_sql_threat_corpus_generates_required_scenarios(tmp_path, monkeypatch):
    import backend.scripts.update_sql_threat_corpus as builder

    monkeypatch.setattr(
        builder,
        "_collect_online_payloads",
        lambda max_payloads=1800: (
            [
                {
                    "payload": "SeLeCt * FrOm users WhErE id=1/**/OR/**/1=1--",
                    "source": "payloadsallthethings_sqli_readme",
                    "url": "https://example.invalid/1",
                },
                {
                    "payload": "EXEC xp_cmdshell 'whoami'",
                    "source": "seclists_mssql",
                    "url": "https://example.invalid/2",
                },
                {
                    "payload": "SELECT * FROM invoices WHERE invoice_id = 10 AND SUBSTRING((SELECT version()),1,1)='1' --",
                    "source": "seclists_generic_blind",
                    "url": "https://example.invalid/3",
                },
            ],
            {"payloadsallthethings_sqli_readme": 1, "seclists_mssql": 1, "seclists_generic_blind": 1},
            [],
        ),
    )
    monkeypatch.setattr(
        builder,
        "_load_sql_feedback_samples",
        lambda limit=500: (
            ["SELECT * FROM users WHERE id=1 OR 1=1 --"],
            ["SELECT id, status FROM orders WHERE tenant_id = ? AND status = ?"],
            1,
            0,
        ),
    )

    out_csv = tmp_path / "sql_online_weaklabels.csv"
    out_report = tmp_path / "sql_online_weaklabels_report.json"
    report = refresh_sql_threat_corpus(
        output_path=out_csv,
        report_path=out_report,
        max_malicious_rows=50,
        max_benign_rows=40,
        feedback_limit=20,
        seed=11,
    )

    assert out_csv.exists()
    assert out_report.exists()
    assert report["status"] == "ok"
    assert report["stats"]["missing_required_scenarios"] == []

    with open(out_csv, "r", encoding="utf-8", newline="") as fp:
        rows = list(csv.DictReader(fp))
    assert len(rows) >= 20
    scenarios = {str(r.get("scenario") or "") for r in rows}
    labels = {str(r.get("label") or "") for r in rows}
    assert set(REQUIRED_SCENARIOS).issubset(scenarios)
    assert {"benign", "malicious"}.issubset(labels)
