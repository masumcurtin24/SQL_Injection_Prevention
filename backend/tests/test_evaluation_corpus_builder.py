from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from backend.scripts.build_evaluation_corpus import SQL_REQUIRED_SCENARIOS, _apply_split, build_domain_corpus


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(path, index=False)


def test_build_sql_corpus_with_required_scenarios(tmp_path: Path):
    corpus_root = tmp_path / "corpus"
    raw = corpus_root / "sql" / "raw" / "seed.csv"
    rows = [
        {
            "label": "benign" if "malicious" not in scenario else "malicious",
            "scenario": scenario,
            "query": f"SELECT '{scenario}'",
            "dialect": "postgresql",
            "orm_name": "sqlalchemy",
            "service_context": "orders-api",
        }
        for scenario in SQL_REQUIRED_SCENARIOS
    ]
    rows[3]["label"] = "malicious"
    rows[4]["label"] = "malicious"
    rows[5]["label"] = "malicious"
    _write_csv(raw, rows)

    report = build_domain_corpus(domain="sql", corpus_root=corpus_root, strict=True, seed=123)

    assert report["quality_gate_passed"] is True
    latest = Path(report["artifacts"]["latest_csv"])
    assert latest.exists()
    df = pd.read_csv(latest)
    assert len(df) >= len(SQL_REQUIRED_SCENARIOS)
    assert set(df["split"]).issubset({"train", "validation", "test"})
    assert set(int(v) for v in df["label"].tolist()) == {0, 1}


def test_build_sql_corpus_strict_fails_on_missing_required_scenario(tmp_path: Path):
    corpus_root = tmp_path / "corpus"
    raw = corpus_root / "sql" / "raw" / "incomplete.csv"
    rows = [
        {
            "label": "benign",
            "scenario": "benign_enterprise_query",
            "query": "SELECT 1",
            "dialect": "postgresql",
            "service_context": "api",
        },
        {
            "label": "malicious",
            "scenario": "obfuscated_sqli",
            "query": "SELECT * FROM users WHERE id=1 OR 1=1 --",
            "dialect": "mysql",
            "service_context": "api",
        },
    ]
    _write_csv(raw, rows)

    with pytest.raises(ValueError):
        build_domain_corpus(domain="sql", corpus_root=corpus_root, strict=True)


def test_apply_split_handles_non_consecutive_index_without_keyerror():
    df = pd.DataFrame(
        [
            {"label": 0, "scenario": "benign_enterprise_query", "text": "select 1"},
            {"label": 0, "scenario": "orm_generated_query", "text": "select 2"},
            {"label": 1, "scenario": "obfuscated_sqli", "text": "or 1=1"},
            {"label": 1, "scenario": "service_context_trace", "text": "union select"},
            {"label": 1, "scenario": "stored_procedure_abuse", "text": "exec xp_cmdshell"},
            {"label": 0, "scenario": "cross_dialect_query", "text": "select now()"},
        ]
    )
    # Simulate a de-dup/filtered frame with a sparse index pattern.
    df = df.drop(index=[1, 4])
    assert list(df.index) == [0, 2, 3, 5]

    out = _apply_split(df, seed=13)
    assert len(out) == 4
    assert set(out["split"]).issubset({"train", "validation", "test"})
