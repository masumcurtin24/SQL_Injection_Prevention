from __future__ import annotations

from pathlib import Path

import pandas as pd

from backend.services.defender_ai_service import DefenderAIService


def test_defender_sql_base_dataset_includes_curated_corpus(tmp_path: Path):
    service = DefenderAIService.get_instance() if DefenderAIService._instance is not None else DefenderAIService()

    original_corpus_dir = service._corpus_dir
    original_raw_dir = service._raw_dir
    try:
        service._corpus_dir = tmp_path / "corpus"
        service._raw_dir = tmp_path / "raw"

        curated = service._corpus_dir / "sql" / "processed"
        curated.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(
            [
                {"text": "dialect:postgresql service:orders select * from orders where id = 1", "label": 0},
                {"text": "dialect:mysql service:api select * from users where id=1 or 1=1 --", "label": 1},
            ]
        ).to_csv(curated / "sql_corpus_latest.csv", index=False)

        X, y = service._load_sql_base_dataset()
        pairs = dict(zip(X, y))
        assert "dialect:postgresql service:orders select * from orders where id = 1" in pairs
        assert "dialect:mysql service:api select * from users where id=1 or 1=1 --" in pairs
        assert pairs["dialect:mysql service:api select * from users where id=1 or 1=1 --"] == 1
    finally:
        service._corpus_dir = original_corpus_dir
        service._raw_dir = original_raw_dir
