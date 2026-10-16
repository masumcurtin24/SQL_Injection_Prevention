"""
Defender AI v1 retraining helper.

Examples:
  python backend/scripts/train_defender_v1.py --domain all --min-feedback 5
  python backend/scripts/train_defender_v1.py --domain spam --min-feedback 20 --promote-if-better
  python backend/scripts/train_defender_v1.py --domain file --min-feedback 10 --promote-if-better
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.core.database import SessionLocal, create_db_tables
from backend.services.defender_ai_service import DefenderAIService


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", choices=["sql", "spam", "file", "all"], default="all")
    parser.add_argument("--min-feedback", type=int, default=5)
    parser.add_argument("--promote-if-better", action="store_true")
    parser.add_argument("--notes", type=str, default=None)
    args = parser.parse_args()

    create_db_tables()
    service = DefenderAIService()

    db = SessionLocal()
    try:
        results = service.retrain_and_register_candidates(
            db=db,
            domain=args.domain,
            min_feedback_samples=max(1, int(args.min_feedback)),
            promote_if_better=bool(args.promote_if_better),
            notes=args.notes,
        )
        print(json.dumps({"status": "ok", "results": results}, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()
