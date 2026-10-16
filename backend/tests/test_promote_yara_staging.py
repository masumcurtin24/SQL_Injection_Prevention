from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.scripts.promote_yara_staging import _resolve_canary_count, _rollback_from_backups


def test_resolve_canary_count_policy_and_override():
    assert _resolve_canary_count(10, {"canary_max_files": 3}, None) == 3
    assert _resolve_canary_count(2, {"canary_max_files": 9}, None) == 2
    assert _resolve_canary_count(5, {"canary_max_files": 3}, 1) == 1
    assert _resolve_canary_count(5, {"canary_max_files": 3}, 0) == 0


def test_rollback_restores_existing_and_removes_new(tmp_path: Path):
    existing = tmp_path / "existing.yar"
    existing.write_text("rule old { condition: true }", encoding="utf-8")

    backup = tmp_path / "backup_existing.yar"
    backup.write_text("rule backup_old { condition: true }", encoding="utf-8")

    existing.write_text("rule changed { condition: true }", encoding="utf-8")

    created = tmp_path / "created.yar"
    created.write_text("rule created { condition: true }", encoding="utf-8")

    result = _rollback_from_backups(
        {
            str(existing.resolve()): str(backup.resolve()),
            str(created.resolve()): None,
        }
    )

    assert result["restored_files"] == 1
    assert result["deleted_new_files"] == 1
    assert existing.read_text(encoding="utf-8") == "rule backup_old { condition: true }"
    assert not created.exists()
