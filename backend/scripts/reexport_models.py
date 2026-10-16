"""
Re-export scikit-learn/joblib models with the currently installed versions.

This script loads each .joblib in backend/data/models_store and re-saves it
with the active library versions (e.g., scikit-learn 1.7.2), backing up the
originals first. This helps eliminate InconsistentVersionWarning on load.

Usage:
  python backend/scripts/reexport_models.py

Notes:
  - The running server will keep using already-loaded models. Restart to pick up re-exported files.
  - Backups are placed under backend/data/models_store/_backup_<timestamp>/
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path
from typing import List

import joblib

# Ensure project root is importable so joblib can resolve any pickled
# references like 'backend.*' during load.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _models_store_dir() -> Path:
    # backend/scripts/reexport_models.py -> backend/scripts -> backend
    return Path(__file__).resolve().parents[1] / "data" / "models_store"


def list_joblib_files(root: Path) -> List[Path]:
    return sorted([p for p in root.glob("*.joblib") if p.is_file()])


def ensure_backup_dir(root: Path) -> Path:
    ts = time.strftime("%Y%m%d_%H%M%S")
    bdir = root / f"_backup_{ts}"
    bdir.mkdir(parents=True, exist_ok=True)
    return bdir


def reexport_file(src: Path, backup_dir: Path) -> None:
    if not src.exists():
        print(f"SKIP (missing): {src}")
        return
    # Backup original
    dst_backup = backup_dir / src.name
    shutil.copy2(src, dst_backup)

    temp_out = src.with_suffix(src.suffix + ".tmp")
    try:
        # Load then re-save with current joblib/sklearn
        obj = joblib.load(src)
        joblib.dump(obj, temp_out)
        os.replace(temp_out, src)
        print(f"OK: {src.name} -> re-exported (backup: {dst_backup.name})")
    finally:
        # Clean up any temp file on failure
        if temp_out.exists():
            try:
                temp_out.unlink()
            except Exception:
                pass


def main() -> int:
    root = _models_store_dir()
    if not root.exists():
        print(f"ERROR: Models store not found: {root}")
        return 2

    print(f"Models store: {root}")
    files = list_joblib_files(root)
    if not files:
        print("No .joblib files found. Nothing to do.")
        return 0

    print("Discovered models:")
    for f in files:
        print(f" - {f.name}")

    backup_dir = ensure_backup_dir(root)
    print(f"Backup directory: {backup_dir}")

    errors = []
    for f in files:
        try:
            reexport_file(f, backup_dir)
        except Exception as e:
            errors.append((f, e))
            print(f"FAIL: {f.name}: {e}")

    if errors:
        print("\nCompleted with errors:")
        for f, e in errors:
            print(f" - {f.name}: {e}")
        return 1

    print("\nAll models re-exported successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
