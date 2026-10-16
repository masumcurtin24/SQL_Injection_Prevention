from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.scripts.yara_updater_lib import (
    collect_benign_files,
    compile_rule_files,
    compile_rule_source,
    extract_rule_names,
    run_fp_regression,
)


def test_extract_rule_names_and_compile_source():
    src = """
rule demo_rule_1 {
  strings:
    $a = "powershell"
  condition:
    $a
}
"""
    names = extract_rule_names(src)
    assert names == ["demo_rule_1"]
    compile_rule_source(src)


def test_fp_regression_counts(tmp_path: Path):
    rule_file = tmp_path / "demo.yar"
    rule_file.write_text(
        """
rule demo_fp_rule {
  strings:
    $x = "hello-world-indicator"
  condition:
    $x
}
""",
        encoding="utf-8",
    )

    benign_1 = tmp_path / "a.txt"
    benign_2 = tmp_path / "b.txt"
    benign_1.write_text("this contains hello-world-indicator once", encoding="utf-8")
    benign_2.write_text("clean sample", encoding="utf-8")

    rules = compile_rule_files([rule_file])
    collected = collect_benign_files([tmp_path], max_files=10, max_bytes_per_file=200_000)
    result = run_fp_regression(
        rules,
        collected,
        max_bytes_per_file=200_000,
    )

    assert result.files_scanned >= 2
    assert result.fp_files >= 1
    assert result.total_matches >= 1
    assert "demo_fp_rule" in result.top_rules
