# Final Benchmark Sources

This file records the source folders used to create the canonical final benchmark package.

## Selected Sources

1. SQL Analysis and Enforcement
   - Source folder: `tmp/sql_benchmark_after_hardening/runs/latest/`
   - Run ID: `20260504035026`
   - Generated: `2026-05-04T03:51:12.585310+00:00`
   - Copied files: `summary.json`, `summary.md`, `gate_result.json`, `thresholds_effective.json`, `sql_predictions.csv`.

2. File Triage
   - Source folder: `tmp/file_benchmark_after_hardening/runs/latest/`
   - Run ID: `20260501030507`
   - Generated: `2026-05-01T03:05:11.023356+00:00`
   - Copied files: `summary.json`, `summary.md`, `gate_result.json`, `thresholds_effective.json`, `file_predictions.csv`, dynamic policy evidence files.

3. Spam/Phishing
   - Source folder: `tmp/spam_benchmark_industry_hardening/runs/latest/`
   - Run ID: `20260501021013`
   - Generated: `2026-05-01T02:11:40.032360+00:00`
   - Copied files: `summary.json`, `summary.md`, `gate_result.json`, `thresholds_effective.json`, `phishing_predictions.csv`.

## Sources Not Selected as Final

- `backend/data/benchmarks/runs/latest/` is an older SQL-only run and is retained as historical evidence.
- `tmp/sql_benchmark_before_hardening/runs/latest/` is pre-hardening SQL evidence.
- `tmp/defender_ai_benchmark_after_hardening/runs/latest/` is a combined run, but its SQL and file metrics are weaker than later module-specific hardening runs.
- Earlier spam/phishing benchmark folders under `tmp/` are superseded by the selected industry-hardening run.

