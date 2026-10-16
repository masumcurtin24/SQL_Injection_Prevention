# Final Benchmark Summary

Official benchmark folder:

`backend/data/benchmarks/runs/final_2026_05_06/`

This document is the professor-facing benchmark summary for the final submission package. It summarises existing benchmark outputs already present in the workspace. The benchmark commands were not re-run as part of this documentation cleanup, and no metric values were fabricated.

## Source Runs

| Module | Source folder | Run ID | Recorded time | Status |
|---|---|---|---|---|
| SQL Analysis and Enforcement | `tmp/sql_benchmark_after_hardening/runs/latest/` | `20260504035026` | `2026-05-04T03:51:12.585310+00:00` | Final selected SQL evidence. |
| File Triage | `tmp/file_benchmark_after_hardening/runs/latest/` | `20260501030507` | `2026-05-01T03:05:11.023356+00:00` | Final selected file evidence. |
| Spam/Phishing | `tmp/spam_benchmark_industry_hardening/runs/latest/` | `20260501021013` | `2026-05-01T02:11:40.032360+00:00` | Final selected spam/phishing evidence. |

## Metric Definitions

- Precision = TP / (TP + FP).
- Recall = TP / (TP + FN).
- F1 = 2 * Precision * Recall / (Precision + Recall).
- FPR = FP / (FP + TN).

## Score Semantics

- Risk score = threat likelihood or severity.
- Decision confidence = confidence in the selected final action or class.
- Operational posture score = dashboard risk posture metric, not benchmark precision.
- Precision is used only for benchmark evaluation using TP / (TP + FP).
- Explainability upgrades expose score semantics, evidence contributions, decision rationale, and AI Reliability without changing these benchmark numbers.

## Final Results

| Module | Precision | Recall | F1 | FPR | Source | Notes |
|---|---:|---:|---:|---:|---|---|
| SQL Analysis | 0.9968 | 0.9843 | 0.9905 | 0.0014 | `tmp/sql_benchmark_after_hardening/runs/latest/summary.json` | Support=1012; TP=313, FP=1, TN=693, FN=5. |
| SQL Enforcement | 1.0000 | 0.9811 | 0.9905 | 0.0000 | `tmp/sql_benchmark_after_hardening/runs/latest/summary.json` | Support=1012; TP=312, FP=0, TN=694, FN=6. |
| File Triage | 1.0000 | 1.0000 | 1.0000 | 0.0000 | `tmp/file_benchmark_after_hardening/runs/latest/summary.json` | Support=77; TP=39, FP=0, TN=38, FN=0. Dynamic runtime was disabled for this run. |
| Spam/Phishing | 1.0000 | 0.9951 | 0.9975 | 0.0000 | `tmp/spam_benchmark_industry_hardening/runs/latest/summary.json` | Support=1125; TP=811, FP=0, TN=310, FN=4. |

## Historical Benchmark Folders

The following folders are retained for traceability but are not the official final benchmark evidence:

- `backend/data/benchmarks/runs/latest/` contains an older SQL-only benchmark from April 2026.
- `tmp/sql_benchmark_before_hardening/runs/latest/` contains pre-hardening SQL evidence.
- `tmp/defender_ai_benchmark_after_hardening/runs/latest/` contains a combined run with stale weaker SQL and file metrics.
- Earlier spam/phishing benchmark folders under `tmp/` are superseded by `tmp/spam_benchmark_industry_hardening/runs/latest/`.
