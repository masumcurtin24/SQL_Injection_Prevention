# Final Benchmark Summary

Official benchmark folder:

`backend/data/benchmarks/runs/final_2026_05_06/`

This summary consolidates the final selected benchmark evidence already present in the submitted workspace. The benchmark runs were not re-executed during this documentation cleanup, and no metric values were invented or manually adjusted.

## Source Runs

| Module | Source folder | Run ID | Generated |
|---|---|---|---|
| SQL Analysis and Enforcement | `tmp/sql_benchmark_after_hardening/runs/latest/` | `20260504035026` | `2026-05-04T03:51:12.585310+00:00` |
| File Triage | `tmp/file_benchmark_after_hardening/runs/latest/` | `20260501030507` | `2026-05-01T03:05:11.023356+00:00` |
| Spam/Phishing | `tmp/spam_benchmark_industry_hardening/runs/latest/` | `20260501021013` | `2026-05-01T02:11:40.032360+00:00` |

## Metric Definitions

- Precision = TP / (TP + FP).
- Recall = TP / (TP + FN).
- F1 = 2 * Precision * Recall / (Precision + Recall).
- False positive rate (FPR) = FP / (FP + TN).

## Score Semantics

- Risk score means threat likelihood or severity.
- Decision confidence means confidence in the selected final action or class.
- Operational posture score means dashboard risk posture. It is not benchmark precision.
- Precision is only used when calculated from TP / (TP + FP).

## Final Results

| Module | Precision | Recall | F1 | FPR | Support | Source | Notes |
|---|---:|---:|---:|---:|---:|---|---|
| SQL Analysis | 0.9968 | 0.9843 | 0.9905 | 0.0014 | 1012 | `tmp/sql_benchmark_after_hardening/runs/latest/summary.json` | TP=313, FP=1, TN=693, FN=5. |
| SQL Enforcement | 1.0000 | 0.9811 | 0.9905 | 0.0000 | 1012 | `tmp/sql_benchmark_after_hardening/runs/latest/summary.json` | TP=312, FP=0, TN=694, FN=6. |
| File Triage | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 77 | `tmp/file_benchmark_after_hardening/runs/latest/summary.json` | TP=39, FP=0, TN=38, FN=0. Dynamic runtime was disabled for this run. |
| Spam/Phishing | 1.0000 | 0.9951 | 0.9975 | 0.0000 | 1125 | `tmp/spam_benchmark_industry_hardening/runs/latest/summary.json` | TP=811, FP=0, TN=310, FN=4. |

## Traceability Notes

The original source folders remain in `tmp/` for traceability. The `backend/data/benchmarks/runs/latest/` folder contains an older SQL-only benchmark and is not the official final benchmark source.

