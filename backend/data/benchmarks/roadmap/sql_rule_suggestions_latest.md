# SQL Rule Suggestion Report

- Generated at: `2026-04-09T16:43:50.426776+00:00`
- Source predictions: `C:\backup 10-10-25\04-17am updates\SQL_Injection_Prevention\backend\data\benchmarks\runs\latest\sql_predictions.csv`
- Total rows: `1012`
- False negatives: `119`
- False positives: `0`

## False-negative pattern frequency
- blind_exfil: 0
- comment_tamper: 90
- copy_program: 1
- metadata_probe: 4
- proc_abuse: 0
- stacked_query: 0
- time_delay: 18
- union_select: 0

## Recommended critical patterns
- re:(?i)(--|/\*|\*/|#)
- re:(?i)\b(sleep\s*\(|pg_sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b
- re:(?i)\b(@@version|version\s*\(|database\s*\(|current_database\s*\(|information_schema)\b
- re:(?i)\bcopy\b[\s\S]{0,120}\bto\s+program\b

## Recommended allowlist templates (review required)
