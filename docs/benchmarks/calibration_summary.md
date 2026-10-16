# Calibration Summary

Date reviewed: `2026-05-13`

Source benchmark folder:

`backend/data/benchmarks/runs/final_2026_05_06/`

This summary does not invent calibration evidence. It uses the per-sample prediction CSVs present in the final benchmark package where a numeric risk score and a hard predicted class are both available.

## Method

For the file and spam/phishing CSVs, a decision-confidence proxy was reconstructed from the project score semantics:

- predicted malicious/positive -> `decision_confidence = risk_score`
- predicted safe/negative -> `decision_confidence = 1 - risk_score`

Correctness was then defined as:

`correct = 1` when the predicted class matched the labelled class, otherwise `0`.

For each confidence bucket:

- `count` = number of samples in the bucket
- `average confidence` = mean reconstructed decision confidence
- `actual correctness rate` = mean of `correct`
- `calibration gap` = absolute difference between average confidence and actual correctness

Expected Calibration Error (ECE) was computed as the sample-count weighted mean bucket gap.

Brier Score was computed as:

`mean((decision_confidence - correct)^2)`

These figures are descriptive calibration diagnostics for the final benchmark rows. They do not claim that the system is fully statistically calibrated.

## Spam/Phishing

Source file:

`backend/data/benchmarks/runs/final_2026_05_06/spam_phishing_predictions.csv`

| Confidence bucket | Count | Average confidence | Actual correctness rate | Calibration gap |
| --- | ---: | ---: | ---: | ---: |
| 0.50-0.60 | 1071 | 0.5552 | 0.9981 | 0.4429 |
| 0.60-0.70 | 50 | 0.6202 | 0.9600 | 0.3398 |
| 0.70-0.80 | 1 | 0.7131 | 1.0000 | 0.2869 |
| 0.80-0.90 | 3 | 0.8300 | 1.0000 | 0.1700 |
| 0.90-1.00 | 0 | n/a | n/a | n/a |

- Samples used: `1125`
- Expected Calibration Error: `0.4375`
- Brier Score: `0.1962`

Interpretation: the final spam/phishing benchmark predictions are often correct while the reconstructed decision-confidence values remain conservative. That is exactly why the product should not present low-confidence or grey-zone operational outputs as hard automatic detections.

## File Upload Security

Source file:

`backend/data/benchmarks/runs/final_2026_05_06/file_predictions.csv`

| Confidence bucket | Count | Average confidence | Actual correctness rate | Calibration gap |
| --- | ---: | ---: | ---: | ---: |
| 0.50-0.60 | 0 | n/a | n/a | n/a |
| 0.60-0.70 | 0 | n/a | n/a | n/a |
| 0.70-0.80 | 15 | 0.7500 | 1.0000 | 0.2500 |
| 0.80-0.90 | 11 | 0.8000 | 1.0000 | 0.2000 |
| 0.90-1.00 | 51 | 0.9000 | 1.0000 | 0.1000 |

- Samples used: `77`
- Expected Calibration Error: `0.1435`
- Brier Score: `0.0245`

Interpretation: this benchmark slice is accurate on the recorded samples, but the score distribution is still discretized by the policy-style file risk bands. It should not be presented as proof of perfect probabilistic calibration.

## SQL Analysis

Source file inspected:

`backend/data/benchmarks/runs/final_2026_05_06/sql_predictions.csv`

Full statistical calibration was not computed for SQL because the final CSV contains hard prediction fields and categorical enforcement risk, but not a per-sample numeric decision-confidence or probability column suitable for the same calibration calculation.

The current system uses calibrated heuristic/model fusion and review-aware decision policy. Reliability diagrams, Expected Calibration Error, and Brier Score for SQL remain future work unless per-sample probability or decision-confidence rows are exported for that domain.

## Professor-Facing Conclusion

A `50%` spam/phishing risk result is not treated as an automatic block decision. It is treated as a grey-zone, review-required decision. The platform separates threat risk, decision confidence, uncertainty, and AI reliability so that uncertain or adversarial cases are escalated instead of overclaimed.

The current confidence scores are calibrated by project fusion logic and policy thresholds. Full statistical calibration using reliability diagrams, Expected Calibration Error, and Brier Score is future work unless per-sample calibration evidence is available for every domain.

The explainability contract now reports these limitations alongside score semantics, evidence contributions, decision rationale, and AI Reliability. This improves traceability but does not change or inflate benchmark values.

The BEC/fraud heuristic upgrade adds deterministic risk floors for multi-condition fraud evidence such as gift-card PIN exfiltration, payroll diversion, payment redirection, and credential-harvesting links. These floors are policy controls with explicit evidence reasons; they are not new benchmark measurements and do not manually change benchmark precision, recall, F1, FPR, or accuracy.

The courier/customs-fee phishing upgrade adds deterministic risk floors for multi-condition delivery scam evidence such as claimed courier identity, customs or redelivery fee pressure, non-official payment links, brand-domain mismatch, urgency/return threats, and tracking lures. These are targeted policy controls and explainability fields; no benchmark numbers were manually changed.

The Office macro-defence upgrade adds deterministic static evidence for uploaded files, including macro containers, risky VBA indicators, OOXML external relationships/templates, and macro-extension mismatches. These are policy controls and explainability fields, not new calibration evidence. No benchmark numbers were changed to reflect this upgrade unless a new labelled benchmark run is produced.
