# Score Formula Reference

This reference separates threat risk, decision confidence, uncertainty, AI reliability, operational dashboard posture, and benchmark metrics. These quantities answer different questions and must not be presented as interchangeable.

## 1. Threat Risk

### SQL Risk

The SQL analyzer combines four signal families:

`sql_risk = clamp01((0.45 * heuristics) + (0.25 * nlp_probability) + (0.20 * anomaly_probability) + (0.10 * ast_score))`

Where:

- `heuristics` is the calibrated SQL signature/indicator score.
- `nlp_probability` is the malicious-class probability derived from the SQL text classifier.
- `anomaly_probability = 0.75` when the anomaly detector flags the query, otherwise `0.0`.
- `ast_score` is the clamped structural feature score for stacked statements, UNION, DDL, EXEC, tautologies, timing functions, catalog access, file exfiltration patterns, and related SQL abuse indicators.

Critical heuristic evidence can apply a policy floor:

`sql_risk = max(sql_risk, 0.93)` when a configured critical SQL indicator is present.

### File Risk

The file analyzer is primarily policy-driven rather than a single smooth probabilistic fusion. The implementation applies deterministic assessment bands and then preserves or raises risk when stronger evidence appears:

`file_risk = clamp01(max(base_policy_risk, applicable_policy_floors))`

Representative base policy risks include:

- Safe upload: `0.10`
- Suspicious/review path: `0.75`
- Disallowed type: `0.80`
- Oversized/rejected upload: `0.90`
- Malicious YARA/signature match: `0.95`

Additional file-policy evidence can raise risk or strengthen the action path for archive abuse, dynamic-analysis indicators, content/extension mismatches, active PDF content, macros, and related controls.

### Macro Defence Mechanism

The file scanner performs static Office macro defence for uploaded files. This is separate from spam/email attachment-lure detection: email text can say "enable macros", but only the file scanner can report whether an uploaded Office file actually contains macro containers or risky macro indicators.

Supported static checks include:

- macro-enabled OOXML extensions such as `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xltm`, `.potm`, `.xlam`, and `.ppam`
- legacy macro-capable Office formats `.doc`, `.xls`, and `.ppt`
- `vbaProject.bin` inside OOXML packages
- macro containers inside non-macro OOXML extensions such as `.docx`, `.xlsx`, and `.pptx`
- OOXML relationships with `TargetMode="External"`, remote templates, DDE-like fields, ActiveX, embeddings, and OLE object paths
- static VBA indicators for auto-execution, shell execution, PowerShell/cmd/mshta/rundll32/regsvr32/wscript/cscript, network download, obfuscation, persistence/system access, and DDE abuse
- Mark-of-the-Web/source trust, signed macro, trusted publisher, and trusted location metadata when supplied by upload context

Macro risk is scored as an explicit policy floor, not as global file-score inflation:

| Macro evidence | Macro risk floor |
| --- | --- |
| No macro evidence | `0.00` |
| Macro present only, signed/trusted and no risky behaviour | `0.20-0.35` |
| Macro present only, unknown/untrusted source | `0.45-0.60` |
| Macro plus auto-execution | `>= 0.65` |
| Macro plus shell/PowerShell/cmd/mshta/regsvr32/rundll32 | `>= 0.80` |
| Macro plus auto-exec and command execution | `>= 0.92` |
| Network download plus execution | `>= 0.92` |
| Obfuscation plus execution | `>= 0.85` |
| `vbaProject.bin` inside non-macro OOXML extension | `>= 0.85` |
| External template/remote relationship | `>= 0.80` |
| DDE command behaviour | `>= 0.92` |

`final_file_risk = max(existing_file_risk, macro_risk_floor)`

Benign macro presence is not automatically labelled malware. Unknown-source benign macro containers are routed to review or monitor, while signed/trusted benign macros can reduce operational handling severity. Signed/trusted status does not override risky macro behaviour.

Action wording is advisory unless enforcement is integrated:

- `block_request` means block through configured policy workflow or analyst approval.
- `quarantine_request` means quarantine is recommended according to configured policy.
- The platform does not claim durable quarantine, gateway blocking, macro execution, or sandbox detonation from static macro scanning alone.

### Spam/Phishing Risk

The spam/phishing analyzer performs weighted late fusion over the active signal families:

`raw_fused = sum(weight_i * score_i) / sum(active_weight_i)`

For each active component:

- Component score = evidence from one signal family.
- Weight = configured contribution weight.
- Numerator term = `score_i * weight_i`.
- Normalized contribution = `(score_i * weight_i) / sum(active_weight_i)`.

The active component set can include:

- classical model
- transformer model
- online learner
- heuristic URL/sender score
- reputation score
- campaign-pattern score
- header-authentication score
- fraud-pattern score
- deterministic BEC fraud score, reported separately as `bec_fraud` and folded into `fraud_pattern` when stronger

The fused score is then calibrated and policy floors may raise the final risk:

`calibrated = sigmoid(a * raw_fused + b)`

`spam_risk = clamp01(max(calibrated, applicable_policy_floors))`

Policy floors can be applied for blocklists, hard campaign signals, fraud-pattern hard signals, strong header-authentication anomalies, aligned campaign+URL risk, deterministic BEC/fraud indicators, and high OOD review conditions. These floors do not claim statistical calibration by themselves; they are explicit decision-policy controls.

### Deterministic BEC/Fraud Rules

Known high-risk BEC patterns such as gift-card PIN requests, payroll diversion, payment redirection, wire fraud, suspicious credential harvesting, MFA/security-alert phishing, remote-support scams, QR-code lures, tax/HR lures, urgent executive requests, and malicious attachment lures are treated as deterministic fraud indicators.

Risk floors are applied only when multiple evidence conditions are satisfied. Examples:

- Gift-card fraud requires a purchase request, card/PIN/code context, exfiltration such as sending photos or codes, and urgency/unavailability language. Floor: at least `0.82`.
- Payroll/direct-deposit fraud requires payroll context, bank/direct-deposit change or verification intent, and urgency/out-of-band pressure. Floor: at least `0.80`.
- Credential harvesting requires credential/account language plus suspicious URL/domain evidence for high-risk blocking floor. Floor: at least `0.81`; strong no-link credential coercion is lower and review-first.
- Invoice/payment redirection and supplier bank-change fraud require invoice/payment context plus new or changed bank, beneficiary, remittance, wire, ACH, or payment instructions. Floor: at least `0.80`.
- QR-code/image lures are review-required when payment/login/verification context is present; suspicious URL evidence can raise them further.

False-positive controls: isolated phrases such as "gift card policy", raffle receipts, payroll policy announcements, normal invoices without new payment instructions, or newsletters explaining scams do not receive high-risk BEC floors. Missing optional evidence is treated as missing evidence, not as a benign vote.

### Courier / Customs-Fee Phishing Rules

Courier/customs-fee phishing is handled as a targeted deterministic phishing category, not as global spam-score inflation. The detector looks for multiple evidence groups:

- claimed courier identity such as DHL, FedEx, UPS, USPS, Australia Post/AusPost, StarTrack, Royal Mail, DPD, Evri, Aramex, Sendle, Toll, TNT, Amazon delivery, or generic parcel/courier language
- customs, handling, delivery, redelivery, postage, shipping, service-fee, card-payment, or pay-now pressure
- delivery problem language such as parcel hold, cannot be delivered, customs hold, missed delivery, address issue, or returned to sender
- urgency/threat language such as within 12 hours, final notice, deadline, today, immediately, or will be returned
- suspicious payment/tracking URLs, especially `/pay`, `/payment`, `/customs`, `/redelivery`, `/tracking`, `/customer/pay`, `/fees`, `/verify`, or `/card`
- claimed-brand vs link-domain mismatch, sender-domain mismatch, IP/punycode/suspicious TLD, or brand keyword in a non-official registrable domain

Official-domain matching is registrable-domain aware:

- `tracking.dhl.com` is treated as aligned with `dhl.com`
- `dhl.com.evil.net` is not treated as aligned with `dhl.com`
- `auspost.com.au.evil.net` is not treated as aligned with `auspost.com.au`

Risk floors are applied only when combinations match:

| Courier evidence | Risk floor |
| --- | --- |
| Claimed courier brand + fee/payment lure + suspicious URL or brand-domain mismatch | `>= 0.82` |
| Claimed brand + customs/redelivery fee + urgency/return threat + suspicious URL | `>= 0.85` |
| Generic parcel/delivery lure + fee/payment pressure + suspicious URL | `>= 0.75` |
| Tracking-number/payment-link lure + non-official tracking-looking domain | `>= 0.78` |
| Brand-domain mismatch without payment pressure | about `0.62`, review-first |
| Official-domain routine shipping notification with no payment/credential pressure | no high-risk floor |

The API exposes this evidence through `courier_phishing`, `courier_category`, `claimed_brand`, `brand_domain_mismatch`, `sender_domain_mismatch`, `suspicious_payment_link`, `courier_link_domains`, `courier_evidence_reasons`, and related explanation fields.

## 2. Decision Confidence

Decision confidence means confidence in the selected class or action, not threat risk.

For the selected final class:

`decision_confidence = risk_score` for malicious, spam/phishing, suspicious, quarantine, or block decisions.

`decision_confidence = 1 - risk_score` for safe/allow decisions.

Examples:

- `spam_risk = 0.08`, safe result -> `decision_confidence = 0.92`
- `spam_risk = 0.91`, phishing result -> `decision_confidence = 0.91`

Uncertainty and OOD review risk are kept separate. They can force analyst review through AI Reliability policy, but they do not rewrite the selected class confidence.

## 3. Spam/Phishing Uncertainty

The spam/phishing analyzer uses evidence-based uncertainty provenance:

`threshold_margin_uncertainty = 1 - min(abs(spam_risk - suspicious_threshold) / 0.20, 1)`

`component_disagreement_uncertainty = weighted_conflict_mass / total_active_weight`

where `weighted_conflict_mass` counts only material component votes that contradict the selected risk side outside a neutral band around the suspicious threshold. Missing components are excluded from this disagreement term and are counted separately as missing-component uncertainty.

`missing_component_uncertainty = min(0.30, 0.10 * missing_important_component_count)`

`low_fidelity_uncertainty = 1 - fidelity_score`

`uncertainty_score = clamp01(max(ood_score, threshold_margin_uncertainty, component_disagreement_uncertainty, missing_component_uncertainty, low_fidelity_uncertainty))`

The API exposes:

```text
uncertainty_components = {
  threshold_margin_uncertainty,
  component_disagreement_uncertainty,
  missing_component_uncertainty,
  ood_score,
  low_fidelity_uncertainty
}
```

The current missing-component review risk checks the availability of important supporting inputs such as transformer scoring, external reputation data, and email headers.

When a multi-condition deterministic BEC/fraud signal is present, the analyzer can raise explanation fidelity because several independent fraud sub-signals agree. This reduces ambiguity from missing optional headers or a weak optional model, but it does not mutate `spam_risk` or `decision_confidence`.

Analyzer-specific notes for the other domains:

- SQL uncertainty uses the largest of threshold proximity, model/rule/anomaly disagreement, missing core SQL signal components, OOD score, and low-fidelity uncertainty.
- File uncertainty uses the largest of threshold proximity, static signal disagreement, missing ML/signature components, OOD score, and low-fidelity uncertainty.

## 4. Unified Explainability Contract

Each analyzer keeps its original response fields and also exposes a shared explainability contract:

| Metric | Formula / Source | Meaning | Used In | Limitations | Tested By |
| --- | --- | --- | --- | --- | --- |
| `score_semantics.risk_score` | Domain risk score (`calibrated_risk_score`, file `risk_score`, or `spam_score`) | Threat risk, not confidence | Score cards, report explanation | Calibrated project score, not a guaranteed probability | `backend/tests/test_explainability_payload_contract.py` |
| `score_semantics.decision_confidence` | Selected class/action confidence | Confidence in the chosen decision | UI and reliability input | Not benchmark precision or accuracy | `backend/tests/test_score_semantics.py` |
| `score_semantics.uncertainty_score` | Max of evidence-based uncertainty components | Weakness/disagreement/OOD/missing evidence | Review gates | Domain-specific approximation | `backend/tests/test_explainability_payload_contract.py` |
| `evidence_contributions.normalized_contribution` | `(component_score * weight) / total_active_weight` | Traceable weighted contribution | Explainability panel and viva explanation | Only available for weighted components | `backend/tests/test_explainability_payload_contract.py` |
| `decision_rationale.review_required` | AI Reliability review gates and action policy | Whether a human must review before final handling | UI, alerts, cases, investigation | Deterministic governance logic | `backend/tests/test_ai_reliability_service.py` |
| `decision_rationale.recommended_handling` | Reliability-aware handling mapping | Allow, monitor, review, block, or quarantine | Suggested actions | Advisory unless an enforcing backend action exists | `backend/tests/test_spam_decision_policy.py` |
| `limitations` | Analyzer caveats + governance limitations | Honest constraints on score meaning and operations | Reports and professor explanation | Must not be used to hide missing evidence | `backend/tests/test_explainability_payload_contract.py` |

The contract answers what was scored, which evidence contributed, whether signals disagreed, why review was required, which thresholds were applied, and what limitations apply. It does not inflate risk, confidence, or benchmark metrics.

## 5. AI Reliability

AI Reliability estimates whether the already-selected decision is trustworthy enough to accept automatically.

The service starts from decision confidence:

`reliability_score = decision_confidence`

Then applies multiplicative penalties:

`reliability_score *= (1 - 0.30 * uncertainty_score)`

`reliability_score *= (1 - 0.35 * ood_score)`

`reliability_score *= (0.70 + 0.30 * fidelity_score)`

The service then subtracts additive penalties for:

- grey-zone risk
- signal conflict
- missing core score fields
- adversarial suspicion

Finally:

`reliability_score = clamp01(reliability_score - additive_penalties)`

Human review is required when any configured gate fires, including:

- `decision_confidence < 0.70`
- `uncertainty_score > 0.40`
- `ood_score > 0.35`
- `fidelity_score < 0.60`
- `0.45 <= risk_score <= 0.65`
- adversarial suspicion
- strong signal conflict
- missing required score fields
- final analyzer action is review, flag, or quarantine

Recommended handling is advisory and review-aware:

- `review` for grey-zone, low-confidence, OOD, adversarial, or conflict-heavy cases
- `block` only for high-risk/high-confidence cases or deterministic hard-block policy
- `allow` for low-risk/high-confidence safe results
- `monitor` for reliable low-to-medium risk cases
- `quarantine` only where the underlying policy route supports that recommendation

## 6. Dashboard Posture and Operational Rates

Dashboard posture is an operational summary, not a benchmark metric:

`posture_score = clamp(100 - (block_rate * 70) - (detection_rate * 30) - (min(critical_alerts, 10) * 2) - (min(high_alerts, 10) * 1), 0, 100)`

Operational detection rate:

`detection_rate = (suspicious_total + blocked_total) / analysis_events`

Operational block rate:

`block_rate = blocked_total / analysis_events`

These are posture/workload rates for the current monitored window. They are not classifier accuracy, precision, recall, or F1.

## 7. Labelled Benchmark Metrics

Benchmark metrics must come from labelled evaluation data only.

`precision = TP / (TP + FP)`

`recall = TP / (TP + FN)`

`F1 = 2 * precision * recall / (precision + recall)`

`FPR = FP / (FP + TN)`

`accuracy = (TP + TN) / (TP + TN + FP + FN)`

These metrics must not be used to describe one individual message, one dashboard posture card, or one live operational event.
