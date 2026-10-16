# AI Reliability and Governance Layer

## Purpose

The AI reliability layer evaluates whether an existing analyzer decision is trustworthy enough to accept automatically or whether it should be reviewed by a human analyst. It sits above the SQL, file, and spam/phishing analyzers. It does not replace their detection logic, alter thresholds, retrain models, or weaken SQL enforcement.

## Architecture

Current analyzer flow:

`Input -> Analyzer -> Risk Score -> Decision Confidence -> Alert / Case / UI`

Phase 1 reliability flow:

`Input -> Analyzer -> Risk Score -> Decision Confidence -> AI Reliability Assessment -> Review / Allow / Monitor / Block / Quarantine -> Alert / Investigation / UI`

The reliability layer consumes already calculated fields:

- `risk_score`, `calibrated_risk_score`, or `spam_score`
- `decision_confidence`
- `uncertainty_score`
- `ood_score`
- `fidelity_score`
- score breakdowns, rule hits, policy evidence, model version, and ruleset version where available

## Inputs and Outputs

The backend service is implemented in `backend/services/ai_reliability_service.py`.

It returns an `AIReliabilityAssessment` with:

- `reliability_score`
- `reliability_status`
- `review_required`
- `review_reasons`
- `signal_conflicts`
- `policy_override`
- `adversarial_suspicion`
- `recommended_handling`
- `reliability_factors`

Analyzer explanations also expose a shared `ExplainabilityPayload`-style contract through `XAIExplanation`:

- `score_semantics`: separates threat risk, decision confidence, uncertainty, OOD, fidelity, and AI Reliability.
- `evidence_contributions`: lists rule/model/heuristic/reputation signals with score, weight, normalized contribution where available, direction, and source.
- `decision_rationale`: records final decision, recommended handling, hard decision vs review, thresholds, review reasons, policy overrides, and limitations.
- `plain_language_summary` and `technical_summary`: provide professor/analyst-friendly and implementation-level explanations.
- `limitations`: records missing evidence, calibration scope, sandbox/quarantine constraints, and deterministic-governance caveats.

## Reliability Status Definitions

- `reliable`: the decision has sufficient confidence, low uncertainty, acceptable OOD risk, and no strong conflicts.
- `needs_review`: the decision is not critically unreliable, but one or more review gates were triggered.
- `low_confidence`: decision confidence is below the operational threshold.
- `out_of_distribution`: OOD score indicates unfamiliar input characteristics.
- `conflicting_signals`: available model, rule, heuristic, signature, or reputation signals disagree.
- `policy_override`: deterministic policy or rule evidence materially influenced the action.
- `adversarial_suspicion`: existing indicators suggest possible evasion, obfuscation, or adversarial behaviour.

## Human Review Gates

Human review is required when any of the following occurs:

- `decision_confidence < 0.70`
- `uncertainty_score > 0.40`
- `ood_score > 0.35`
- `fidelity_score < 0.60`
- `0.45 <= risk_score <= 0.65`
- strong signal conflict exists
- adversarial suspicion is detected
- required risk or confidence scores are missing
- the analyzer action is review, flag, or quarantine

## Formula

The reliability score starts from `decision_confidence` and applies reliability penalties:

`reliability_score = decision_confidence`

`reliability_score *= (1 - 0.30 * uncertainty_score)`

`reliability_score *= (1 - 0.35 * ood_score)`

`reliability_score *= (0.70 + 0.30 * fidelity_score)`

The service then subtracts additive penalties for grey-zone risk, signal conflict, missing scores, and adversarial suspicion. The final value is clamped to `[0.0, 1.0]`.

## Recommended Handling Policy

Recommended handling is review-aware:

- `review` for grey-zone, low-confidence, OOD, adversarial, or conflicting-signal cases
- `block` only for high-risk/high-confidence decisions or deterministic hard-block policy
- `allow` only for low-risk/high-confidence safe decisions
- `monitor` for reliable low-to-medium risk cases
- `quarantine` only where the analyzer/policy route supports that recommendation

This means a review-required spam/phishing result must not be rendered as a hard "Spam detected" verdict in the UI.

## Signal Conflict Detection

The layer conservatively checks for disagreement between available signals, including:

- high heuristic/rule score with low model score
- high YARA/signature score with low model score
- high reputation, campaign, URL, or header risk with low model score
- high model score with weak supporting rules
- high OOD with high decision confidence
- critical indicators with only moderate final risk

These conflicts do not override the analyzer decision. They explain why human review may be appropriate.

For spam/phishing, deterministic multi-condition BEC and impersonation evidence is treated differently from a single weak heuristic. Gift-card PIN exfiltration, payroll diversion, payment redirection, credential harvesting with suspicious URLs, courier/customs-fee payment lures, delivery/redelivery fee scams, and similar patterns can reduce ambiguity when several required sub-signals agree. A low optional model score is recorded as context, but it is not automatically treated as a strong conflict when deterministic evidence is high and auditable.

## Adversarial Suspicion Indicators

The layer uses existing evidence only. It does not introduce a new detector.

Examples include:

- SQL comment splitting, encoded keywords, tautology obfuscation, UNION/time-based indicators
- file extension/content mismatch, archive path traversal, risky macros, critical Office macro chains, OOXML external templates/relationships, ActiveX/OLE embeddings, PDF active content, YARA critical evidence
- spam/phishing punycode, sender/domain mismatch, IP links, blocklist hits, display-link mismatch, and obfuscated URL indicators
- spam/phishing BEC and impersonation indicators such as gift-card PIN requests, payroll/direct-deposit change requests, payment redirection, suspicious credential-harvesting URLs, courier/customs-fee payment links on non-official domains, brand-domain mismatch, MFA coercion, remote-support lures, QR payment/login lures, and malicious attachment lures

## File Macro Defence Governance

The file analyzer implements static macro-container and risky macro-indicator detection for uploaded Office files. This is separate from email macro-lure detection. The spam/phishing analyzer may report that an email encourages users to enable macros, but it does not claim an actual uploaded file was macro-scanned unless the file analyzer processed that file.

Macro reliability inputs include:

- macro container presence (`vbaProject.bin`, legacy OLE VBA evidence, macro-enabled extension)
- risky VBA indicators such as `AutoOpen`, `Document_Open`, `Workbook_Open`, `WScript.Shell`, `Shell`, PowerShell/cmd/mshta/rundll32/regsvr32, URL download APIs, XMLHTTP/WinHTTP, obfuscation, persistence, and DDE patterns
- OOXML external templates/relationships, remote targets, ActiveX, embeddings, and OLE object indicators
- source trust, Mark-of-the-Web/source zone, signed macro, trusted publisher, and trusted location metadata when supplied

Macro action policy remains review-aware:

- benign macro presence from unknown source routes to review or monitor, not automatic malware labelling
- signed/trusted benign macros can reduce handling severity only when risky indicators are absent
- risky macro chains produce `block_request` or `quarantine_request`
- `block_request` and `quarantine_request` are action plans or recommendations, not proof that a gateway or durable quarantine store already acted

The project does not execute Office macros and does not claim full sandbox detonation unless a dynamic-analysis provider completes and returns evidence for that scan.

## Difference from Risk and Decision Confidence

Risk score means threat likelihood or severity. Higher risk means the input is more dangerous.

Decision confidence means confidence in the selected final class or action. For benign decisions, low risk produces high decision confidence. For malicious, suspicious, quarantine, or block decisions, high risk produces high decision confidence.

Reliability score means trustworthiness of the AI decision after considering uncertainty, OOD, fidelity, signal conflicts, policy overrides, and adversarial indicators. It is not a risk score and it is not benchmark precision.

A 50% spam/phishing risk result is not treated as an automatic block decision. It is treated as a grey-zone, review-required decision. The platform separates threat risk, decision confidence, uncertainty, and AI reliability so that uncertain or adversarial cases are escalated instead of overclaimed.

High-confidence BEC detections can produce a `block_request` action plan. `block_request` means the platform recommends or plans blocking through configured policy workflow; it is not a claim that a mail gateway already performed durable blocking or quarantine.

## Alert and Investigation Usage

Alert severity and case priority remain based on risk and severity, not reliability score. Reliability is displayed as triage context:

- whether review is required
- why review is required
- whether deterministic policy override occurred
- whether adversarial suspicion exists
- which signal conflicts were detected

Alerts preserve `risk_score`, `decision_confidence`, `ai_reliability`, `review_required`, `recommended_handling`, review reasons, signal conflicts, and evidence contributions in the alert detail explainability payload. Cases created from alerts copy the alert explainability summary into case evidence, so case severity remains risk/impact based while confidence and reliability stay separate. Investigation details expose an explainability summary for SQL, file, and spam live-event records so the timeline can show what happened, why it was flagged, what handling was recommended, and whether review was required.

## Limitations

Phase 1 is deterministic and rule-based. It depends on the quality and availability of existing analyzer outputs. It does not perform drift detection, full cross-domain statistical calibration plotting, retraining, macro execution, dynamic sandboxing, poisoning analysis, or LLM-based decision-making.

The current confidence scores are calibrated by project fusion logic and policy thresholds. Full statistical calibration using reliability diagrams, Expected Calibration Error, and Brier Score is future work unless per-sample calibration evidence is available. A current calibration diagnostic summary is documented in `docs/benchmarks/calibration_summary.md`.

## Future Work

- calibration reports
- reliability diagrams
- model cards
- drift monitoring
- feedback poisoning protection
- dynamic sandbox connector
- LLM-assisted analyst summaries for explanation support, not final decision-making
