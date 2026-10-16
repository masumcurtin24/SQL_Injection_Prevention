# File Dynamic-Request Policy Summary

- sample_count: `77`
- request_rate: `0.0`
- not_requested_rate: `1.0`
- skip_rate: `0.0`
- completed_rate: `0.0`
- unavailable_rate: `0.0`
- failed_rate: `0.0`
- running_or_deferred_rate: `0.0`
- provider_run_label: `disabled`
- provider_name: `none`

## Top Request Decisions
- `not_requested`: count=77, rate=1.0

## Top Skip Reasons
- `dynamic_disabled`: count=77, rate=1.0

## Dynamic State Visibility
- completed_rate: `0.0`
- unavailable_rate: `0.0`
- failed_rate: `0.0`
- running_or_deferred_rate: `0.0`
- not_requested_rate: `1.0`
- requested_but_provider_unavailable_count: `0`

## Provider Readiness
- run_label: `disabled`
- provider_name: `none`
- configured: `False`
- available: `False`
- validation_state: `live_not_validated`
- validation_reason: `validation_provider_mismatch`

## Informational Dynamic Delta
- additional_iocs_from_dynamic_total: `0`
- additional_evidence_items_from_dynamic_total: `0`
- samples_with_dynamic_completed: `0`
- limitation: No completed dynamic-analysis samples were observed in this run; IOC/evidence deltas are informational only.
- limitation: Dynamic provider produced no additional evidence/IOCs; this does not prove dynamic analysis has no value.
- limitation: Dynamic-policy metrics reflect verdict dynamic_analysis state only; they are not inferred from logs.
- limitation: Quality/value gates for dynamic IOC/evidence uplift are intentionally informational until live provider data is established.
