"""Deterministic AI reliability assessment for analyzer decisions.

This layer consumes existing analyzer outputs. It does not mutate risk scores,
decision confidence, thresholds, rules, or enforcement decisions.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Dict, List, Optional, Tuple

from backend.server.schemas.responses import AIReliabilityAssessment


SAFE_HANDLING_ACTIONS = {"allow", "monitor", "review", "block", "quarantine"}


def _clamp01(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _flatten_scores(payload: Mapping[str, Any] | None, prefix: str = "") -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    if not isinstance(payload, Mapping):
        return flat
    for key, value in payload.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            flat.update(_flatten_scores(value, name))
        else:
            flat[name] = value
    return flat


def _max_score_by_keywords(flat: Mapping[str, Any], keywords: Tuple[str, ...]) -> Optional[float]:
    values: List[float] = []
    for key, value in flat.items():
        key_lc = str(key).lower()
        if not any(keyword in key_lc for keyword in keywords):
            continue
        numeric = _as_float(value)
        if numeric is not None:
            values.append(_clamp01(numeric))
    return max(values) if values else None


def _truthy_flag_by_keywords(flat: Mapping[str, Any], keywords: Tuple[str, ...]) -> bool:
    for key, value in flat.items():
        key_lc = str(key).lower()
        if any(keyword in key_lc for keyword in keywords) and bool(value):
            return True
    return False


def _normalize_tokens(values: Optional[List[str]]) -> List[str]:
    if not values:
        return []
    normalized: List[str] = []
    for value in values:
        token = str(value or "").strip().lower()
        if token and token not in normalized:
            normalized.append(token)
    return normalized


def _detect_policy_override(
    *,
    final_action: Optional[str],
    rule_hits: List[str],
    flat_scores: Mapping[str, Any],
) -> bool:
    action = str(final_action or "").strip().lower()
    policy_tokens = (
        "policy",
        "override",
        "blocklist",
        "allowlist",
        "deny",
        "disallowed",
        "quarantine",
        "critical",
        "yara",
        "hard_block",
        "yaml_critical",
    )
    if any(token in action for token in ("policy_override", "deny_non_migration")):
        return True
    if any(any(policy_token in hit for policy_token in policy_tokens) for hit in rule_hits):
        return True
    return _truthy_flag_by_keywords(
        flat_scores,
        ("hard_block_signal", "policy_override", "blocklist", "critical_rule", "yara_critical"),
    )


def _detect_adversarial_suspicion(
    *,
    domain: str,
    rule_hits: List[str],
    flat_scores: Mapping[str, Any],
) -> bool:
    joined_hits = " ".join(rule_hits)
    domain_lc = str(domain or "").lower()
    common_tokens = (
        "obfuscat",
        "encoded",
        "homoglyph",
        "zero_width",
        "zero-width",
        "punycode",
        "mismatch",
        "evasion",
        "split",
    )
    sql_tokens = (
        "comment",
        "union",
        "time",
        "sleep",
        "benchmark",
        "waitfor",
        "tautology",
        "yaml_critical_pattern",
    )
    file_tokens = (
        "extension_content_mismatch",
        "double_extension",
        "path_traversal",
        "macro",
        "openaction",
        "javascript",
        "pdf_active",
        "yara",
    )
    spam_tokens = (
        "hxxp",
        "bracketed",
        "display_link",
        "display-link",
        "domain_mismatch",
        "ip_link",
        "brand_lookalike",
        "sender_punycode",
    )
    domain_tokens = common_tokens
    if domain_lc == "sql":
        domain_tokens = common_tokens + sql_tokens
    elif domain_lc == "file":
        domain_tokens = common_tokens + file_tokens
    elif domain_lc in {"spam", "phishing", "email"}:
        domain_tokens = common_tokens + spam_tokens

    if any(token in joined_hits for token in domain_tokens):
        return True
    return _truthy_flag_by_keywords(
        flat_scores,
        (
            "extension_mismatch",
            "signature_mismatch",
            "path_traversal",
            "macro_risky",
            "pdf_active",
            "sender_punycode",
            "domain_mismatch",
            "display_link_mismatch",
            "zero_width",
            "homoglyph",
        ),
    )


def _detect_signal_conflicts(
    *,
    domain: str,
    risk_score: Optional[float],
    decision_confidence: Optional[float],
    ood_score: float,
    score_breakdown: Optional[Dict[str, Any]],
    rule_hits: List[str],
) -> Tuple[List[str], bool]:
    flat = _flatten_scores(score_breakdown)
    conflicts: List[str] = []
    strong = False
    domain_lc = str(domain or "").lower()

    model_score = _max_score_by_keywords(
        flat,
        ("model", "ml", "classical", "transformer", "nlp", "anomaly", "text"),
    )
    rule_score = _max_score_by_keywords(flat, ("rule", "heuristic", "ast", "signature", "indicator"))
    yara_score = _max_score_by_keywords(flat, ("yara", "signature"))
    reputation_score = _max_score_by_keywords(flat, ("reputation", "url", "domain", "header", "campaign", "fraud"))
    deterministic_spam_fraud = bool(
        domain_lc in {"spam", "phishing", "email"}
        and (
            any("bec_fraud_hard_signal" in hit or "fraud_pattern_hard_signal" in hit for hit in rule_hits)
            or _truthy_flag_by_keywords(flat, ("bec_fraud_hard_signal", "fraud_pattern_hard_signal"))
        )
    )

    high_rule_evidence = bool(rule_hits) or (rule_score is not None and rule_score >= 0.75)
    if model_score is not None and model_score <= 0.35 and high_rule_evidence:
        if deterministic_spam_fraud:
            conflicts.append("model_low_deterministic_fraud_high")
        elif domain_lc == "file" and (yara_score is not None and yara_score >= 0.75):
            conflicts.append("yara_high_model_low")
            strong = True
        elif domain_lc in {"spam", "phishing", "email"} and (reputation_score is not None and reputation_score >= 0.75):
            conflicts.append("reputation_high_model_low")
            strong = True
        elif domain_lc == "sql":
            conflicts.append("model_low_rule_high")
            strong = True
        else:
            conflicts.append("heuristic_high_model_low")
            strong = True

    low_rule_score = rule_score is not None and rule_score <= 0.25 and not rule_hits
    if model_score is not None and model_score >= 0.75 and low_rule_score:
        conflicts.append("model_high_rule_low")

    if (
        ood_score > 0.35
        and decision_confidence is not None
        and decision_confidence >= 0.85
    ):
        conflicts.append("ood_high_confidence_high")

    if risk_score is not None and 0.45 <= risk_score <= 0.75:
        critical_flag = _truthy_flag_by_keywords(
            flat,
            ("critical", "hard_block", "yara", "path_traversal", "macro_risky", "blocklist"),
        ) or any(
            any(token in hit for token in ("critical", "yara", "path_traversal", "macro", "blocklist"))
            for hit in rule_hits
        )
        if critical_flag:
            conflicts.append("critical_indicator_moderate_risk")
            strong = True

    ordered: List[str] = []
    for item in conflicts:
        if item not in ordered:
            ordered.append(item)
    return ordered, strong


def _recommended_handling(
    *,
    final_action: Optional[str],
    review_required: bool,
    reliability_status: str,
    risk_score: Optional[float],
    decision_confidence: Optional[float],
    policy_override: bool,
) -> str:
    action = str(final_action or "").strip().lower().replace("-", "_")
    block_action = any(token in action for token in ("block", "deny"))
    quarantine_action = "quarantine" in action
    high_risk_high_confidence = bool(
        risk_score is not None
        and decision_confidence is not None
        and risk_score >= 0.80
        and decision_confidence >= 0.80
    )

    # Deterministic hard policy can still advise block/quarantine, but
    # ordinary low-confidence or grey-zone cases must remain review-first.
    if policy_override and block_action:
        return "block"
    if policy_override and quarantine_action:
        return "quarantine"
    if review_required:
        return "review"
    if block_action:
        return "block" if high_risk_high_confidence else "review"
    if quarantine_action:
        return "quarantine" if high_risk_high_confidence else "review"
    if reliability_status == "reliable" and risk_score is not None and risk_score < 0.35:
        return "allow"
    if reliability_status == "reliable":
        return "monitor"
    return "review"


def assess_ai_reliability(
    *,
    domain: str,
    risk_score: Any,
    decision_confidence: Any,
    uncertainty_score: Any = 0.0,
    ood_score: Any = 0.0,
    fidelity_score: Any = 1.0,
    score_breakdown: Optional[Dict[str, Any]] = None,
    final_action: Optional[str] = None,
    severity: Optional[str] = None,
    rule_hits: Optional[List[str]] = None,
    model_version: Optional[str] = None,
    ruleset_version: Optional[str] = None,
) -> AIReliabilityAssessment:
    """Assess whether an existing analyzer decision is reliable enough to accept.

    The original analyzer scores are read-only inputs. The returned reliability
    score describes trustworthiness of the selected decision, not threat risk.
    """
    risk_raw = _as_float(risk_score)
    confidence_raw = _as_float(decision_confidence)
    uncertainty_raw = _as_float(uncertainty_score)
    ood_raw = _as_float(ood_score)
    fidelity_raw = _as_float(fidelity_score)

    missing_scores: List[str] = []
    if risk_raw is None:
        missing_scores.append("risk_score")
    if confidence_raw is None:
        missing_scores.append("decision_confidence")

    risk = _clamp01(risk_raw) if risk_raw is not None else None
    confidence = _clamp01(confidence_raw) if confidence_raw is not None else 0.0
    uncertainty = _clamp01(uncertainty_raw) if uncertainty_raw is not None else 0.0
    ood = _clamp01(ood_raw) if ood_raw is not None else 0.0
    fidelity = _clamp01(fidelity_raw) if fidelity_raw is not None else 1.0
    if fidelity_raw is None:
        missing_scores.append("fidelity_score")

    normalized_hits = _normalize_tokens(rule_hits)
    flat_scores = _flatten_scores(score_breakdown)
    signal_conflicts, strong_conflict = _detect_signal_conflicts(
        domain=domain,
        risk_score=risk,
        decision_confidence=confidence if confidence_raw is not None else None,
        ood_score=ood,
        score_breakdown=score_breakdown,
        rule_hits=normalized_hits,
    )
    policy_override = _detect_policy_override(
        final_action=final_action,
        rule_hits=normalized_hits,
        flat_scores=flat_scores,
    )
    adversarial_suspicion = _detect_adversarial_suspicion(
        domain=domain,
        rule_hits=normalized_hits,
        flat_scores=flat_scores,
    )

    grey_zone = bool(risk is not None and 0.45 <= risk <= 0.65)
    reliability_score = confidence
    reliability_score *= 1.0 - 0.30 * uncertainty
    reliability_score *= 1.0 - 0.35 * ood
    reliability_score *= 0.70 + 0.30 * fidelity

    additive_penalties: Dict[str, float] = {}
    if grey_zone:
        additive_penalties["grey_zone_risk"] = 0.15
    if signal_conflicts:
        additive_penalties["signal_conflict"] = 0.20 if strong_conflict else 0.10
    if missing_scores:
        additive_penalties["missing_scores"] = 0.15
    if adversarial_suspicion:
        additive_penalties["adversarial_suspicion"] = 0.20

    reliability_score -= sum(additive_penalties.values())
    reliability_score = round(_clamp01(reliability_score), 4)

    action_lc = str(final_action or "").strip().lower().replace("-", "_")
    final_action_requires_review = any(token in action_lc for token in ("review", "flag", "quarantine"))
    review_reasons: List[str] = []
    if confidence_raw is None or confidence < 0.70:
        review_reasons.append("Decision confidence is below the operational threshold.")
    if uncertainty > 0.40:
        review_reasons.append("Uncertainty score exceeds the operational review threshold.")
    if ood > 0.35:
        review_reasons.append("OOD score indicates an unfamiliar input pattern.")
    if fidelity < 0.60:
        review_reasons.append("Low explanation fidelity reduces decision trust.")
    if grey_zone:
        review_reasons.append("Risk score is in the grey-zone range.")
    if strong_conflict:
        review_reasons.append("Model and rule-based signals disagree.")
    if policy_override:
        review_reasons.append("Deterministic policy override was applied.")
    if adversarial_suspicion:
        review_reasons.append("Potential adversarial or obfuscation indicators were detected.")
    if missing_scores:
        review_reasons.append("Required reliability input scores were missing.")
    if final_action_requires_review:
        review_reasons.append("The analyzer action routes this event to review or quarantine.")

    review_required = bool(review_reasons)
    if policy_override:
        reliability_status = "policy_override"
    elif adversarial_suspicion:
        reliability_status = "adversarial_suspicion"
    elif strong_conflict:
        reliability_status = "conflicting_signals"
    elif ood > 0.35:
        reliability_status = "out_of_distribution"
    elif confidence_raw is None or confidence < 0.70:
        reliability_status = "low_confidence"
    elif review_required:
        reliability_status = "needs_review"
    else:
        reliability_status = "reliable"

    handling = _recommended_handling(
        final_action=final_action,
        review_required=review_required,
        reliability_status=reliability_status,
        risk_score=risk,
        decision_confidence=confidence if confidence_raw is not None else None,
        policy_override=policy_override,
    )

    return AIReliabilityAssessment(
        reliability_score=reliability_score,
        reliability_status=reliability_status,
        review_required=review_required,
        review_reasons=review_reasons,
        signal_conflicts=signal_conflicts,
        policy_override=policy_override,
        adversarial_suspicion=adversarial_suspicion,
        recommended_handling=handling if handling in SAFE_HANDLING_ACTIONS else "review",
        reliability_factors={
            "domain": domain,
            "explanation": (
                "AI Reliability starts from decision confidence and is reduced by uncertainty, OOD, "
                "low fidelity, signal conflict, policy override, adversarial suspicion, and missing evidence. "
                "It is deterministic governance logic and does not modify risk_score or decision_confidence."
            ),
            "risk_score": risk,
            "decision_confidence": confidence if confidence_raw is not None else None,
            "uncertainty_score": uncertainty,
            "ood_score": ood,
            "fidelity_score": fidelity,
            "grey_zone_risk": grey_zone,
            "strong_signal_conflict": strong_conflict,
            "deterministic_spam_fraud_signal": any(
                "bec_fraud_hard_signal" in hit or "fraud_pattern_hard_signal" in hit for hit in normalized_hits
            ),
            "missing_scores": missing_scores,
            "multiplicative_penalties": {
                "uncertainty_factor": round(1.0 - 0.30 * uncertainty, 4),
                "ood_factor": round(1.0 - 0.35 * ood, 4),
                "fidelity_factor": round(0.70 + 0.30 * fidelity, 4),
            },
            "additive_penalties": additive_penalties,
            "final_action": final_action,
            "severity": severity,
            "model_version": model_version,
            "ruleset_version": ruleset_version,
        },
    )
