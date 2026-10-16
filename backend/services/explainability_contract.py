"""Shared explainability contract helpers.

The helpers in this module enrich existing analyzer explanations without
changing analyzer risk scores, decision confidence, thresholds, or actions.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Dict, Iterable, List, Optional

from backend.server.schemas.responses import (
    DecisionRationale,
    EvidenceContribution,
    ExplanationScoreSemantics,
    XAIExplanation,
)


SAFE_HANDLING = {"allow", "monitor", "review", "block", "quarantine"}


def _as_dict(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump"):
        try:
            dumped = value.model_dump()
            return dict(dumped) if isinstance(dumped, Mapping) else {}
        except Exception:
            return {}
    return {}


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _clamp01_optional(value: Any) -> Optional[float]:
    numeric = _as_float(value)
    if numeric is None:
        return None
    return max(0.0, min(1.0, numeric))


def _dedupe(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _risk_label(domain: str, threat_category: Optional[str]) -> str:
    key = f"{domain} {threat_category or ''}".lower()
    if "spam" in key or "phish" in key or "email" in key:
        return "Spam/Phishing Risk"
    if "file" in key or "upload" in key:
        return "File Risk"
    if "sql" in key or "query" in key:
        return "SQL Risk"
    return "Threat Risk"


def _handling_from_decision(decision: Optional[str]) -> str:
    action = str(decision or "").strip().lower().replace("-", "_")
    if any(token in action for token in ("block", "deny")):
        return "block"
    if "quarantine" in action:
        return "quarantine"
    if any(token in action for token in ("review", "flag", "warn")):
        return "review"
    if "monitor" in action:
        return "monitor"
    return "allow"


def _decision_type(*, handling: str, review_required: bool, policy_override: bool) -> str:
    if policy_override:
        return "policy_override"
    if review_required:
        return "review_required"
    if handling in {"block", "quarantine"}:
        return "hard_block"
    if handling == "monitor":
        return "monitor"
    return "allow"


def _direction_from_score(value: Any) -> str:
    score = _as_float(value)
    if score is None:
        return "context"
    if score >= 0.55:
        return "raises_risk"
    if score <= 0.35:
        return "lowers_risk"
    return "mixed"


def _direction_from_evidence(severity: Any, score: Any) -> str:
    sev = str(severity or "").lower()
    if sev in {"critical", "high", "medium"}:
        return "raises_risk"
    if _as_float(score) is not None:
        return _direction_from_score(score)
    return "context"


def _component_contributions(explanation: XAIExplanation) -> List[EvidenceContribution]:
    raw_attrs = list(explanation.model_attributions or [])
    weighted_items: List[Dict[str, Any]] = []
    for item in raw_attrs:
        data = _as_dict(item)
        name = str(data.get("component") or data.get("feature") or data.get("token") or "").strip()
        if not name:
            continue
        score = _as_float(data.get("score"))
        weight = _as_float(data.get("weight"))
        if score is not None and weight is not None and weight > 0:
            weighted_items.append({"name": name, "score": score, "weight": weight, "data": data})

    total_active_weight = sum(item["weight"] for item in weighted_items)
    contributions: List[EvidenceContribution] = []
    seen: set[str] = set()
    for item in raw_attrs:
        data = _as_dict(item)
        name = str(data.get("component") or data.get("feature") or data.get("token") or data.get("algorithm") or "").strip()
        if not name:
            continue
        score = data.get("score", data.get("value", data.get("weight")))
        weight = _as_float(data.get("weight"))
        normalized = None
        score_float = _as_float(data.get("score"))
        if score_float is not None and weight is not None and total_active_weight > 0:
            normalized = round((score_float * weight) / total_active_weight, 6)
        key = f"component:{name}"
        if key in seen:
            continue
        seen.add(key)
        category = "model_component" if data.get("component") else "model_attribution"
        explanation_text = (
            "Weighted fusion component; normalized contribution is score x weight divided by total active weight."
            if normalized is not None
            else "Model attribution or diagnostic component returned by the analyzer."
        )
        contributions.append(
            EvidenceContribution(
                name=name,
                category=category,
                value=score,
                weight=weight,
                normalized_contribution=normalized,
                direction=_direction_from_score(score),
                explanation=explanation_text,
                source="model_attributions",
            )
        )
    return contributions


def _evidence_contributions(explanation: XAIExplanation) -> List[EvidenceContribution]:
    contributions = _component_contributions(explanation)
    seen = {f"{item.category}:{item.name}" for item in contributions}
    for item in explanation.evidence or []:
        data = _as_dict(item)
        name = str(data.get("label") or data.get("id") or "Evidence").strip()
        source = str(data.get("source") or data.get("id") or "evidence").strip()
        key = f"evidence:{source}:{name}"
        if key in seen:
            continue
        seen.add(key)
        value = data.get("score")
        if value is None:
            value = data.get("snippet") if data.get("snippet") else True
        contributions.append(
            EvidenceContribution(
                name=name,
                category=str(data.get("source") or "evidence"),
                value=value,
                weight=None,
                normalized_contribution=None,
                direction=_direction_from_evidence(data.get("severity"), data.get("score")),
                explanation=str(data.get("description") or "Analyzer evidence item used in the decision trace."),
                source=source,
            )
        )
    return contributions


def _score_type_notes(domain: str, reliability_present: bool) -> List[str]:
    notes = [
        "Threat risk estimates how dangerous the input appears; it is not the same as decision confidence.",
        "Decision confidence is confidence in the selected class/action.",
        "Uncertainty captures threshold proximity, signal disagreement, OOD behavior, missing evidence, or low fidelity.",
    ]
    if reliability_present:
        notes.append("AI Reliability is deterministic decision-governance logic, not a learned calibration model.")
    if str(domain).lower() in {"spam", "phishing", "email"}:
        notes.append("Grey-zone spam/phishing results are routed to analyst review instead of hard detection.")
    return notes


def _plain_summary(
    *,
    risk_label: str,
    risk_score: Optional[float],
    decision_confidence: Optional[float],
    handling: str,
    review_required: bool,
    review_reasons: List[str],
) -> str:
    risk_text = f"{risk_label} is {risk_score * 100:.2f}%" if risk_score is not None else f"{risk_label} was not returned"
    conf_text = (
        f"decision confidence is {decision_confidence * 100:.2f}%"
        if decision_confidence is not None
        else "decision confidence was not returned"
    )
    if review_required:
        reason = review_reasons[0] if review_reasons else "the governance policy requires review."
        return f"{risk_text}; {conf_text}. Recommended handling is {handling}. Review is required because {reason}"
    return f"{risk_text}; {conf_text}. Recommended handling is {handling}. No review gate fired."


def _technical_summary(
    *,
    explanation: XAIExplanation,
    risk_label: str,
    handling: str,
    review_required: bool,
    contribution_count: int,
) -> str:
    thresholds = ", ".join(f"{k}={v}" for k, v in (explanation.thresholds or {}).items()) or "not returned"
    return (
        f"{risk_label} comes from the analyzer's calibrated fusion/rule pipeline. "
        f"Decision confidence is read from decision_confidence/confidence and is not rewritten by uncertainty. "
        f"{contribution_count} evidence contribution(s) are exposed for traceability. "
        f"Thresholds applied: {thresholds}. "
        f"AI Reliability recommends {handling}; review_required={str(review_required).lower()}."
    )


def complete_explainability_contract(
    explanation: Optional[XAIExplanation],
    *,
    domain: str,
    input_summary: Optional[str] = None,
    limitations: Optional[List[str]] = None,
) -> Optional[XAIExplanation]:
    """Populate the unified explainability contract on an existing explanation."""
    if explanation is None:
        return None

    reliability = explanation.ai_reliability
    risk_value = explanation.spam_risk if explanation.spam_risk is not None else explanation.risk_score
    risk_score = _clamp01_optional(risk_value)
    decision_confidence = _clamp01_optional(
        explanation.decision_confidence if explanation.decision_confidence is not None else explanation.confidence
    )
    uncertainty_score = _clamp01_optional(explanation.uncertainty_score)
    ood_score = _clamp01_optional(explanation.ood_score)
    fidelity_score = _clamp01_optional(explanation.fidelity_score)
    reliability_score = _clamp01_optional(getattr(reliability, "reliability_score", None))
    label = _risk_label(domain, explanation.threat_category)
    handling = str(getattr(reliability, "recommended_handling", "") or "").strip().lower()
    if handling not in SAFE_HANDLING:
        handling = _handling_from_decision(explanation.decision)
    review_reasons = list(getattr(reliability, "review_reasons", []) or [])
    review_required = bool(getattr(reliability, "review_required", False) or explanation.abstain_reason or handling == "review")
    policy_override = bool(getattr(reliability, "policy_override", False))

    base_limitations = [
        "This score is a calibrated project risk score, not a guaranteed probability.",
        "Benchmark precision, recall, F1, FPR, and accuracy require labelled evaluation data and are not single-event scores.",
    ]
    if str(domain).lower() in {"file", "upload"} and not any(
        str(step.stage if hasattr(step, "stage") else _as_dict(step).get("stage")).lower() == "dynamic_analysis"
        for step in (explanation.decision_trace or [])
    ):
        base_limitations.append("Dynamic sandboxing was not used in this file explanation payload.")
    if reliability is not None:
        base_limitations.append("AI Reliability is deterministic decision-governance logic, not a learned calibration model.")
    if input_summary:
        base_limitations.append(f"Input summary: {input_summary}")

    final_limitations = _dedupe(
        list(explanation.limitations or [])
        + list(explanation.caveats or [])
        + base_limitations
        + list(limitations or [])
    )
    contributions = _evidence_contributions(explanation)

    explanation.score_semantics = ExplanationScoreSemantics(
        risk_score=risk_score,
        risk_label=label,
        decision_confidence=decision_confidence,
        uncertainty_score=uncertainty_score,
        uncertainty_components=explanation.uncertainty_components,
        ood_score=ood_score,
        fidelity_score=fidelity_score,
        reliability_score=reliability_score,
        score_type_notes=_score_type_notes(domain, reliability is not None),
    )
    explanation.evidence_contributions = contributions or None
    explanation.decision_rationale = DecisionRationale(
        final_decision=explanation.decision,
        decision_type=_decision_type(
            handling=handling,
            review_required=review_required,
            policy_override=policy_override,
        ),
        recommended_handling=handling if handling in SAFE_HANDLING else "review",
        hard_decision=bool(handling in {"block", "quarantine"} and not review_required),
        review_required=review_required,
        review_reasons=review_reasons,
        thresholds_applied=explanation.thresholds or {},
        policy_overrides=["Deterministic policy override was applied."] if policy_override else [],
        limitations=final_limitations,
    )
    explanation.plain_language_summary = explanation.plain_language_summary or _plain_summary(
        risk_label=label,
        risk_score=risk_score,
        decision_confidence=decision_confidence,
        handling=handling,
        review_required=review_required,
        review_reasons=review_reasons,
    )
    explanation.technical_summary = explanation.technical_summary or _technical_summary(
        explanation=explanation,
        risk_label=label,
        handling=handling,
        review_required=review_required,
        contribution_count=len(contributions),
    )
    explanation.limitations = final_limitations
    return explanation

