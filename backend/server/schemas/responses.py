# backend/server/schemas/responses.py
from pydantic import BaseModel, Field, ConfigDict # Ensure ConfigDict is imported for Pydantic v2
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime, date # Ensure date is imported if used
from backend.server.schemas.identity import UserSummary

class XAIExplanationEvidence(BaseModel):
    """Atomic evidence item that supports the final decision."""
    id: str = Field(description="Stable code for the indicator (e.g., union_select, suspicious_tld).")
    label: str = Field(description="Human-readable indicator name.")
    severity: Optional[str] = Field(None, description="Indicator severity (low/medium/high/critical).")
    description: Optional[str] = Field(None, description="Why this indicator matters.")
    snippet: Optional[str] = Field(None, description="Small snippet from the input that triggered the indicator.")
    start: Optional[int] = Field(None, description="Character offset start (when applicable).")
    end: Optional[int] = Field(None, description="Character offset end (when applicable).")
    score: Optional[float] = Field(None, description="Indicator weight or contribution (0..1), if available.")
    source: Optional[str] = Field(None, description="Source subsystem (heuristics/model/policy/yara/url_indicators).")
    impact: Optional[str] = Field(None, description="Potential security impact implied by this indicator.")

    model_config = ConfigDict(from_attributes=True)

class XAIExplanationTraceStep(BaseModel):
    """Decision trace step to support explainability."""
    stage: str = Field(description="Pipeline stage name (e.g., heuristics, anomaly_model, aggregator).")
    summary: str = Field(description="Short human-readable summary of the stage output.")
    details: Optional[Dict[str, Any]] = Field(None, description="Structured stage outputs (scores, labels, thresholds).")

    model_config = ConfigDict(from_attributes=True)


class AIReliabilityAssessment(BaseModel):
    """Trustworthiness assessment for an already selected AI decision."""
    reliability_score: float = Field(description="Trustworthiness of the selected AI decision after reliability penalties (0..1).")
    reliability_status: Literal[
        "reliable",
        "needs_review",
        "low_confidence",
        "out_of_distribution",
        "conflicting_signals",
        "policy_override",
        "adversarial_suspicion",
    ] = Field(description="Deterministic reliability status for analyst triage.")
    review_required: bool = Field(description="True when the decision should be reviewed by a human analyst.")
    review_reasons: List[str] = Field(default_factory=list, description="Human-readable reasons why review is recommended.")
    signal_conflicts: List[str] = Field(default_factory=list, description="Detected disagreements between available model, rule, reputation, or OOD signals.")
    policy_override: bool = Field(False, description="True when deterministic policy/rule evidence materially influenced the decision.")
    adversarial_suspicion: bool = Field(False, description="True when existing indicators suggest possible evasion or adversarial behaviour.")
    recommended_handling: Literal["allow", "monitor", "review", "block", "quarantine"] = Field(description="Advisory handling derived from reliability and existing final action.")
    reliability_factors: Dict[str, Any] = Field(default_factory=dict, description="Structured reliability inputs, penalties, and threshold flags.")

    model_config = ConfigDict(from_attributes=True)


class SpamDecisionDisplay(BaseModel):
    """Frontend-safe display policy for spam/phishing outcomes."""
    status_label: str = Field(description="User-facing status label aligned with review and handling policy.")
    status_color: Literal["green", "amber", "red"] = Field(description="Display tone for the top-level spam status card.")
    hard_detection: bool = Field(description="False when the result is grey-zone/review-required rather than a hard detection.")
    review_required: bool = Field(description="True when analyst review is required before treating the outcome as final.")
    recommended_handling: Literal["allow", "monitor", "review", "block", "quarantine"] = Field(
        description="Handling route used by the display policy."
    )
    reliability_status: Optional[str] = Field(None, description="Reliability state that informed the display policy.")
    detail: Optional[str] = Field(None, description="Short rationale for the selected display state.")

    model_config = ConfigDict(from_attributes=True)


class ExplanationScoreSemantics(BaseModel):
    """Shared score semantics for analyzer explanations."""
    risk_score: Optional[float] = Field(None, description="Threat-risk score (0..1), not decision confidence.")
    risk_label: Optional[str] = Field(None, description="Domain-specific risk label, e.g. SQL Risk or Spam/Phishing Risk.")
    decision_confidence: Optional[float] = Field(None, description="Confidence in the selected final class/action (0..1).")
    uncertainty_score: Optional[float] = Field(None, description="Evidence weakness / disagreement / OOD uncertainty (0..1).")
    uncertainty_components: Optional[Dict[str, float]] = Field(None, description="Structured uncertainty component scores.")
    ood_score: Optional[float] = Field(None, description="Out-of-distribution or unfamiliar-input score (0..1).")
    fidelity_score: Optional[float] = Field(None, description="Agreement/faithfulness proxy for the explanation (0..1).")
    reliability_score: Optional[float] = Field(None, description="AI Reliability trustworthiness score (0..1), when assessed.")
    score_type_notes: List[str] = Field(default_factory=list, description="Human-readable notes that prevent score misinterpretation.")

    model_config = ConfigDict(from_attributes=True)


class EvidenceContribution(BaseModel):
    """Mathematically traceable contribution or evidence signal."""
    name: str = Field(description="Signal, model, rule, heuristic, or reputation component name.")
    category: str = Field(description="Signal family such as model, heuristic, reputation, yara, policy, or evidence.")
    value: Optional[Any] = Field(None, description="Observed value or component score.")
    weight: Optional[float] = Field(None, description="Configured contribution weight, if applicable.")
    normalized_contribution: Optional[float] = Field(
        None,
        description="For weighted fusion: (component_score * weight) / total_active_weight.",
    )
    direction: str = Field(description="How this signal affected the risk decision: raises_risk, lowers_risk, neutral, mixed, or context.")
    explanation: str = Field(description="Human-readable explanation of the signal.")
    source: str = Field(description="Subsystem/source that produced the signal.")

    model_config = ConfigDict(from_attributes=True)


class DecisionRationale(BaseModel):
    """Review-aware decision rationale separate from raw scores."""
    final_decision: str = Field(description="Final analyzer decision/action.")
    decision_type: str = Field(description="Decision class such as allow, monitor, review_required, hard_block, or policy_override.")
    recommended_handling: Literal["allow", "monitor", "review", "block", "quarantine"] = Field(
        description="Recommended handling route for operators."
    )
    hard_decision: bool = Field(description="True only when the system can treat the decision as a hard automated outcome.")
    review_required: bool = Field(description="True when analyst review is required before final handling.")
    review_reasons: List[str] = Field(default_factory=list, description="Specific review gates that fired.")
    thresholds_applied: Dict[str, Any] = Field(default_factory=dict, description="Thresholds used in the final decision.")
    policy_overrides: List[str] = Field(default_factory=list, description="Deterministic policy overrides that influenced the decision.")
    limitations: List[str] = Field(default_factory=list, description="Known score, evidence, or operational limitations.")

    model_config = ConfigDict(from_attributes=True)


class XAIExplanation(BaseModel):
    """Structured explainability payload (Explainable AI / decision trace)."""
    decision: str = Field(description="High-level decision (e.g., ALLOW/WARN/BLOCK or a policy action code).")
    severity: Optional[str] = Field(None, description="Overall severity/risk level.")
    threat_category: Optional[str] = Field(None, description="Threat category (e.g., Boolean SQLi, Time-based SQLi, Spam/Phishing).")
    risk_score: Optional[float] = Field(None, description="Threat-risk score (0..1), where higher means more dangerous.")
    decision_confidence: Optional[float] = Field(None, description="Confidence in the selected final decision/class (0..1).")
    confidence: Optional[float] = Field(
        None,
        description="Backward-compatible alias for decision_confidence (0..1), not a threat-risk score.",
    )
    spam_risk: Optional[float] = Field(None, description="Spam/phishing risk score (0..1), when the explanation belongs to email analysis.")
    confidence_label: Optional[str] = Field(None, description="Qualitative confidence bucket (low/medium/high).")
    uncertainty_score: Optional[float] = Field(None, description="Estimated uncertainty for this decision (0..1).")
    uncertainty_components: Optional[Dict[str, float]] = Field(
        None,
        description="Structured uncertainty provenance such as threshold proximity, disagreement, missing inputs, and OOD score.",
    )
    fidelity_score: Optional[float] = Field(None, description="Estimated explanation fidelity/faithfulness (0..1).")
    ood_score: Optional[float] = Field(None, description="Out-of-distribution score (0..1), when available.")
    abstain_reason: Optional[str] = Field(None, description="Reason why manual review or abstention is recommended.")
    impact: Optional[str] = Field(None, description="Likely attacker impact if allowed to proceed.")
    evidence: Optional[List[XAIExplanationEvidence]] = Field(None, description="List of evidence items supporting the decision.")
    highlights: Optional[List[Dict[str, Any]]] = Field(None, description="Optional highlight spans (character offsets) for UI rendering.")
    model_attributions: Optional[List[Dict[str, Any]]] = Field(None, description="Optional model attributions (e.g., SHAP top features).")
    decision_trace: Optional[List[XAIExplanationTraceStep]] = Field(None, description="Step-by-step decision trace across subsystems.")
    remediation: Optional[List[str]] = Field(None, description="Actionable remediation guidance.")
    counterfactual: Optional[str] = Field(None, description="What change would likely reduce risk for this input.")
    model_version: Optional[str] = Field(None, description="Active model version or model family used for this decision.")
    ruleset_version: Optional[str] = Field(None, description="Rules/signature set version used for this decision.")
    policy_version: Optional[str] = Field(None, description="Policy profile/version used for thresholding and actions.")
    thresholds: Optional[Dict[str, float]] = Field(None, description="Decision thresholds used for the final decision.")
    provenance: Optional[Dict[str, Any]] = Field(None, description="Provenance metadata (pipeline, components, timestamps).")
    caveats: Optional[List[str]] = Field(None, description="Known caveats or uncertainty notes for analyst context.")
    ai_reliability: Optional[AIReliabilityAssessment] = Field(
        None,
        description="Reliability and human-review assessment for the selected AI decision.",
    )
    score_semantics: Optional[ExplanationScoreSemantics] = Field(
        None,
        description="Unified risk/confidence/uncertainty/reliability semantics for frontend and reports.",
    )
    evidence_contributions: Optional[List[EvidenceContribution]] = Field(
        None,
        description="Traceable evidence and component contributions used to support the decision.",
    )
    decision_rationale: Optional[DecisionRationale] = Field(
        None,
        description="Review-aware action rationale and decision policy output.",
    )
    plain_language_summary: Optional[str] = Field(
        None,
        description="Professor/analyst-friendly explanation of the decision.",
    )
    technical_summary: Optional[str] = Field(
        None,
        description="Technical explanation of score calculation, signals, thresholds, and governance.",
    )
    limitations: Optional[List[str]] = Field(
        None,
        description="Explicit limitations such as calibration scope, missing evidence, unavailable sandboxing, or non-learned reliability.",
    )

    model_config = ConfigDict(from_attributes=True)

class AnomalyDetectionResult(BaseModel):
    is_anomalous: bool = Field(description="True if the query is considered anomalous, False otherwise.")
    score: float = Field(description="Anomaly score from the model.")
    prediction_label: str = Field(description="Human-readable label.")
    
    model_config = ConfigDict(from_attributes=True)

class QueryValidationResult(BaseModel):
    classification_label: str = Field(description="Classification from the NLP model.")
    classification_score: Optional[float] = Field(None, description="Confidence score for the classification.")
    
    model_config = ConfigDict(from_attributes=True)

class CombinedRiskAssessment(BaseModel):
    overall_risk_level: str = Field(description="Calculated overall risk level.")
    suggested_action: str = Field(description="A suggested action based on the combined analysis.")
    reasoning: Optional[List[str]] = Field(None, description="Brief reasons for the assessment.")
    calibrated_risk_score: Optional[float] = Field(
        None,
        description="Calibrated aggregate risk score (0.0 - 1.0).",
    )
    signal_contributions: Optional[Dict[str, float]] = Field(
        None,
        description="Weighted contribution of signal families (heuristics/anomaly/nlp/ast).",
    )
    ast_features: Optional[Dict[str, Any]] = Field(
        None,
        description="AST/structural SQL features used in risk calibration.",
    )
    
    model_config = ConfigDict(from_attributes=True)

class SQLHeuristicsResult(BaseModel):
    suspected: bool = Field(description="True if heuristic signatures suggest injection.")
    hits: List[str] = Field(default_factory=list, description="Matched heuristic indicators.")
    heuristic_score: Optional[float] = Field(None, description="Aggregated heuristic score (0.0 - 1.0).")
    
    model_config = ConfigDict(from_attributes=True)


class SQLPrecisionEvaluationResponse(BaseModel):
    sample_count: int = Field(description="Total evaluated samples.")
    confusion_matrix: Dict[str, int] = Field(description="Binary confusion matrix counts.")
    precision: float = Field(description="Precision score.")
    recall: float = Field(description="Recall score.")
    f1: float = Field(description="F1 score.")
    accuracy: float = Field(description="Accuracy score.")
    thresholds: Dict[str, float] = Field(description="Scoring thresholds used for evaluation.")
    false_positives: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Subset of false-positive samples with explanation fields.",
    )
    false_negatives: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Subset of false-negative samples with explanation fields.",
    )
    predictions: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Optional per-sample prediction rows when include_predictions=true.",
    )

class AnalysisResponse(BaseModel): # For SQL Query Analysis
    query_received: str
    analysis_timestamp: datetime
    analysis_id: Optional[str] = None
    anomaly_detection: AnomalyDetectionResult
    query_validation: Optional[QueryValidationResult] = None
    heuristics_detection: Optional[SQLHeuristicsResult] = None
    combined_assessment: Optional[CombinedRiskAssessment] = None
    explanation: Optional[XAIExplanation] = None
    ai_reliability: Optional[AIReliabilityAssessment] = None
    defender_actions: Optional[List[str]] = Field(None, description="Policy actions selected by Defender AI incident response.")
    defender_action_summary: Optional[Dict[str, Any]] = Field(None, description="Structured incident response decision details.")
    errors: Optional[List[str]] = None
    
    model_config = ConfigDict(from_attributes=True, json_schema_extra={
        "example": {
            "query_received": "SELECT * FROM users WHERE id = 1 OR 1=1 -- comment",
            "analysis_timestamp": "2025-05-18T10:30:00.123Z",
            "analysis_id": "sql-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "anomaly_detection": {"is_anomalous": True, "score": -0.15, "prediction_label": "Anomalous"},
            "query_validation": {"classification_label": "Malicious Signature", "classification_score": 0.92},
            "combined_assessment": {"overall_risk_level": "High", "suggested_action": "BLOCK_IMMEDIATE", "reasoning": ["Anomaly detected", "Malicious signature found"]},
            "errors": None
        }
    })

class SpamClassificationResult(BaseModel):
    is_spam: bool
    spam_score: Optional[float] = None
    decision_confidence: Optional[float] = Field(
        None,
        description="Confidence in the selected email class. For benign classifications, low spam_score means high decision confidence.",
    )
    classification_label: str
    
    model_config = ConfigDict(from_attributes=True)

class EmailAnalysisResponse(BaseModel):
    received_subject: Optional[str] = None
    analysis_timestamp: datetime
    analysis_id: str
    spam_classification: SpamClassificationResult
    errors: Optional[List[str]] = None
    url_indicators: Optional[Dict[str, Any]] = None
    meta_features: Optional[Dict[str, Any]] = None
    score_breakdown: Optional[Dict[str, Any]] = None
    explanation: Optional[XAIExplanation] = None
    ai_reliability: Optional[AIReliabilityAssessment] = None
    decision_display: Optional[SpamDecisionDisplay] = Field(
        None,
        description="Review-aware top-level spam/phishing display policy for frontend rendering.",
    )
    defender_actions: Optional[List[str]] = Field(None, description="Policy actions selected by Defender AI incident response.")
    defender_action_summary: Optional[Dict[str, Any]] = Field(None, description="Structured incident response decision details.")
    
    model_config = ConfigDict(from_attributes=True, json_schema_extra={
        "example": {
            "received_subject": "Limited Time Offer!",
            "analysis_timestamp": "2025-05-18T10:35:00.123Z",
            "analysis_id": "email-spam-xxxxxxxx",
            "spam_classification": {"is_spam": True, "spam_score": 0.95, "decision_confidence": 0.95, "classification_label": "Spam"},
            "errors": None
        }
    })

# --- Schemas for File Analysis (Consolidated and Corrected) ---
class FileTypeValidationResult(BaseModel):
    detected_mime_type: Optional[str] = Field(None, description="MIME type detected from file content/extension.")
    is_allowed_type: Optional[bool] = Field(None, description="True if the detected file type is within an allowed list.")
    extension_provided: Optional[str] = Field(None, description="File extension provided in the filename.")
    
    model_config = ConfigDict(from_attributes=True)

class MalwareScanResult(BaseModel): # For YARA/Signature based
    scan_engine_version: Optional[str] = Field(None, description="Scan engine version (e.g., YARA ruleset version).")
    is_malicious: bool = Field(description="True if known malware signature/rule was matched, False otherwise.")
    threat_name: Optional[str] = Field(None, description="Name of the detected threat/rule, if any.")
    scan_details: Optional[Dict[str, Any]] = Field(None, description="Additional details (e.g., matched YARA rules).")
    
    model_config = ConfigDict(from_attributes=True)

class MLScanResult(BaseModel): 
    model_name: Optional[str] = Field(None, description="Name or version of the ML model used.")
    is_suspicious_ml: bool = Field(description="True if the ML model classified the content as suspicious/malicious.")
    prediction_label_ml: Optional[str] = Field(None, description="Label predicted by the ML model (e.g., 'Benign_Text', 'Malicious_Text').")
    prediction_score_ml: Optional[float] = Field(None, description="Confidence score from the ML model.")
    classifier_name: Optional[str] = Field(None, description="Classifier class name (e.g., RandomForestClassifier, LogisticRegression).")
    vectorizer_name: Optional[str] = Field(None, description="Vectorizer class name (e.g., TfidfVectorizer).")
    top_tokens: Optional[List[str]] = Field(None, description="Top tokens (n-grams) by tf-idf weight in this sample.")
    evidence_terms: Optional[List[str]] = Field(None, description="Suspicious terms matched in content (e.g., 'cve-', 'exploit', 'powershell').")
    shap_algorithm: Optional[str] = Field(None, description="SHAP explainer used (e.g., TreeExplainer, LinearExplainer).")
    shap_top_features: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Top SHAP feature contributions for this sample: [{ token, value }].",
    )
    
    model_config = ConfigDict(from_attributes=True)


class MacroDefenseResult(BaseModel):
    macro_present: bool = Field(False, description="True when a macro container or legacy macro evidence was detected.")
    macro_container_type: Optional[str] = Field(None, description="Detected macro container type: ooxml_vba_project, legacy_ole_vba, dde_field, or related static source.")
    macro_risk_score: float = Field(0.0, description="Static macro risk score in [0,1].")
    macro_risk_level: str = Field("none", description="none|low|medium|high|critical")
    macro_indicators: List[str] = Field(default_factory=list)
    auto_exec_indicators: List[str] = Field(default_factory=list)
    execution_indicators: List[str] = Field(default_factory=list)
    network_indicators: List[str] = Field(default_factory=list)
    obfuscation_indicators: List[str] = Field(default_factory=list)
    external_reference_indicators: List[str] = Field(default_factory=list)
    embedded_object_indicators: List[str] = Field(default_factory=list)
    motw_zone: Optional[str] = Field(None, description="Mark-of-the-Web/source zone when supplied by upload context.")
    source_trust: Optional[str] = Field(None, description="trusted|untrusted|unknown when supplied or inferred.")
    signed_macro: Optional[bool] = Field(None, description="Whether macro signature metadata was supplied and positive.")
    trusted_publisher: Optional[bool] = Field(None, description="Whether supplied publisher metadata is trusted.")
    recommended_handling: str = Field("allow", description="allow|monitor|review|block_request|quarantine_request")
    evidence_reasons: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class FileAnalysisDetails(BaseModel):
    filename: str
    filesize_kb: float
    type_validation: Optional[FileTypeValidationResult] = None
    malware_scan: Optional[MalwareScanResult] = None # YARA/Signature scan
    ml_scan: Optional[MLScanResult] = Field(None, description="Results from content-based ML scanning.")
    macro_defense: Optional[MacroDefenseResult] = Field(None, description="Static Office macro defence findings.")
    
    model_config = ConfigDict(from_attributes=True)

class FileAnalysisOverallAssessment(BaseModel):
    overall_status: str = Field(description="Overall status of the file.")
    risk_score: Optional[float] = Field(None, description="A numerical score representing the perceived risk (0.0 to 1.0).")
    recommended_action: str = Field(description="Suggested action.")
    reasoning: Optional[List[str]] = Field(None, description="Brief reasons for the assessment.")
    
    model_config = ConfigDict(from_attributes=True)


class FileVerdictEvidenceItem(BaseModel):
    code: str = Field(description="Stable code for the evidence item.")
    label: str = Field(description="Human-readable evidence label.")
    severity: Optional[str] = Field(None, description="low/medium/high/critical")
    source: Optional[str] = Field(None, description="Source stage (type_validation/yara/archive/ml/heuristics).")
    path: Optional[str] = Field(None, description="Nested path in archive/document, when applicable.")
    details: Optional[Dict[str, Any]] = Field(None, description="Small structured details for this evidence item.")

    model_config = ConfigDict(from_attributes=True)


class FileVerdictStage(BaseModel):
    stage: str = Field(description="Pipeline stage name.")
    status: str = Field(description="Stage status: ok/hit/skipped/error.")
    summary: Optional[str] = Field(None, description="Short stage summary.")
    details: Optional[Dict[str, Any]] = Field(None, description="Structured stage details.")

    model_config = ConfigDict(from_attributes=True)


class FileIOC(BaseModel):
    type: str = Field(description="IOC type: url|domain|ip|email|hash|path|command")
    value: str = Field(description="Normalized IOC value.")
    source_stage: str = Field(description="Stage that produced the IOC.")
    source_path: Optional[str] = Field(
        None,
        description="Nested source path when IOC came from archive/document content.",
    )
    archive_lineage: Optional[List[str]] = Field(
        None,
        description="Archive lineage paths related to this IOC.",
    )
    confidence: Optional[float] = Field(None, description="Confidence proxy (0..1).")
    severity_hint: Optional[str] = Field(None, description="low/medium/high/critical")
    dedup_key: str = Field(description="Stable dedup key for deterministic normalization.")
    provenance: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Merged provenance records retained during deduplication.",
    )

    model_config = ConfigDict(from_attributes=True)


class FileDynamicAnalysisState(BaseModel):
    requested: bool = Field(False, description="Whether dynamic analysis was requested by policy.")
    request_decision: Optional[str] = Field(
        None,
        description=(
            "Deterministic request decision code: "
            "not_requested|request_dynamic|skip_unsupported|skip_size_limit|skip_low_risk|"
            "skip_policy_exempt|request_but_provider_unavailable."
        ),
    )
    reason_codes: List[str] = Field(default_factory=list, description="Stable reason codes backing the request decision.")
    policy_profile: Optional[str] = Field(None, description="Active dynamic request policy profile name.")
    request_trace: List[Dict[str, Any]] = Field(default_factory=list, description="Machine-readable policy evaluation trace.")
    skip_reason: Optional[str] = Field(None, description="Canonical skip reason when dynamic analysis is not requested.")
    provider: Optional[str] = Field(None, description="External dynamic-analysis provider name.")
    submission_id: Optional[str] = Field(None, description="Provider-side submission handle.")
    dynamic_status: str = Field(
        description="Lifecycle state: not_requested|pending_submission|submitted|running|completed|failed|unavailable."
    )
    submitted_at: Optional[datetime] = Field(None, description="UTC submission time when sent to provider.")
    completed_at: Optional[datetime] = Field(None, description="UTC completion time for provider result.")
    failure_reason: Optional[str] = Field(None, description="Reason when dynamic analysis failed/unavailable.")
    dynamic_summary: Optional[str] = Field(None, description="Short normalized provider summary.")
    dynamic_evidence_items: List[FileVerdictEvidenceItem] = Field(default_factory=list)
    dynamic_iocs: List[FileIOC] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class FileStructuredVerdict(BaseModel):
    analysis_id: str
    sample_id: Optional[str] = None
    classification: str = Field(description="safe/suspicious/blocked")
    severity: str = Field(description="low/medium/high")
    score: Optional[float] = Field(None, description="Risk score (0..1).")
    confidence: Optional[float] = Field(None, description="Decision confidence (0..1), not file risk.")
    declared_type: Optional[str] = Field(None, description="Declared file extension/type from filename.")
    detected_type: Optional[str] = Field(None, description="Detected MIME/content type.")
    matched_rules: List[str] = Field(default_factory=list, description="Matched rule identifiers (e.g., YARA rules).")
    matched_signatures: List[str] = Field(default_factory=list, description="Matched AV signatures, when available.")
    iocs: List[FileIOC] = Field(default_factory=list, description="Canonical machine-readable IOC collection.")
    dynamic_analysis: Optional[FileDynamicAnalysisState] = None
    evidence_items: List[FileVerdictEvidenceItem] = Field(default_factory=list)
    archive_lineage: List[str] = Field(default_factory=list, description="Nested archive/document paths with findings.")
    macro_defense: Optional[MacroDefenseResult] = Field(None, description="Static Office macro defence findings.")
    analysis_stages: List[FileVerdictStage] = Field(default_factory=list)
    analyst_summary: str = Field(description="Concise analyst-facing summary of why the verdict was assigned.")

    model_config = ConfigDict(from_attributes=True)

class FileAnalysisResponse(BaseModel):
    analysis_id: str
    analysis_timestamp: datetime
    file_details: FileAnalysisDetails # This now includes ml_scan
    overall_assessment: FileAnalysisOverallAssessment
    structured_verdict: Optional[FileStructuredVerdict] = Field(
        None,
        description="Pure structured verdict/evidence contract built before side effects.",
    )
    errors: Optional[List[str]] = None
    # Optional: positions to highlight in text previews (character offsets in decoded UTF-8)
    highlights: Optional[List[Dict[str, Any]]] = None
    macro_defense: Optional[MacroDefenseResult] = Field(None, description="Static Office macro defence findings.")
    explanation: Optional[XAIExplanation] = None
    ai_reliability: Optional[AIReliabilityAssessment] = None
    defender_actions: Optional[List[str]] = Field(None, description="Policy actions selected by Defender AI incident response.")
    defender_action_summary: Optional[Dict[str, Any]] = Field(None, description="Structured incident response decision details.")
    
    model_config = ConfigDict(from_attributes=True, json_schema_extra={
        "example": {
            "analysis_id": "file-analysis-uuid-12345",
            "analysis_timestamp": "2025-05-18T10:40:00.123Z",
            "file_details": {
                "filename": "suspicious_script.js",
                "filesize_kb": 12.5,
                "type_validation": {
                    "detected_mime_type": "application/javascript",
                    "is_allowed_type": True,
                    "extension_provided": ".js"
                },
                "malware_scan": { 
                    "scan_engine_version": "YARA (rules: basic_rules.yar)",
                    "is_malicious": True,
                    "threat_name": "SimpleJavaScriptObfuscation"
                },
                "ml_scan": { 
                    "model_name": "file_text_analyzer_v1",
                    "is_suspicious_ml": True,
                    "prediction_label_ml": "Malicious_Text",
                    "prediction_score_ml": 0.85
                }
            },
            "overall_assessment": {
                "overall_status": "Malicious", 
                "risk_score": 0.95, 
                "recommended_action": "BLOCK_UPLOAD_QUARANTINE",
                "reasoning": ["YARA rule matched: SimpleJavaScriptObfuscation", "ML model classified as Malicious_Text"]
            }, 
            "errors": None
        }
    })


class FileScanJobAcceptedResponse(BaseModel):
    job_id: str
    filename: str
    status: str
    attempts: int
    max_attempts: int
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class FileScanJobStatusResponse(BaseModel):
    job_id: str
    filename: str
    status: str
    attempts: int
    max_attempts: int
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class FileScanQueueStatsResponse(BaseModel):
    running: bool
    worker_count: int
    queue_max_size: int
    queue_size: int
    jobs_total: int
    status_counts: Dict[str, int]
    backend: Optional[str] = None
    processor_enabled: Optional[bool] = None
    redis_url: Optional[str] = None
    namespace: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# --- Schemas for Alerts Data ---
class Alert(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    timestamp: datetime
    severity: str
    title: str
    message: str
    source_ip: Optional[str] = None
    target: Optional[str] = None
    query: Optional[str] = None
    acknowledged: bool = False
    tags: Optional[List[str]] = None
    owner_user_id: Optional[str] = None
    owner: Optional[UserSummary] = None
    
    model_config = ConfigDict(from_attributes=True)

class AlertsListResponse(BaseModel):
    alerts: List[Alert]
    total_alerts: int
    page: Optional[int] = None
    page_size: Optional[int] = None
    total_pages: Optional[int] = None
    
    model_config = ConfigDict(from_attributes=True, json_schema_extra={
         "example": {
                "alerts": [
                    {
                        "id": "alert-sql-xxxxxxxx", "timestamp": "2025-05-18T10:30:00.123Z", 
                        "severity": "High", "title": "SQL Alert: High Risk Query", 
                        "message": "Query: '1' OR '1'='1'; --'...", "source_ip": None, 
                        "target": "SQL_Analyzer_Service", "query": "1' OR '1'='1'; --",
                        "acknowledged": False, "tags": ["SQL_Injection_Suspected", "HIGH"]
                    }
                ],
                "total_alerts": 1, "page": 1, "page_size": 10, "total_pages": 1
            }
    })

# --- Schemas for Dashboard Data ---
class DashboardStatCard(BaseModel):
    title: str; value: str; unit: Optional[str] = None; trend: Optional[str] = None
    trend_color_class: Optional[str] = "text-accent-green"; description: Optional[str] = None
    icon_name: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

class DashboardOverallStats(BaseModel):
    commands: int; events: int; detections: int; actions_taken: int
    
    model_config = ConfigDict(from_attributes=True)

class DashboardSummaryResponse(BaseModel):
    last_updated: datetime
    stat_cards: List[DashboardStatCard]
    overall_stats: DashboardOverallStats
    
    model_config = ConfigDict(from_attributes=True)

class ThreatTrendDataPoint(BaseModel):
    name: str; SQL_Injection: int; Spam: int; Files: int; Other: int 
    
    model_config = ConfigDict(from_attributes=True)

class ThreatTrendResponse(BaseModel):
    time_period: str
    trend_data: List[ThreatTrendDataPoint]
    
    model_config = ConfigDict(from_attributes=True)

class ThreatByCategory(BaseModel):
    name: str; count: int; fill_color: str 
    
    model_config = ConfigDict(from_attributes=True)

class ThreatsByCategoryResponse(BaseModel):
    data: List[ThreatByCategory]
    
    model_config = ConfigDict(from_attributes=True)

class AlertSeverityDistribution(BaseModel):
    name: str; value: int; fill_color: str 
    
    model_config = ConfigDict(from_attributes=True)

class AlertSeverityDistributionResponse(BaseModel):
    data: List[AlertSeverityDistribution]
    
    model_config = ConfigDict(from_attributes=True)
    
class DashboardStats(BaseModel):
    total_queries: int
    malicious_queries: int
    files_scanned: int
    spam_detected: int
    sql_risk_posture_score: Optional[float] = Field(
        0.0,
        description="Risk-derived SQL posture score (0-100), calculated as 100 * (1 - average calibrated SQL risk).",
    )
    sql_precision_score: Optional[float] = Field(
        0.0,
        description="Deprecated alias for sql_risk_posture_score. This is not statistical precision.",
    )
    sql_avg_calibrated_risk: Optional[float] = Field(
        0.0,
        description="Average calibrated SQL risk score for the selected scope (0-1).",
    )
    sql_high_risk_rate: Optional[float] = Field(
        0.0,
        description="Percentage of SQL analyses at or above high-risk threshold.",
    )
    sql_precision_sample_size: Optional[int] = Field(
        0,
        description="Number of SQL analyses used for SQL risk-posture computation.",
    )


class DashboardStatsDailyPoint(BaseModel):
    """Per-day dashboard stats for history views."""
    date: date
    total_queries: int
    malicious_queries: int
    files_scanned: int
    spam_detected: int

    model_config = ConfigDict(from_attributes=True)


class DashboardStatsHistoryResponse(BaseModel):
    time_period: str
    data: List[DashboardStatsDailyPoint]

    model_config = ConfigDict(from_attributes=True)
