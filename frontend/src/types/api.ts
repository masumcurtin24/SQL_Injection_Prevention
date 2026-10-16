// File: frontend/src/types/api.ts
// This file defines the shapes of data. No changes are needed here, but it's provided for completeness.

// --- SQL Analysis API (matches backend/server/schemas/responses.py) ---
export interface SQLQueryPayload { query: string }

export interface XAIExplanationEvidence {
    id: string;
    label: string;
    severity?: string | null;
    description?: string | null;
    snippet?: string | null;
    start?: number | null;
    end?: number | null;
    score?: number | null;
    source?: string | null;
    impact?: string | null;
}

export interface XAIExplanationTraceStep {
    stage: string;
    summary: string;
    details?: Record<string, any> | null;
}

export interface AIReliabilityAssessment {
    reliability_score: number;
    reliability_status: string;
    review_required: boolean;
    review_reasons: string[];
    signal_conflicts: string[];
    policy_override: boolean;
    adversarial_suspicion: boolean;
    recommended_handling: string;
    reliability_factors?: Record<string, unknown> | null;
}

export interface SpamDecisionDisplay {
    status_label: string;
    status_color: 'green' | 'amber' | 'red';
    hard_detection: boolean;
    review_required: boolean;
    recommended_handling: 'allow' | 'monitor' | 'review' | 'block' | 'quarantine';
    reliability_status?: string | null;
    detail?: string | null;
}

export interface ExplanationScoreSemantics {
    risk_score?: number | null;
    risk_label?: string | null;
    decision_confidence?: number | null;
    uncertainty_score?: number | null;
    uncertainty_components?: Record<string, number> | null;
    ood_score?: number | null;
    fidelity_score?: number | null;
    reliability_score?: number | null;
    score_type_notes?: string[];
}

export interface EvidenceContribution {
    name: string;
    category: string;
    value?: number | string | boolean | null;
    weight?: number | null;
    normalized_contribution?: number | null;
    direction: string;
    explanation: string;
    source: string;
}

export interface DecisionRationale {
    final_decision: string;
    decision_type: string;
    recommended_handling: 'allow' | 'monitor' | 'review' | 'block' | 'quarantine';
    hard_decision: boolean;
    review_required: boolean;
    review_reasons: string[];
    thresholds_applied?: Record<string, any>;
    policy_overrides?: string[];
    limitations?: string[];
}

export interface XAIExplanation {
    decision: string;
    severity?: string | null;
    threat_category?: string | null;
    risk_score?: number | null;
    decision_confidence?: number | null;
    confidence?: number | null;
    spam_risk?: number | null;
    confidence_label?: string | null;
    uncertainty_score?: number | null;
    uncertainty_components?: Record<string, number> | null;
    fidelity_score?: number | null;
    ood_score?: number | null;
    abstain_reason?: string | null;
    impact?: string | null;
    evidence?: XAIExplanationEvidence[] | null;
    highlights?: { start: number; end: number; label: string; severity?: string }[] | null;
    model_attributions?: Record<string, any>[] | null;
    decision_trace?: XAIExplanationTraceStep[] | null;
    remediation?: string[] | null;
    counterfactual?: string | null;
    model_version?: string | null;
    ruleset_version?: string | null;
    policy_version?: string | null;
    thresholds?: Record<string, number> | null;
    provenance?: Record<string, any> | null;
    caveats?: string[] | null;
    ai_reliability?: AIReliabilityAssessment | null;
    score_semantics?: ExplanationScoreSemantics | null;
    evidence_contributions?: EvidenceContribution[] | null;
    decision_rationale?: DecisionRationale | null;
    plain_language_summary?: string | null;
    technical_summary?: string | null;
    limitations?: string[] | null;
}

export interface UserSummary {
    id: string;
    display_name: string;
    full_name?: string | null;
    role?: string | null;
}

export interface AnomalyDetectionResult {
    is_anomalous: boolean;
    score: number;
    prediction_label: string;
}

export interface QueryValidationResult {
    classification_label: string;
    classification_score?: number | null;
}

export interface SQLHeuristicsResult {
    suspected: boolean;
    hits: string[];
    heuristic_score?: number | null;
}

export interface CombinedRiskAssessment {
    overall_risk_level: string;
    suggested_action: string;
    reasoning?: string[] | null;
    calibrated_risk_score?: number | null;
    signal_contributions?: Record<string, number> | null;
    ast_features?: Record<string, any> | null;
}

export interface AnalysisApiResponse {
    query_received: string;
    analysis_timestamp: string;
    analysis_id?: string;
    anomaly_detection: AnomalyDetectionResult;
    query_validation?: QueryValidationResult | null;
    heuristics_detection?: SQLHeuristicsResult | null;
    combined_assessment?: CombinedRiskAssessment | null;
    explanation?: XAIExplanation | null;
    ai_reliability?: AIReliabilityAssessment | null;
    errors?: string[] | null;
}

export interface SpamAnalysisResponse {
    analysis_id?: string;
    is_spam: boolean;
    spam_score: number;
    decision_confidence?: number | null;
    classification_label?: string;
    score_breakdown?: {
      final?: number;
      decision_confidence?: number;
      raw_fused?: number;
      classical?: number | null;
      transformer?: number | null;
      online?: number | null;
      heuristic?: number | null;
      url_heuristic?: number | null;
      reputation?: number | null;
      campaign?: number | null;
      header?: number | null;
      fraud_pattern?: number | null;
      bec_fraud?: number | null;
      courier_phishing?: number | null;
      brand_impersonation?: number | null;
      payment_link_impersonation?: number | null;
      fraud_category?: string | null;
      bec_risk_floor?: number | null;
      ood?: number | null;
      thresholds?: Record<string, number> | null;
      hard_block_signal?: boolean;
      campaign_hard_signal?: boolean;
      fraud_pattern_hard_signal?: boolean;
      header_hard_signal?: boolean;
      uncertainty_components?: Record<string, number> | null;
    } | null;
    url_indicators?: Record<string, any> | null;
    meta_features?: Record<string, any> | null;
    explanation?: XAIExplanation | null;
    ai_reliability?: AIReliabilityAssessment | null;
    decision_display?: SpamDecisionDisplay | null;
    defender_actions?: string[] | null;
    defender_action_summary?: Record<string, any> | null;
}

export interface FileAnalysisResponse {
    analysis_id?: string;
    analysis_timestamp?: string;
    filename: string;
    is_malicious: boolean;
    matched_rules: string[];
    // Optional richer fields mapped from backend FileAnalysisResponse
    overall_status?: string;
    recommended_action?: string;
    risk_score?: number | null;
    decision_confidence?: number | null;
    reasoning?: string[];
    mime_type?: string;
    file_size_kb?: number | null;
    short_summary?: string;
    highlights?: { start: number; end: number; label: string; severity?: 'low'|'medium'|'high' }[];
    file_details?: Record<string, any> | null;
    overall_assessment?: Record<string, any> | null;
    structured_verdict?: Record<string, any> | null;
    macro_defense?: MacroDefenseResult | null;
    explanation?: XAIExplanation | null;
    ai_reliability?: AIReliabilityAssessment | null;
}

export interface MacroDefenseResult {
    macro_present: boolean;
    macro_container_type?: string | null;
    macro_risk_score: number;
    macro_risk_level: 'none' | 'low' | 'medium' | 'high' | 'critical' | string;
    macro_indicators: string[];
    auto_exec_indicators: string[];
    execution_indicators: string[];
    network_indicators: string[];
    obfuscation_indicators: string[];
    external_reference_indicators: string[];
    embedded_object_indicators: string[];
    motw_zone?: string | null;
    source_trust?: string | null;
    signed_macro?: boolean | null;
    trusted_publisher?: boolean | null;
    recommended_handling: 'allow' | 'monitor' | 'review' | 'block_request' | 'quarantine_request' | string;
    evidence_reasons: string[];
    limitations: string[];
}

export interface Alert {
    id: number;                 // UI numeric id (hash)
    backend_id?: string;        // Backend string id used for actions
    tenant_id?: string | null;
    description: string;
    timestamp: string; // ISO 8601 format
    severity: 'low' | 'medium' | 'high';
    acknowledged?: boolean;
    owner_user_id?: string | null;
    owner?: UserSummary | null;
}

export interface AlertDetails {
    id: string;
    tenant_id?: string | null;
    timestamp: string;
    severity: string;
    title: string;
    message: string;
    source_ip?: string | null;
    target?: string | null;
    query?: string | null;
    acknowledged: boolean;
    tags?: string[] | null;
    analysis_id?: string | null;
    analysis_type?: string | null;
    explainability?: XAIExplanation | null;
    analysis_context?: Record<string, any> | null;
    defender_actions?: string[] | null;
    linked_case_ids?: string[] | null;
    owner_user_id?: string | null;
    owner?: UserSummary | null;
    linked_case_owner_user_ids?: string[] | null;
    linked_case_owners?: UserSummary[] | null;
}

export interface LiveEvent {
    id: string;
    type: 'query' | 'file_scan' | 'spam_check' | 'alert';
    tenant_id?: string | null;
    message: string;
    timestamp: string; // ISO 8601 format
    isMalicious?: boolean;
}

export interface LiveEventDetail {
    id: string;
    type: LiveEvent['type'];
    tenant_id?: string | null;
    timestamp?: string | null;
    summary?: string | null;
    isMalicious?: boolean;
    details?: Record<string, any> | null;
}

export interface DashboardStats {
    total_queries: number;
    malicious_queries: number;
    files_scanned: number;
    spam_detected: number;
    sql_risk_posture_score?: number;
    sql_precision_score?: number;
    sql_avg_calibrated_risk?: number;
    sql_high_risk_rate?: number;
    sql_precision_sample_size?: number;
}

export interface DashboardDomainBreakdown {
    total: number;
    safe: number;
    suspicious: number;
    blocked: number;
}

export interface DashboardExecutiveOverview {
    scope: 'today' | 'total';
    day?: string | null;
    as_of: string;
    window_start?: string | null;
    window_end?: string | null;
    security_posture: 'stable' | 'watch' | 'critical';
    posture_score: number;
    totals: {
      events: number;
      analysis_events: number;
      safe: number;
      suspicious: number;
      blocked: number;
      alerts: number;
      critical_alerts: number;
    };
    rates: {
      detection_rate: number;
      block_rate: number;
      alert_rate_per_100_events: number;
    };
    latency: {
      latest_event_at?: string | null;
      ingestion_lag_seconds?: number | null;
    };
    domains: {
      sql: DashboardDomainBreakdown;
      file: DashboardDomainBreakdown;
      spam: DashboardDomainBreakdown;
    };
    alerts_by_severity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      other: number;
    };
    top_risks: Array<{ label: string; count: number }>;
}

export interface DashboardFileScanItem {
    analysis_id: string;
    tenant_id?: string | null;
    timestamp: string;
    filename: string;
    category?: 'safe' | 'suspicious' | 'blocked';
    filesize_kb?: number | null;
    overall_status?: string | null;
    risk_score?: number | null;
    recommended_action?: string | null;
    reasoning?: string[] | null;
    detected_mime_type?: string | null;
    is_allowed_type?: boolean | null;
    yara_malicious?: boolean;
    yara_threat_name?: string | null;
    ml_suspicious?: boolean;
    ml_prediction_label?: string | null;
    ml_prediction_score?: number | null;
}

export interface DashboardSQLQueryItem {
    analysis_id: string;
    tenant_id?: string | null;
    timestamp: string;
    query_received: string;
    category?: 'safe' | 'suspicious' | 'blocked';
    risk_level?: string | null;
    suggested_action?: string | null;
    reasoning?: string[] | null;
    is_malicious?: boolean;
    anomaly_score?: number | null;
    anomaly_label?: string | null;
    is_anomalous?: boolean;
    classification_label?: string | null;
    classification_score?: number | null;
}

export interface DashboardSpamDetectionItem {
    analysis_id: string;
    tenant_id?: string | null;
    timestamp: string;
    received_subject?: string | null;
    category?: 'safe' | 'suspicious' | 'blocked';
    is_spam?: boolean;
    spam_score?: number | null;
    classification_label?: string | null;
}

export interface DashboardStatsDailyPoint extends DashboardStats {
    date: string; // YYYY-MM-DD
}

export interface DashboardStatsHistoryResponse {
    time_period: string;
    data: DashboardStatsDailyPoint[];
}

export type PlatformHealthStatus = 'healthy' | 'degraded' | 'critical' | 'unknown';

export interface PlatformHealthEndpointMetric {
    method?: string;
    path?: string;
    requests_total?: number;
    errors_total?: number;
    error_rate?: number;
    latency_ms_avg?: number;
    latency_ms_max?: number;
    latency_ms_last?: number;
    last_status_code?: number;
    last_seen_at?: string | null;
}

export interface DashboardPlatformHealthResponse {
    as_of: string;
    overall_status: PlatformHealthStatus;
    score: number;
    issues: string[];
    warnings: string[];
    components: {
      http: {
        status: PlatformHealthStatus;
        requests_total: number;
        errors_total: number;
        error_rate: number;
        avg_latency_ms: number;
        top_error_endpoints: PlatformHealthEndpointMetric[];
        top_slow_endpoints: PlatformHealthEndpointMetric[];
      };
      websocket: {
        status: PlatformHealthStatus;
        active_connections: number;
        connections_total: number;
        disconnects_total: number;
        auth_failures_total: number;
        messages_broadcast_total: number;
        broadcast_send_failures_total: number;
        broadcast_failure_rate: number;
        last_event_at?: string | null;
      };
      queue: {
        status: PlatformHealthStatus;
        running?: boolean | null;
        processor_enabled?: boolean | null;
        queue_size?: number | null;
        queue_max_size?: number | null;
        utilization?: number | null;
        jobs_total?: number | null;
        dead_letter?: number | null;
        failed?: number | null;
        status_counts?: Record<string, number> | null;
        backend?: string | null;
        redis_url?: string | null;
        namespace?: string | null;
      };
      models: {
        status: PlatformHealthStatus;
        required_domains: string[];
        active_by_domain: Record<string, { version?: string; model_name?: string; promoted_at?: string | null; timestamp?: string | null }>;
        missing_active_domains: string[];
        pending_feedback: number;
        latest_job?: Record<string, any> | null;
        job_status_counts?: Record<string, number>;
      };
      quality: {
        status: PlatformHealthStatus;
        fp_days: number;
        analyst_only: boolean;
        labeled_total: number;
        false_positives_total: number;
        global_false_positive_rate: number;
        by_domain: Record<string, { labeled: number; false_positives: number; false_positive_rate: number }>;
      };
    };
}

export interface DashboardAccessSessionItem {
    session_id: string;
    tenant_id?: string | null;
    user_id: string;
    email: string;
    full_name?: string | null;
    role: string;
    status: string;
    ip?: string | null;
    user_agent?: string | null;
    started_at?: string | null;
    last_used_at?: string | null;
    ended_at?: string | null;
    duration_seconds?: number | null;
    active_seconds?: number | null;
    idle_seconds?: number | null;
    revoke_reason?: string | null;
}

export interface DashboardAccessFeedResponse {
    as_of: string;
    active_only: boolean;
    count: number;
    active_sessions: number;
    items: DashboardAccessSessionItem[];
}

export type CaseStatus = 'new' | 'triaged' | 'investigating' | 'contained' | 'closed';
export type CaseSeverity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface SecurityCaseTimelineEntry {
    timestamp: string;
    actor_user_id?: string | null;
    actor?: UserSummary | null;
    action: string;
    note?: string | null;
    details?: Record<string, any> | null;
}

export interface CaseNoteEntry {
    id: string;
    case_id: string;
    tenant_id?: string | null;
    created_at: string;
    author_user_id: string;
    author?: UserSummary | null;
    note: string;
}

export interface AlertCaseLinkEntry {
    id: string;
    case_id: string;
    tenant_id?: string | null;
    alert_id: string;
    linked_at: string;
    linked_by_user_id: string;
    linked_by?: UserSummary | null;
    note?: string | null;
}

export interface CaseActivityEntry {
    tenant_id?: string | null;
    timestamp: string;
    actor_user_id?: string | null;
    actor?: UserSummary | null;
    action: string;
    note?: string | null;
    details?: Record<string, any> | null;
}

export interface SecurityCaseSummary {
    id: string;
    tenant_id?: string | null;
    created_at: string;
    updated_at: string;
    status: CaseStatus;
    severity: CaseSeverity;
    title: string;
    domain?: string | null;
    source_type?: string | null;
    source_id?: string | null;
    owner_user_id?: string | null;
    owner?: UserSummary | null;
    created_by_user_id: string;
    created_by?: UserSummary | null;
    tags?: string[];
}

export interface SecurityCaseDetail extends SecurityCaseSummary {
    description?: string | null;
    evidence?: Record<string, any>[];
    timeline?: SecurityCaseTimelineEntry[];
    notes?: CaseNoteEntry[];
    alert_links?: AlertCaseLinkEntry[];
    activity?: CaseActivityEntry[];
}

export interface SecurityCaseListResponse {
    cases: SecurityCaseSummary[];
    total_cases: number;
    page: number;
    page_size: number;
    total_pages: number;
    status_counts: Record<string, number>;
}

export interface SecurityCaseStatsResponse {
    total_cases: number;
    open_cases: number;
    closed_cases: number;
    by_status: Record<string, number>;
}

export interface CaseNotesResponse {
    case_id: string;
    count: number;
    notes: CaseNoteEntry[];
}

export interface CaseAlertLinksResponse {
    case_id: string;
    count: number;
    links: AlertCaseLinkEntry[];
}

export interface CaseActivityResponse {
    case_id: string;
    count: number;
    activity: CaseActivityEntry[];
}

export type InvestigationEventType =
    | 'query'
    | 'file_scan'
    | 'spam_check'
    | 'alert'
    | 'case'
    | 'case_note'
    | 'case_alert_link';

export type CorrelationLevel = 'strong' | 'moderate' | 'weak' | 'none';

export interface InvestigationCorrelationReason {
    code: string;
    label: string;
    detail?: string | null;
    key?: string | null;
    value?: string | null;
}

export interface InvestigationRelatedEvent {
    id: string;
    event_type: InvestigationEventType;
    timestamp: string;
    title: string;
    severity?: string | null;
    source_ref: Record<string, string>;
    correlation_level?: CorrelationLevel | null;
    correlation_reasons?: InvestigationCorrelationReason[];
}

export interface InvestigationRelatedEntity {
    key: string;
    value: string;
    match_count: number;
    reasons?: string[];
    related_event_ids?: string[];
}

export interface InvestigationTimelineItem {
    id: string;
    tenant_id?: string | null;
    timestamp: string;
    event_type: InvestigationEventType;
    severity?: string | null;
    title: string;
    summary?: string | null;
    actor_user_id?: string | null;
    actor?: UserSummary | null;
    owner_user_id?: string | null;
    owner?: UserSummary | null;
    entity_keys: Record<string, string>;
    source_ref: Record<string, string>;
    case_ids: string[];
    correlation_level?: CorrelationLevel | null;
    correlation_reasons?: InvestigationCorrelationReason[];
    related_entities?: InvestigationRelatedEntity[];
    related_events?: InvestigationRelatedEvent[];
}

export interface InvestigationTimelineResponse {
    items: InvestigationTimelineItem[];
    count: number;
    limit: number;
    start?: string | null;
    end?: string | null;
    before?: string | null;
    event_types?: string | null;
    entity_key?: string | null;
    entity_value?: string | null;
}

export interface AuditLogItem {
    id: string;
    tenant_id?: string | null;
    timestamp: string;
    actor_user_id?: string | null;
    actor?: UserSummary | null;
    action: string;
    resource_type?: string | null;
    resource_id?: string | null;
    ip?: string | null;
    user_agent?: string | null;
    success: boolean;
    details?: Record<string, any> | null;
}

export interface AuditListResponse {
    items: AuditLogItem[];
    limit: number;
    offset: number;
    total: number;
}

export interface DefenderModelInfo {
    id: string;
    tenant_id?: string | null;
    domain: string;
    stage: string;
    version: string;
    created_at?: string | null;
    created_by?: string | null;
    metrics?: Record<string, any> | null;
}

export interface DefenderTrainingJobInfo {
    id: string;
    tenant_id?: string | null;
    domain: string;
    status: string;
    requested_by?: string | null;
    created_at?: string | null;
    completed_at?: string | null;
    result?: Record<string, any> | null;
}

export interface DefenderStatusResponse {
    feedback_counts: Record<string, number>;
    pending_feedback: number;
    models: Record<string, DefenderModelInfo[]>;
    recent_jobs: DefenderTrainingJobInfo[];
    job_status_counts: Record<string, number>;
}

export interface SqlEnforcementConfigResponse {
    rules: Record<string, any>;
    env_overrides: Record<string, string>;
    restart_required: boolean;
    scope?: string;
    tenant_id?: string | null;
}

export interface SqlEnforcementPatchPayload {
    critical_patterns?: string[];
    ddl_exec?: {
        policy?: 'deny_non_migration' | 'deny' | 'monitor' | 'allow';
        allowed_services?: string;
        allowlist_patterns?: string[];
    };
    allowlist?: {
        mode?: 'safe' | 'regex';
        last_reviewed_at?: string;
        max_age_days?: number;
    };
    monitor?: {
        backoff_n?: number;
    };
    parameterization?: {
        require?: boolean;
    };
    service_context?: {
        require?: boolean;
    };
    telemetry?: {
        file?: string;
    };
}

export interface SqlEnforcementPatchResponse {
    rules: Record<string, any>;
    before_sha256: string;
    after_sha256: string;
    changed_paths: string[];
    restart_required: boolean;
    scope?: string;
    tenant_id?: string | null;
}

export type GovernanceSupportMode = 'editable' | 'read_only' | 'partially_supported';

export interface GovernanceDomainSection {
    support: GovernanceSupportMode;
    writable_actions: string[];
    controls: Record<string, any>;
    metadata: Record<string, any>;
    notes: string[];
}

export interface GovernanceChangeEntry {
    id: string;
    timestamp: string;
    tenant_id?: string | null;
    actor_user_id?: string | null;
    actor?: UserSummary | null;
    action: string;
    resource_type?: string | null;
    resource_id?: string | null;
    success: boolean;
    details?: Record<string, any> | null;
}

export interface GovernanceOverviewResponse {
    as_of: string;
    scope: 'tenant' | 'global';
    tenant_id?: string | null;
    domains: Record<string, GovernanceDomainSection>;
    recent_changes: GovernanceChangeEntry[];
}

export interface SpamAutopipelineStatusResponse {
    enabled: boolean;
    running: boolean;
    run_on_start: boolean;
    interval_minutes: number;
    in_progress: boolean;
    min_feedback_samples: number;
    promote_if_better: boolean;
    allow_corpus_only: boolean;
    strict_corpus: boolean;
    weaklabel_limits: {
        max_phish_rows: number;
        max_ham_rows: number;
        feedback_limit: number;
        seed: number;
    };
    runs_total: number;
    runs_succeeded: number;
    runs_failed: number;
    last_run?: Record<string, any> | null;
}

