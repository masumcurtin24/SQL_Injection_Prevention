# backend/core/models.py
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, UniqueConstraint # Added Float
from datetime import datetime, timezone # Added timezone
import json 
import uuid
from typing import Optional, List, Dict, Any # Added Dict, Any

from .database import Base # Import Base from your database.py


DEFAULT_TENANT_ID = "tenant-primary"


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Tenant identifier.",
    )
    slug = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
        comment="Tenant slug used by frontend selector.",
    )
    name = Column(
        String,
        nullable=False,
        comment="Human readable tenant name.",
    )
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Whether tenant is active.",
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="Creation timestamp (UTC).",
    )

    def __repr__(self):
        return f"<Tenant(id='{self.id}', slug='{self.slug}', active={self.is_active})>"

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True, comment="Unique identifier for the alert (e.g., UUID).")
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, comment="Timestamp of when the alert was created (UTC).") # Added timezone=True
    severity = Column(String, index=True, nullable=False, comment="Severity level (e.g., 'Critical', 'High', 'Medium', 'Low', 'Info').")
    title = Column(String, nullable=False, comment="A concise title for the alert.")
    message = Column(Text, nullable=False, comment="A detailed message describing the alert.")
    
    source_ip = Column(String, nullable=True, index=True, comment="Source IP address related to the alert, if applicable.")
    target = Column(String, nullable=True, comment="Target system or component related to the alert, if applicable.")
    query = Column(Text, nullable=True, comment="Associated SQL query, if applicable.")
    
    acknowledged = Column(Boolean, default=False, index=True, nullable=False, comment="Whether the alert has been acknowledged by an admin.")
    
    _tags_json = Column("tags", Text, nullable=True, comment="JSON string representation of a list of tags.")

    @property
    def tags(self) -> Optional[List[str]]:
        if self._tags_json:
            try:
                return json.loads(self._tags_json)
            except json.JSONDecodeError:
                return [] 
        return None

    @tags.setter
    def tags(self, value: Optional[List[str]]):
        if value is None:
            self._tags_json = None
        else:
            if isinstance(value, list):
                self._tags_json = json.dumps(value)
            else:
                self._tags_json = json.dumps([])

    def __repr__(self):
        return f"<Alert(id='{self.id}', title='{self.title}', severity='{self.severity}')>"

# --- New Models for Storing Analysis Results ---

class SQLAnalysisLog(Base):
    __tablename__ = "sql_analysis_logs"

    id = Column(String, primary_key=True, index=True, comment="Corresponds to analysis_id from AnalysisResponse.")
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, comment="Timestamp of the analysis (UTC).")
    query_received = Column(Text, nullable=False, comment="The SQL query that was analyzed.")
    risk_level = Column(String, nullable=True, index=True, comment="Denormalized overall risk level (Low|Medium|High|Critical).")
    suggested_action = Column(String, nullable=True, index=True, comment="Denormalized decision action (ALLOW|FLAG|BLOCK...).")
    category = Column(String, nullable=True, index=True, comment="Dashboard category (safe|suspicious|blocked).")
    is_malicious = Column(Boolean, nullable=True, index=True, comment="Denormalized malicious indicator for fast filtering.")
    
    # Store complex Pydantic models as JSON strings
    _anomaly_detection_result_json = Column("anomaly_detection_result", Text, nullable=False, comment="JSON of AnomalyDetectionResult.")
    _query_validation_result_json = Column("query_validation_result", Text, nullable=True, comment="JSON of QueryValidationResult.")
    _combined_assessment_json = Column("combined_assessment", Text, nullable=True, comment="JSON of CombinedRiskAssessment.")
    _errors_json = Column("errors", Text, nullable=True, comment="JSON list of error strings encountered during analysis.")

    # Helper properties to get/set JSON fields as dicts
    def _get_json_field(self, field_name: str) -> Optional[Any]:
        json_str = getattr(self, field_name, None)
        if json_str:
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                return None # Or handle error appropriately
        return None

    def _set_json_field(self, field_name: str, value: Optional[Any]):
        if value is None:
            setattr(self, field_name, None)
        else:
            setattr(self, field_name, json.dumps(value))

    @property
    def anomaly_detection_result(self) -> Optional[Dict[str, Any]]:
        return self._get_json_field("_anomaly_detection_result_json")
    @anomaly_detection_result.setter
    def anomaly_detection_result(self, value: Optional[Dict[str, Any]]):
        self._set_json_field("_anomaly_detection_result_json", value)

    @property
    def query_validation_result(self) -> Optional[Dict[str, Any]]:
        return self._get_json_field("_query_validation_result_json")
    @query_validation_result.setter
    def query_validation_result(self, value: Optional[Dict[str, Any]]):
        self._set_json_field("_query_validation_result_json", value)

    @property
    def combined_assessment(self) -> Optional[Dict[str, Any]]:
        return self._get_json_field("_combined_assessment_json")
    @combined_assessment.setter
    def combined_assessment(self, value: Optional[Dict[str, Any]]):
        self._set_json_field("_combined_assessment_json", value)

    @property
    def errors(self) -> Optional[List[str]]:
        return self._get_json_field("_errors_json") # Assumes errors are stored as a list
    @errors.setter
    def errors(self, value: Optional[List[str]]):
        self._set_json_field("_errors_json", value)
        
    def __repr__(self):
        return f"<SQLAnalysisLog(id='{self.id}', query='{self.query_received[:50]}...')>"


class SpamAnalysisLog(Base):
    __tablename__ = "spam_analysis_logs"

    id = Column(String, primary_key=True, index=True, comment="Corresponds to analysis_id from EmailAnalysisResponse.")
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, comment="Timestamp of the analysis (UTC).")
    received_subject = Column(String, nullable=True, comment="Subject of the analyzed email.")
    is_spam = Column(Boolean, nullable=True, index=True, comment="Denormalized spam flag for fast filtering.")
    spam_score = Column(Float, nullable=True, index=True, comment="Denormalized spam score for filtering and sorting.")
    classification_label = Column(String, nullable=True, index=True, comment="Denormalized classifier label (Ham|Spam|Phishing...).")
    category = Column(String, nullable=True, index=True, comment="Dashboard category (safe|suspicious|blocked).")
    # Assuming body_text is part of what's logged or used for classification, but not stored directly if very large
    # For simplicity, we'll store the SpamClassificationResult as JSON
    _spam_classification_result_json = Column("spam_classification_result", Text, nullable=False, comment="JSON of SpamClassificationResult.")
    _errors_json = Column("errors", Text, nullable=True, comment="JSON list of error strings encountered.")

    # Helper properties (can reuse _get_json_field, _set_json_field if moved to a mixin or base class)
    @property
    def spam_classification_result(self) -> Optional[Dict[str, Any]]:
        json_str = getattr(self, "_spam_classification_result_json", None)
        if json_str: return json.loads(json_str)
        return None
    @spam_classification_result.setter
    def spam_classification_result(self, value: Optional[Dict[str, Any]]):
        setattr(self, "_spam_classification_result_json", json.dumps(value) if value else None)

    @property
    def errors(self) -> Optional[List[str]]:
        json_str = getattr(self, "_errors_json", None)
        if json_str: return json.loads(json_str)
        return None
    @errors.setter
    def errors(self, value: Optional[List[str]]):
        setattr(self, "_errors_json", json.dumps(value) if value else None)
        
    def __repr__(self):
        return f"<SpamAnalysisLog(id='{self.id}', subject='{self.received_subject[:50]}...')>"


class FileAnalysisLog(Base):
    __tablename__ = "file_analysis_logs"

    id = Column(String, primary_key=True, index=True, comment="Corresponds to analysis_id from FileAnalysisResponse.")
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True, comment="Timestamp of the analysis (UTC).")
    filename = Column(String, nullable=False, comment="Name of the analyzed file.")
    filesize_kb = Column(Float, nullable=False, comment="Size of the file in kilobytes.")
    overall_status = Column(String, nullable=True, index=True, comment="Denormalized overall assessment status.")
    recommended_action = Column(String, nullable=True, index=True, comment="Denormalized recommendation action.")
    risk_score_value = Column(Float, nullable=True, index=True, comment="Denormalized risk score for fast filtering.")
    category = Column(String, nullable=True, index=True, comment="Dashboard category (safe|suspicious|blocked).")
    
    # Store complex Pydantic models as JSON strings
    _file_details_json = Column("file_details", Text, nullable=False, comment="JSON of FileAnalysisDetails (excluding filename & size as they are separate columns).")
    _overall_assessment_json = Column("overall_assessment", Text, nullable=False, comment="JSON of FileAnalysisOverallAssessment.")
    _errors_json = Column("errors", Text, nullable=True, comment="JSON list of error strings encountered.")

    # Helper properties
    @property
    def file_details(self) -> Optional[Dict[str, Any]]: # Note: This will store type_validation, malware_scan
        json_str = getattr(self, "_file_details_json", None)
        if json_str: return json.loads(json_str)
        return None
    @file_details.setter
    def file_details(self, value: Optional[Dict[str, Any]]):
        setattr(self, "_file_details_json", json.dumps(value) if value else None)

    @property
    def overall_assessment(self) -> Optional[Dict[str, Any]]:
        json_str = getattr(self, "_overall_assessment_json", None)
        if json_str: return json.loads(json_str)
        return None
    @overall_assessment.setter
    def overall_assessment(self, value: Optional[Dict[str, Any]]):
        setattr(self, "_overall_assessment_json", json.dumps(value) if value else None)

    @property
    def errors(self) -> Optional[List[str]]:
        json_str = getattr(self, "_errors_json", None)
        if json_str: return json.loads(json_str)
        return None
    @errors.setter
    def errors(self, value: Optional[List[str]]):
        setattr(self, "_errors_json", json.dumps(value) if value else None)

    def __repr__(self):
        return f"<FileAnalysisLog(id='{self.id}', filename='{self.filename}')>"


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        comment="Session identifier (UUID).",
    )
    family_id = Column(String, nullable=False, index=True, comment="Refresh-token family identifier.")
    user_id = Column(String, nullable=False, index=True, comment="Owner user ID.")
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    refresh_token_hash = Column(
        String,
        nullable=False,
        unique=True,
        index=True,
        comment="HMAC-SHA256 hash of refresh token.",
    )
    status = Column(
        String,
        nullable=False,
        default="active",
        index=True,
        comment="active|rotated|revoked.",
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Creation timestamp (UTC).",
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="Last update timestamp (UTC).",
    )
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Refresh-token expiry timestamp (UTC).",
    )
    last_used_at = Column(DateTime(timezone=True), nullable=True, comment="Last successful use timestamp (UTC).")
    revoked_at = Column(DateTime(timezone=True), nullable=True, index=True, comment="Revocation timestamp (UTC).")
    revoke_reason = Column(String, nullable=True, comment="Rotation/logout/reuse reason.")
    replaced_by_session_id = Column(String, nullable=True, index=True, comment="New session ID after rotation.")
    ip = Column(String, nullable=True, index=True, comment="Client IP address.")
    user_agent = Column(String, nullable=True, comment="Client user agent.")

    def __repr__(self):
        return (
            f"<AuthSession(id='{self.id}', user_id='{self.user_id}', "
            f"status='{self.status}', family_id='{self.family_id}')>"
        )


class DefenderFeedback(Base):
    __tablename__ = "defender_feedback"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        comment="UUID string identifier.",
    )
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Feedback submission timestamp (UTC).",
    )
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    domain = Column(
        String,
        nullable=False,
        index=True,
        comment="Detection domain: sql|spam|file.",
    )
    analysis_id = Column(
        String,
        nullable=True,
        index=True,
        comment="Optional analysis ID associated with this feedback.",
    )
    predicted_label = Column(
        String,
        nullable=True,
        index=True,
        comment="Original model/system label before feedback.",
    )
    true_label = Column(
        String,
        nullable=False,
        index=True,
        comment="Human-validated ground-truth label.",
    )
    confidence = Column(
        Float,
        nullable=True,
        comment="Optional confidence value from original prediction (0..1).",
    )
    source = Column(
        String,
        nullable=False,
        default="human",
        index=True,
        comment="Feedback source (human|system).",
    )
    notes = Column(Text, nullable=True, comment="Optional analyst notes.")
    processed = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Whether this sample has been consumed by retraining pipeline.",
    )
    _sample_payload_json = Column(
        "sample_payload",
        Text,
        nullable=False,
        comment="JSON payload used for labeling/training.",
    )

    @property
    def sample_payload(self) -> Dict[str, Any]:
        json_str = getattr(self, "_sample_payload_json", None)
        if not json_str:
            return {}
        try:
            parsed = json.loads(json_str)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    @sample_payload.setter
    def sample_payload(self, value: Optional[Dict[str, Any]]):
        payload = value if isinstance(value, dict) else {}
        self._sample_payload_json = json.dumps(payload)

    def __repr__(self):
        return f"<DefenderFeedback(id='{self.id}', domain='{self.domain}', true_label='{self.true_label}')>"


class DefenderModelRegistry(Base):
    __tablename__ = "defender_model_registry"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        comment="UUID string identifier.",
    )
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Registry entry creation timestamp (UTC).",
    )
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    domain = Column(
        String,
        nullable=False,
        index=True,
        comment="Model domain: sql|spam|file.",
    )
    model_name = Column(String, nullable=False, comment="Model family/name.")
    version = Column(String, nullable=False, index=True, comment="Model version identifier.")
    stage = Column(
        String,
        nullable=False,
        default="candidate",
        index=True,
        comment="Lifecycle stage: candidate|active|retired.",
    )
    artifact_path = Column(String, nullable=False, comment="Filesystem path to model artifact.")
    promoted_at = Column(DateTime(timezone=True), nullable=True, comment="Promotion timestamp when stage becomes active.")
    notes = Column(Text, nullable=True, comment="Optional free-text notes.")
    _metrics_json = Column("metrics", Text, nullable=True, comment="JSON-serialized evaluation metrics.")

    @property
    def metrics(self) -> Optional[Dict[str, Any]]:
        json_str = getattr(self, "_metrics_json", None)
        if not json_str:
            return None
        try:
            parsed = json.loads(json_str)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None

    @metrics.setter
    def metrics(self, value: Optional[Dict[str, Any]]):
        self._metrics_json = json.dumps(value) if isinstance(value, dict) else None

    def __repr__(self):
        return (
            f"<DefenderModelRegistry(id='{self.id}', domain='{self.domain}', "
            f"version='{self.version}', stage='{self.stage}')>"
        )


class DefenderTrainingJob(Base):
    __tablename__ = "defender_training_jobs"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        comment="UUID string identifier.",
    )
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Job creation timestamp (UTC).",
    )
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    started_at = Column(DateTime(timezone=True), nullable=True, comment="Job execution start timestamp (UTC).")
    finished_at = Column(DateTime(timezone=True), nullable=True, comment="Job completion timestamp (UTC).")
    status = Column(
        String,
        nullable=False,
        default="queued",
        index=True,
        comment="Job lifecycle status: queued|running|succeeded|failed.",
    )
    domain = Column(
        String,
        nullable=False,
        index=True,
        comment="Target domain: sql|spam|file|all.",
    )
    requested_by = Column(
        String,
        nullable=True,
        index=True,
        comment="User id that triggered the job.",
    )
    min_feedback_samples = Column(
        Integer,
        nullable=False,
        default=5,
        comment="Minimum feedback samples required per domain.",
    )
    promote_if_better = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether auto-promotion gate should run after training.",
    )
    notes = Column(Text, nullable=True, comment="Operator notes for this run.")
    _result_json = Column("result", Text, nullable=True, comment="JSON serialized training result payload.")

    @property
    def result(self) -> Optional[Dict[str, Any]]:
        json_str = getattr(self, "_result_json", None)
        if not json_str:
            return None
        try:
            parsed = json.loads(json_str)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None

    @result.setter
    def result(self, value: Optional[Dict[str, Any]]):
        self._result_json = json.dumps(value) if isinstance(value, dict) else None

    def __repr__(self):
        return f"<DefenderTrainingJob(id='{self.id}', domain='{self.domain}', status='{self.status}')>"


class User(Base):
    __tablename__ = "users"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        comment="UUID string identifier.",
    )
    email = Column(String, unique=True, index=True, nullable=False, comment="User email (lowercased).")
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Primary tenant assigned to this user.",
    )
    full_name = Column(String, nullable=True, comment="User display full name.")
    password_hash = Column(String, nullable=False, comment="Argon2 password hash.")
    role = Column(String, nullable=False, index=True, default="viewer", comment="admin|analyst|reviewer|viewer")
    is_active = Column(Boolean, nullable=False, default=True, comment="Whether the user can authenticate.")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="Creation timestamp (UTC).",
    )
    last_login_at = Column(DateTime(timezone=True), nullable=True, comment="Last login timestamp (UTC).")

    def __repr__(self):
        return f"<User(id='{self.id}', email='{self.email}', role='{self.role}', active={self.is_active})>"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
        comment="UUID string identifier.",
    )
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Audit event timestamp (UTC).",
    )
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    actor_user_id = Column(String, nullable=True, index=True, comment="Actor user ID (nullable for anonymous/failure events).")
    action = Column(String, nullable=False, index=True, comment="Action name (e.g., auth.login, config.patch).")
    resource_type = Column(String, nullable=True, index=True, comment="Resource type (e.g., user, alert, config).")
    resource_id = Column(String, nullable=True, index=True, comment="Resource identifier.")
    ip = Column(String, nullable=True, index=True, comment="Client IP address if available.")
    user_agent = Column(String, nullable=True, comment="Client user agent.")
    success = Column(Boolean, nullable=False, default=True, index=True, comment="Event outcome.")
    details_json = Column(Text, nullable=True, comment="JSON-serialized event details.")

    def __repr__(self):
        return f"<AuditLog(id='{self.id}', action='{self.action}', success={self.success})>"


class SecurityCase(Base):
    __tablename__ = "security_cases"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: f"case-{uuid.uuid4()}",
        comment="Case identifier.",
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Creation timestamp (UTC).",
    )
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Last update timestamp (UTC).",
    )
    status = Column(
        String,
        nullable=False,
        default="new",
        index=True,
        comment="Case status: new|triaged|investigating|contained|closed.",
    )
    severity = Column(
        String,
        nullable=False,
        default="Medium",
        index=True,
        comment="Case severity: Critical|High|Medium|Low.",
    )
    title = Column(String, nullable=False, comment="Case title.")
    description = Column(Text, nullable=True, comment="Case description.")
    domain = Column(
        String,
        nullable=True,
        index=True,
        comment="Domain: sql|file|spam|alert|platform.",
    )
    source_type = Column(
        String,
        nullable=True,
        index=True,
        comment="Source object type that originated the case.",
    )
    source_id = Column(
        String,
        nullable=True,
        index=True,
        comment="Source object identifier.",
    )
    owner_user_id = Column(
        String,
        nullable=True,
        index=True,
        comment="Current case owner user ID.",
    )
    created_by_user_id = Column(
        String,
        nullable=False,
        index=True,
        comment="Creator user ID.",
    )
    _tags_json = Column("tags", Text, nullable=True, comment="JSON list of case tags.")
    _evidence_json = Column("evidence", Text, nullable=True, comment="JSON list of evidence objects.")
    _timeline_json = Column("timeline", Text, nullable=True, comment="JSON list of case timeline events.")

    @property
    def tags(self) -> List[str]:
        if not self._tags_json:
            return []
        try:
            parsed = json.loads(self._tags_json)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []

    @tags.setter
    def tags(self, value: Optional[List[str]]):
        if isinstance(value, list):
            self._tags_json = json.dumps([str(v) for v in value if str(v).strip()])
            return
        self._tags_json = json.dumps([])

    @property
    def evidence(self) -> List[Dict[str, Any]]:
        if not self._evidence_json:
            return []
        try:
            parsed = json.loads(self._evidence_json)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []

    @evidence.setter
    def evidence(self, value: Optional[List[Dict[str, Any]]]):
        if isinstance(value, list):
            cleaned: List[Dict[str, Any]] = []
            for item in value:
                if isinstance(item, dict):
                    cleaned.append(item)
            self._evidence_json = json.dumps(cleaned)
            return
        self._evidence_json = json.dumps([])

    @property
    def timeline(self) -> List[Dict[str, Any]]:
        if not self._timeline_json:
            return []
        try:
            parsed = json.loads(self._timeline_json)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []

    @timeline.setter
    def timeline(self, value: Optional[List[Dict[str, Any]]]):
        if isinstance(value, list):
            cleaned: List[Dict[str, Any]] = []
            for item in value:
                if isinstance(item, dict):
                    cleaned.append(item)
            self._timeline_json = json.dumps(cleaned)
            return
        self._timeline_json = json.dumps([])

    def __repr__(self):
        return f"<SecurityCase(id='{self.id}', status='{self.status}', severity='{self.severity}')>"


class SecurityCaseNote(Base):
    __tablename__ = "security_case_notes"

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: f"case-note-{uuid.uuid4()}",
        comment="Case note identifier.",
    )
    case_id = Column(
        String,
        nullable=False,
        index=True,
        comment="Parent case identifier.",
    )
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Case note creation timestamp (UTC).",
    )
    author_user_id = Column(
        String,
        nullable=False,
        index=True,
        comment="Authoring user ID.",
    )
    note = Column(
        Text,
        nullable=False,
        comment="Case note text.",
    )

    def __repr__(self):
        return f"<SecurityCaseNote(id='{self.id}', case_id='{self.case_id}')>"


class AlertCaseLink(Base):
    __tablename__ = "alert_case_links"
    __table_args__ = (
        UniqueConstraint("case_id", "alert_id", name="uq_alert_case_links_case_alert"),
    )

    id = Column(
        String,
        primary_key=True,
        index=True,
        default=lambda: f"case-alert-link-{uuid.uuid4()}",
        comment="Case-alert link identifier.",
    )
    case_id = Column(
        String,
        nullable=False,
        index=True,
        comment="Linked case identifier.",
    )
    tenant_id = Column(
        String,
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
        comment="Owning tenant ID.",
    )
    alert_id = Column(
        String,
        nullable=False,
        index=True,
        comment="Linked alert identifier.",
    )
    linked_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        comment="Link creation timestamp (UTC).",
    )
    linked_by_user_id = Column(
        String,
        nullable=False,
        index=True,
        comment="User ID that created the link.",
    )
    note = Column(
        Text,
        nullable=True,
        comment="Optional link rationale/note.",
    )

    def __repr__(self):
        return (
            f"<AlertCaseLink(id='{self.id}', case_id='{self.case_id}', "
            f"alert_id='{self.alert_id}')>"
        )

