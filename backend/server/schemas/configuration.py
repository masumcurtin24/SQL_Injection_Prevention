from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field
from backend.server.schemas.identity import UserSummary


class DdlExecConfig(BaseModel):
    policy: Literal["deny_non_migration", "deny", "monitor", "allow"]
    allowed_services: str
    allowlist_patterns: List[str]

    model_config = ConfigDict(extra="forbid")


class AllowlistConfig(BaseModel):
    mode: Literal["safe", "regex"]
    last_reviewed_at: str
    max_age_days: int = Field(ge=1)

    model_config = ConfigDict(extra="forbid")


class MonitorConfig(BaseModel):
    backoff_n: int = Field(ge=1)

    model_config = ConfigDict(extra="forbid")


class BoolRequireConfig(BaseModel):
    require: bool

    model_config = ConfigDict(extra="forbid")


class TelemetryConfig(BaseModel):
    file: str

    model_config = ConfigDict(extra="forbid")


class SqlConstructionRegistryEntry(BaseModel):
    id: str
    enabled: bool = True
    service: str = Field(
        default=".*",
        description="Service regex that scopes this raw SQL governance entry.",
    )
    fingerprint: Optional[str] = None
    template: Optional[str] = None
    tenant_id: Optional[str] = "*"
    role: Optional[Literal["viewer", "reviewer", "analyst", "admin", "*"]] = "*"
    reason: str
    expires_at: Optional[str] = None
    owner: Optional[str] = None
    allow_unparameterized: bool = True

    model_config = ConfigDict(extra="forbid")


class SqlConstructionServiceProfile(BaseModel):
    id: str
    enabled: bool = True
    service: str = Field(
        default=".*",
        description="Service regex that scopes this SQL secure-construction profile.",
    )
    description: Optional[str] = None
    require_parameterized_select: bool = True
    require_parameterized_write: bool = True
    require_approved_raw_sql: bool = True
    unknown_raw_sql_action: Literal[
        "flag_for_review_block",
        "block_immediate",
        "block_critical",
        "monitor",
        "allow",
    ] = "flag_for_review_block"

    model_config = ConfigDict(extra="forbid")


class SqlConstructionConfig(BaseModel):
    mode: Literal["off", "monitor", "strict"] = "strict"
    require_parameterized_default: bool = True
    require_approved_raw_sql: bool = True
    unknown_raw_sql_action: Literal[
        "flag_for_review_block",
        "block_immediate",
        "block_critical",
        "monitor",
        "allow",
    ] = "flag_for_review_block"
    migration_service_pattern: str = "^alembic$|^/admin/migrations$|^/startup/bootstrap-admin$"
    allow_constant_select: bool = True
    service_profiles: List[SqlConstructionServiceProfile] = Field(default_factory=list)
    approved_raw_sql: List[SqlConstructionRegistryEntry] = Field(default_factory=list)
    raw_sql_exceptions: List[SqlConstructionRegistryEntry] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class ArchiveLimitsConfig(BaseModel):
    max_files: int = Field(ge=1)
    max_depth: int = Field(ge=1)
    max_uncompressed_mb: int = Field(ge=1)
    max_entry_mb: int = Field(ge=1)

    model_config = ConfigDict(extra="forbid")


class YaraPolicyConfig(BaseModel):
    malicious_threat_levels: List[str]
    suspicious_threat_levels: List[str]

    model_config = ConfigDict(extra="forbid")


class AllowDomainsConfig(BaseModel):
    payment: List[str]
    exfil: List[str]

    model_config = ConfigDict(extra="forbid")


class FileDetectionConfig(BaseModel):
    poc_policy: Literal["suspicious", "malicious_on_danger", "block_on_danger"]
    archive_limits: ArchiveLimitsConfig
    yara: YaraPolicyConfig
    allow_domains: AllowDomainsConfig
    watch_lolbas_binaries: List[str]

    model_config = ConfigDict(extra="forbid")


class SpamDetectionConfig(BaseModel):
    final_threshold: float = Field(ge=0.0, le=1.0)
    thresholds: Optional["SpamThresholdsConfig"] = None
    feature_weights: Optional["SpamFeatureWeightsConfig"] = None
    calibration: Optional["SpamCalibrationConfig"] = None
    suspicious_tlds: List[str]

    model_config = ConfigDict(extra="forbid")


class SpamThresholdsConfig(BaseModel):
    allow: float = Field(ge=0.0, le=1.0)
    suspicious: float = Field(ge=0.0, le=1.0)
    block: float = Field(ge=0.0, le=1.0)
    ood: float = Field(ge=0.0, le=1.0)

    model_config = ConfigDict(extra="forbid")


class SpamFeatureWeightsConfig(BaseModel):
    classical: float = Field(ge=0.0, le=1.0)
    transformer: float = Field(ge=0.0, le=1.0)
    online: float = Field(ge=0.0, le=1.0)
    heuristic: float = Field(ge=0.0, le=1.0)
    reputation: float = Field(ge=0.0, le=1.0)
    campaign: float = Field(ge=0.0, le=1.0)
    header: float = Field(ge=0.0, le=1.0)
    fraud_pattern: float = Field(ge=0.0, le=1.0)

    model_config = ConfigDict(extra="forbid")


class SpamCalibrationConfig(BaseModel):
    a: float
    b: float

    model_config = ConfigDict(extra="forbid")


class SqlEnforcementRules(BaseModel):
    critical_patterns: List[str]
    ddl_exec: DdlExecConfig
    allowlist: AllowlistConfig
    monitor: MonitorConfig
    parameterization: BoolRequireConfig
    service_context: BoolRequireConfig
    telemetry: TelemetryConfig
    sql_construction: Optional[SqlConstructionConfig] = None
    file_detection: Optional[FileDetectionConfig] = None
    spam_detection: Optional[SpamDetectionConfig] = None

    model_config = ConfigDict(extra="forbid")


class DdlExecPatch(BaseModel):
    policy: Optional[Literal["deny_non_migration", "deny", "monitor", "allow"]] = None
    allowed_services: Optional[str] = None
    allowlist_patterns: Optional[List[str]] = None

    model_config = ConfigDict(extra="forbid")


class AllowlistPatch(BaseModel):
    mode: Optional[Literal["safe", "regex"]] = None
    last_reviewed_at: Optional[str] = None
    max_age_days: Optional[int] = Field(default=None, ge=1)

    model_config = ConfigDict(extra="forbid")


class MonitorPatch(BaseModel):
    backoff_n: Optional[int] = Field(default=None, ge=1)

    model_config = ConfigDict(extra="forbid")


class BoolRequirePatch(BaseModel):
    require: Optional[bool] = None

    model_config = ConfigDict(extra="forbid")


class TelemetryPatch(BaseModel):
    file: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class SqlConstructionRegistryEntryPatch(BaseModel):
    id: Optional[str] = None
    enabled: Optional[bool] = None
    service: Optional[str] = None
    fingerprint: Optional[str] = None
    template: Optional[str] = None
    tenant_id: Optional[str] = None
    role: Optional[Literal["viewer", "reviewer", "analyst", "admin", "*"]] = None
    reason: Optional[str] = None
    expires_at: Optional[str] = None
    owner: Optional[str] = None
    allow_unparameterized: Optional[bool] = None

    model_config = ConfigDict(extra="forbid")


class SqlConstructionServiceProfilePatch(BaseModel):
    id: Optional[str] = None
    enabled: Optional[bool] = None
    service: Optional[str] = None
    description: Optional[str] = None
    require_parameterized_select: Optional[bool] = None
    require_parameterized_write: Optional[bool] = None
    require_approved_raw_sql: Optional[bool] = None
    unknown_raw_sql_action: Optional[
        Literal["flag_for_review_block", "block_immediate", "block_critical", "monitor", "allow"]
    ] = None

    model_config = ConfigDict(extra="forbid")


class SqlConstructionPatch(BaseModel):
    mode: Optional[Literal["off", "monitor", "strict"]] = None
    require_parameterized_default: Optional[bool] = None
    require_approved_raw_sql: Optional[bool] = None
    unknown_raw_sql_action: Optional[
        Literal["flag_for_review_block", "block_immediate", "block_critical", "monitor", "allow"]
    ] = None
    migration_service_pattern: Optional[str] = None
    allow_constant_select: Optional[bool] = None
    service_profiles: Optional[List[SqlConstructionServiceProfilePatch]] = None
    approved_raw_sql: Optional[List[SqlConstructionRegistryEntryPatch]] = None
    raw_sql_exceptions: Optional[List[SqlConstructionRegistryEntryPatch]] = None

    model_config = ConfigDict(extra="forbid")


class ArchiveLimitsPatch(BaseModel):
    max_files: Optional[int] = Field(default=None, ge=1)
    max_depth: Optional[int] = Field(default=None, ge=1)
    max_uncompressed_mb: Optional[int] = Field(default=None, ge=1)
    max_entry_mb: Optional[int] = Field(default=None, ge=1)

    model_config = ConfigDict(extra="forbid")


class YaraPolicyPatch(BaseModel):
    malicious_threat_levels: Optional[List[str]] = None
    suspicious_threat_levels: Optional[List[str]] = None

    model_config = ConfigDict(extra="forbid")


class AllowDomainsPatch(BaseModel):
    payment: Optional[List[str]] = None
    exfil: Optional[List[str]] = None

    model_config = ConfigDict(extra="forbid")


class FileDetectionPatch(BaseModel):
    poc_policy: Optional[Literal["suspicious", "malicious_on_danger", "block_on_danger"]] = None
    archive_limits: Optional[ArchiveLimitsPatch] = None
    yara: Optional[YaraPolicyPatch] = None
    allow_domains: Optional[AllowDomainsPatch] = None
    watch_lolbas_binaries: Optional[List[str]] = None

    model_config = ConfigDict(extra="forbid")


class SpamDetectionPatch(BaseModel):
    final_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    thresholds: Optional["SpamThresholdsPatch"] = None
    feature_weights: Optional["SpamFeatureWeightsPatch"] = None
    calibration: Optional["SpamCalibrationPatch"] = None
    suspicious_tlds: Optional[List[str]] = None

    model_config = ConfigDict(extra="forbid")


class SpamThresholdsPatch(BaseModel):
    allow: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    suspicious: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    block: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    ood: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    model_config = ConfigDict(extra="forbid")


class SpamFeatureWeightsPatch(BaseModel):
    classical: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    transformer: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    online: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    heuristic: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    reputation: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    campaign: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    header: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    fraud_pattern: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    model_config = ConfigDict(extra="forbid")


class SpamCalibrationPatch(BaseModel):
    a: Optional[float] = None
    b: Optional[float] = None

    model_config = ConfigDict(extra="forbid")


class SqlEnforcementPatch(BaseModel):
    critical_patterns: Optional[List[str]] = None
    ddl_exec: Optional[DdlExecPatch] = None
    allowlist: Optional[AllowlistPatch] = None
    monitor: Optional[MonitorPatch] = None
    parameterization: Optional[BoolRequirePatch] = None
    service_context: Optional[BoolRequirePatch] = None
    telemetry: Optional[TelemetryPatch] = None
    sql_construction: Optional[SqlConstructionPatch] = None
    file_detection: Optional[FileDetectionPatch] = None
    spam_detection: Optional[SpamDetectionPatch] = None

    model_config = ConfigDict(extra="forbid")


class ConfigGetResponse(BaseModel):
    rules: Dict[str, Any]
    env_overrides: Dict[str, str]
    scope: str = "global"
    tenant_id: Optional[str] = None
    restart_required: bool = True


class ConfigPatchResponse(BaseModel):
    rules: Dict[str, Any]
    scope: str = "global"
    tenant_id: Optional[str] = None
    before_sha256: str
    after_sha256: str
    changed_paths: List[str]
    restart_required: bool = True


class GovernanceDomainSection(BaseModel):
    support: Literal["editable", "read_only", "partially_supported"]
    writable_actions: List[str] = Field(default_factory=list)
    controls: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)


class GovernanceChangeEntry(BaseModel):
    id: str
    timestamp: datetime
    tenant_id: Optional[str] = None
    actor_user_id: Optional[str] = None
    actor: Optional[UserSummary] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    success: bool
    details: Optional[Dict[str, Any]] = None


class GovernanceOverviewResponse(BaseModel):
    as_of: datetime
    scope: Literal["tenant", "global"] = "tenant"
    tenant_id: Optional[str] = None
    domains: Dict[str, GovernanceDomainSection] = Field(default_factory=dict)
    recent_changes: List[GovernanceChangeEntry] = Field(default_factory=list)
