from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class SQLFeedbackRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=10000)
    true_label: Literal["Malicious", "Benign"]
    predicted_label: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    analysis_id: Optional[str] = None
    source: Literal["human", "system"] = "human"
    notes: Optional[str] = None


class FileFeedbackRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=512)
    observed_text: Optional[str] = Field(None, max_length=20000)
    true_label: Literal["Malicious", "Suspicious", "Safe"]
    predicted_label: Optional[str] = None
    recommended_action: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    analysis_id: Optional[str] = None
    source: Literal["human", "system"] = "human"
    notes: Optional[str] = None


class SpamFeedbackV1Request(BaseModel):
    subject: Optional[str] = Field(None, max_length=500)
    body_text: str = Field(..., min_length=1, max_length=20000)
    sender_email: Optional[str] = Field(None, max_length=320)
    true_label: Literal["Spam", "Ham"]
    predicted_label: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    analysis_id: Optional[str] = None
    source: Literal["human", "system"] = "human"
    notes: Optional[str] = None


class DefenderRetrainRequest(BaseModel):
    domain: Literal["sql", "spam", "file", "all"] = "all"
    min_feedback_samples: int = Field(5, ge=1, le=10000)
    promote_if_better: bool = False
    notes: Optional[str] = None


class DefenderPromoteRequest(BaseModel):
    registry_id: str = Field(..., min_length=1)
    force: bool = False
    notes: Optional[str] = None


class DefenderRollbackRequest(BaseModel):
    domain: Literal["sql", "spam", "file"]
    target_registry_id: Optional[str] = None
    notes: Optional[str] = None


class DefenderModelInfo(BaseModel):
    id: str
    tenant_id: str
    timestamp: datetime
    domain: str
    model_name: str
    version: str
    stage: str
    artifact_path: str
    promoted_at: Optional[datetime] = None
    notes: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class DefenderStatusResponse(BaseModel):
    feedback_counts: Dict[str, int]
    pending_feedback: int
    models: Dict[str, List[DefenderModelInfo]]
    recent_jobs: List["DefenderTrainingJobInfo"] = Field(default_factory=list)
    job_status_counts: Dict[str, int] = Field(default_factory=dict)


class DefenderRetrainResult(BaseModel):
    domain: str
    status: str
    details: Dict[str, Any]


class DefenderRetrainResponse(BaseModel):
    status: str
    job_id: Optional[str] = None
    results: List[DefenderRetrainResult]


class DefenderTrainingJobInfo(BaseModel):
    id: str
    tenant_id: str
    timestamp: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: str
    domain: str
    requested_by: Optional[str] = None
    min_feedback_samples: int
    promote_if_better: bool
    notes: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class DefenderRollbackResponse(BaseModel):
    domain: str
    rolled_back_from_registry_id: Optional[str] = None
    active_registry: DefenderModelInfo


DefenderStatusResponse.model_rebuild()
