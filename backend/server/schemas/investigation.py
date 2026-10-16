from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field
from backend.server.schemas.identity import UserSummary

InvestigationEventType = Literal[
    "query",
    "file_scan",
    "spam_check",
    "alert",
    "case",
    "case_note",
    "case_alert_link",
]

CorrelationLevel = Literal["strong", "moderate", "weak", "none"]


class InvestigationCorrelationReason(BaseModel):
    code: str
    label: str
    detail: Optional[str] = None
    key: Optional[str] = None
    value: Optional[str] = None


class InvestigationRelatedEvent(BaseModel):
    id: str
    event_type: InvestigationEventType
    timestamp: datetime
    title: str
    severity: Optional[str] = None
    source_ref: Dict[str, str] = Field(default_factory=dict)
    correlation_level: Optional[CorrelationLevel] = None
    correlation_reasons: List[InvestigationCorrelationReason] = Field(default_factory=list)


class InvestigationRelatedEntity(BaseModel):
    key: str
    value: str
    match_count: int
    reasons: List[str] = Field(default_factory=list)
    related_event_ids: List[str] = Field(default_factory=list)


class InvestigationTimelineItem(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    timestamp: datetime
    event_type: InvestigationEventType
    severity: Optional[str] = None
    title: str
    summary: Optional[str] = None
    actor_user_id: Optional[str] = None
    actor: Optional[UserSummary] = None
    owner_user_id: Optional[str] = None
    owner: Optional[UserSummary] = None
    entity_keys: Dict[str, str] = Field(default_factory=dict)
    source_ref: Dict[str, str] = Field(default_factory=dict)
    case_ids: List[str] = Field(default_factory=list)
    correlation_level: Optional[CorrelationLevel] = None
    correlation_reasons: List[InvestigationCorrelationReason] = Field(default_factory=list)
    related_entities: List[InvestigationRelatedEntity] = Field(default_factory=list)
    related_events: List[InvestigationRelatedEvent] = Field(default_factory=list)


class InvestigationTimelineResponse(BaseModel):
    items: List[InvestigationTimelineItem]
    count: int
    limit: int
    start: Optional[str] = None
    end: Optional[str] = None
    before: Optional[str] = None
    event_types: Optional[str] = None
    entity_key: Optional[str] = None
    entity_value: Optional[str] = None
