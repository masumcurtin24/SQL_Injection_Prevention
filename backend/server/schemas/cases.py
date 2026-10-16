from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field
from backend.server.schemas.identity import UserSummary

CaseStatus = Literal["new", "triaged", "investigating", "contained", "closed"]
CaseSeverity = Literal["Critical", "High", "Medium", "Low"]


class CaseTimelineEntry(BaseModel):
    timestamp: datetime
    actor_user_id: Optional[str] = None
    actor: Optional[UserSummary] = None
    action: str
    note: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=4000)
    severity: CaseSeverity = "Medium"
    domain: Optional[str] = Field(None, max_length=40)
    source_type: Optional[str] = Field(None, max_length=40)
    source_id: Optional[str] = Field(None, max_length=255)
    owner_user_id: Optional[str] = Field(None, max_length=128)
    tags: List[str] = Field(default_factory=list, max_length=50)
    evidence: List[Dict[str, Any]] = Field(default_factory=list, max_length=200)
    alert_ids: List[str] = Field(default_factory=list, max_length=200)


class CaseStatusUpdateRequest(BaseModel):
    status: CaseStatus
    note: Optional[str] = Field(None, max_length=2000)


class CaseAssignRequest(BaseModel):
    owner_user_id: Optional[str] = Field(None, max_length=128)
    note: Optional[str] = Field(None, max_length=2000)


class CaseNoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)


class CaseAlertLinkRequest(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=255)
    note: Optional[str] = Field(None, max_length=2000)


class CaseNoteEntry(BaseModel):
    id: str
    case_id: str
    tenant_id: str
    created_at: datetime
    author_user_id: str
    author: Optional[UserSummary] = None
    note: str

    model_config = ConfigDict(from_attributes=True)


class AlertCaseLinkEntry(BaseModel):
    id: str
    case_id: str
    tenant_id: str
    alert_id: str
    linked_at: datetime
    linked_by_user_id: str
    linked_by: Optional[UserSummary] = None
    note: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class CaseActivityEntry(BaseModel):
    tenant_id: Optional[str] = None
    timestamp: datetime
    actor_user_id: Optional[str] = None
    actor: Optional[UserSummary] = None
    action: str
    note: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class SecurityCaseSummary(BaseModel):
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime
    status: CaseStatus
    severity: CaseSeverity
    title: str
    domain: Optional[str] = None
    source_type: Optional[str] = None
    source_id: Optional[str] = None
    owner_user_id: Optional[str] = None
    owner: Optional[UserSummary] = None
    created_by_user_id: str
    created_by: Optional[UserSummary] = None
    tags: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class SecurityCaseDetail(SecurityCaseSummary):
    description: Optional[str] = None
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[CaseTimelineEntry] = Field(default_factory=list)
    notes: List[CaseNoteEntry] = Field(default_factory=list)
    alert_links: List[AlertCaseLinkEntry] = Field(default_factory=list)
    activity: List[CaseActivityEntry] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class SecurityCaseListResponse(BaseModel):
    cases: List[SecurityCaseSummary]
    total_cases: int
    page: int
    page_size: int
    total_pages: int
    status_counts: Dict[str, int]


class SecurityCaseStatsResponse(BaseModel):
    total_cases: int
    open_cases: int
    closed_cases: int
    by_status: Dict[str, int]


class CaseNotesResponse(BaseModel):
    case_id: str
    count: int
    notes: List[CaseNoteEntry]


class CaseAlertLinksResponse(BaseModel):
    case_id: str
    count: int
    links: List[AlertCaseLinkEntry]


class CaseActivityResponse(BaseModel):
    case_id: str
    count: int
    activity: List[CaseActivityEntry]
