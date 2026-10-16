from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict
from backend.server.schemas.identity import UserSummary


class AuditLogItem(BaseModel):
    id: str
    timestamp: datetime
    tenant_id: str
    actor_user_id: Optional[str] = None
    actor: Optional[UserSummary] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class AuditListResponse(BaseModel):
    items: List[AuditLogItem]
    limit: int
    offset: int
    total: int
