from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


class UserSummary(BaseModel):
    id: str
    display_name: str
    full_name: Optional[str] = None
    role: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
