from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

ALLOWED_ROLES = {"admin", "analyst", "reviewer", "viewer"}


class UserPublic(BaseModel):
    id: str
    email: str
    tenant_id: str
    role: str
    full_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UserOut(BaseModel):
    id: str
    email: str
    tenant_id: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    refresh_expires_in: Optional[int] = None
    user: UserPublic


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=2048)


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    user: UserPublic


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=2048)


class LogoutResponse(BaseModel):
    success: bool
    detail: str


class LogoutAllResponse(BaseModel):
    success: bool
    revoked_sessions: int


class StepUpRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    actions: Optional[List[str]] = Field(
        default=None,
        description="Optional action scopes this step-up token may authorize. Defaults to wildcard.",
    )


class StepUpResponse(BaseModel):
    step_up_token: str
    token_type: str = "bearer"
    expires_in: int
    actions: List[str]


class UserCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    tenant_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=1024)
    full_name: Optional[str] = Field(default=None, max_length=160)
    role: str = Field(default="viewer")
    is_active: bool = True

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("full_name")
    @classmethod
    def _normalize_full_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        normalized = str(v).strip()
        return normalized or None

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        role = v.strip().lower()
        if role not in ALLOWED_ROLES:
            raise ValueError(f"Invalid role: {role}")
        return role

    @field_validator("tenant_id")
    @classmethod
    def _normalize_tenant_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        normalized = str(v).strip()
        return normalized or None


class UserUpdateRequest(BaseModel):
    tenant_id: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None

    @field_validator("full_name")
    @classmethod
    def _normalize_full_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        normalized = str(v).strip()
        if len(normalized) > 160:
            raise ValueError("Full name is too long.")
        return normalized or None

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        role = v.strip().lower()
        if role not in ALLOWED_ROLES:
            raise ValueError(f"Invalid role: {role}")
        return role

    @field_validator("password")
    @classmethod
    def _validate_password(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        password = v.strip()
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters.")
        if len(password) > 1024:
            raise ValueError("Password too long.")
        return password

    @field_validator("tenant_id")
    @classmethod
    def _normalize_tenant_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        normalized = str(v).strip()
        if len(normalized) > 128:
            raise ValueError("Tenant ID is too long.")
        return normalized or None


class UsersListResponse(BaseModel):
    users: List[UserOut]


class TenantSummary(BaseModel):
    id: str
    slug: str
    name: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class TenantListResponse(BaseModel):
    current_tenant_id: str
    tenants: List[TenantSummary]


class UserDeleteResponse(BaseModel):
    success: bool
    detail: str
    user_id: str
    email: str
