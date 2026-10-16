from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.models import Tenant, User
from backend.security.auth import create_step_up_token, hash_password, verify_password
from backend.security.request_context import sql_service_context
from backend.services.auth_service import AuthRefreshError, AuthService
from backend.server.deps.auth import get_current_user, require_role
from backend.server.deps.tenant import TenantContext, get_tenant_context, list_accessible_tenants, resolve_user_tenant_id
from backend.server.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    LogoutRequest,
    LogoutResponse,
    LogoutAllResponse,
    StepUpRequest,
    StepUpResponse,
    UserCreateRequest,
    UserUpdateRequest,
    UserOut,
    UserPublic,
    UserDeleteResponse,
    TenantListResponse,
    TenantSummary,
    UsersListResponse,
)
from backend.utils.audit import write_audit
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


@router.post("/login", response_model=LoginResponse, summary="Authenticate and receive a JWT access token")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    email = payload.email.strip().lower()

    # Login uses fixed SQLAlchemy ORM predicates. Assign auth_service so the
    # SQL enforcer can audit these internal lookups without classifying them as
    # anonymous unknown_service traffic.
    with sql_service_context("auth_service"):
        user = db.query(User).filter(User.email == email).first()
        if user is None or not bool(user.is_active):
            write_audit(
                db=db,
                request=request,
                actor=None,
                action="auth.login",
                resource_type="auth",
                resource_id="login",
                details={"attempted_email": email, "reason": "user_not_found_or_inactive"},
                success=False,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not verify_password(user.password_hash, payload.password):
            write_audit(
                db=db,
                request=request,
                actor=None,
                action="auth.login",
                resource_type="auth",
                resource_id="login",
                details={"attempted_email": email, "reason": "bad_password"},
                success=False,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user.last_login_at = datetime.now(timezone.utc)
        db.add(user)
        db.commit()
        db.refresh(user)
        write_audit(
            db=db,
            request=request,
            actor=user,
            action="auth.login",
            resource_type="auth",
            resource_id="login",
            details={"email": user.email, "role": user.role},
            success=True,
        )

        token_bundle = AuthService.issue_login_tokens(db=db, user=user, request=request)
    return LoginResponse(
        access_token=str(token_bundle["access_token"]),
        token_type="bearer",
        expires_in=int(token_bundle["access_expires_in"]),
        refresh_token=str(token_bundle["refresh_token"]),
        refresh_expires_in=int(token_bundle["refresh_expires_in"]),
        user=UserPublic(
            id=user.id,
            email=user.email,
            tenant_id=resolve_user_tenant_id(user),
            role=user.role,
            full_name=user.full_name,
        ),
    )


@router.get("/me", response_model=UserOut, summary="Get current user (JWT required)")
def me(current_user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(current_user)


@router.post("/step-up", response_model=StepUpResponse, summary="Perform step-up authentication for sensitive actions")
def step_up_authentication(
    payload: StepUpRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StepUpResponse:
    if not verify_password(current_user.password_hash, payload.password):
        write_audit(
            db=db,
            request=request,
            actor=current_user,
            action="auth.step_up",
            resource_type="auth",
            resource_id="step_up",
            details={"reason": "bad_password"},
            success=False,
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    scoped_actions = []
    for action in payload.actions or []:
        value = str(action or "").strip()
        if value and value not in scoped_actions:
            scoped_actions.append(value)
    if not scoped_actions:
        scoped_actions = ["*"]

    token, expires_in = create_step_up_token(
        user_id=current_user.id,
        role=current_user.role,
        email=current_user.email,
        tenant_id=resolve_user_tenant_id(current_user),
        actions=scoped_actions,
        exp=None,
    )
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="auth.step_up",
        resource_type="auth",
        resource_id="step_up",
        details={"actions": scoped_actions, "expires_in": expires_in},
        success=True,
    )
    return StepUpResponse(
        step_up_token=token,
        token_type="bearer",
        expires_in=expires_in,
        actions=scoped_actions,
    )


@router.post("/refresh", response_model=RefreshResponse, summary="Rotate refresh token and get new access token")
def refresh(
    payload: RefreshRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> RefreshResponse:
    try:
        refreshed = AuthService.refresh_tokens(db=db, refresh_token=payload.refresh_token, request=request)
        user = refreshed.get("user")
        if user is None:
            raise HTTPException(status_code=401, detail="User not found for refresh token.")
        write_audit(
            db=db,
            request=request,
            actor=user,
            action="auth.refresh",
            resource_type="auth",
            resource_id="refresh",
            details={"user_id": user.id, "email": user.email, "role": user.role},
            success=True,
        )
        return RefreshResponse(
            access_token=str(refreshed["access_token"]),
            token_type="bearer",
            expires_in=int(refreshed["access_expires_in"]),
            refresh_token=str(refreshed["refresh_token"]),
            refresh_expires_in=int(refreshed["refresh_expires_in"]),
            user=UserPublic(
                id=user.id,
                email=user.email,
                tenant_id=resolve_user_tenant_id(user),
                role=user.role,
                full_name=user.full_name,
            ),
        )
    except AuthRefreshError as e:
        write_audit(
            db=db,
            request=request,
            actor=None,
            action="auth.refresh",
            resource_type="auth",
            resource_id="refresh",
            details={"reason": e.reason},
            success=False,
        )
        raise HTTPException(status_code=401, detail=e.detail)


@router.post("/logout", response_model=LogoutResponse, summary="Revoke current refresh token")
def logout(
    payload: LogoutRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LogoutResponse:
    ok = AuthService.logout(db=db, user=current_user, refresh_token=payload.refresh_token)
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="auth.logout",
        resource_type="auth",
        resource_id="logout",
        details={"user_id": current_user.id, "email": current_user.email, "token_revoked": bool(ok)},
        success=True,
    )
    if not ok:
        return LogoutResponse(success=False, detail="Session not found or already revoked.")
    return LogoutResponse(success=True, detail="Session revoked.")


@router.post("/logout-all", response_model=LogoutAllResponse, summary="Revoke all active refresh sessions for current user")
def logout_all(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LogoutAllResponse:
    revoked = AuthService.logout_all(db=db, user=current_user)
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="auth.logout_all",
        resource_type="auth",
        resource_id="logout_all",
        details={"user_id": current_user.id, "email": current_user.email, "revoked_sessions": revoked},
        success=True,
    )
    return LogoutAllResponse(success=True, revoked_sessions=revoked)


@router.post(
    "/users",
    response_model=UserOut,
    summary="Create a user (admin only)",
)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> UserOut:
    email = payload.email.strip().lower()
    tenant_id = str(payload.tenant_id or "").strip() or tenant_ctx.tenant_id
    if tenant_id != tenant_ctx.tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden tenant scope")

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id, Tenant.is_active.is_(True)).first()
    if tenant is None:
        raise HTTPException(status_code=400, detail=f"Invalid tenant: {tenant_id}")

    existing = db.query(User).filter(User.email == email).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="User already exists")

    user = User(
        email=email,
        tenant_id=tenant_id,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="auth.user.create",
        resource_type="user",
        resource_id=user.id,
        details={
            "email": user.email,
            "tenant_id": user.tenant_id,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": bool(user.is_active),
        },
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return UserOut.model_validate(user)


@router.get(
    "/users",
    response_model=UsersListResponse,
    dependencies=[Depends(require_role("admin"))],
    summary="List users (admin only)",
)
def list_users(
    db: Session = Depends(get_db),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> UsersListResponse:
    users = (
        db.query(User)
        .filter(User.tenant_id == tenant_ctx.tenant_id)
        .order_by(User.created_at.desc())
        .all()
    )
    return UsersListResponse(users=[UserOut.model_validate(u) for u in users])


@router.patch(
    "/users/{user_id}",
    response_model=UserOut,
    summary="Update a user role/status/password (admin only)",
)
def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> UserOut:
    user = db.query(User).filter(User.id == user_id, User.tenant_id == tenant_ctx.tenant_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    next_role = payload.role if payload.role is not None else user.role
    next_is_active = payload.is_active if payload.is_active is not None else bool(user.is_active)

    admin_count = (
        db.query(User)
        .filter(
            User.tenant_id == tenant_ctx.tenant_id,
            User.role == "admin",
            User.is_active.is_(True),
        )
        .count()
    )
    if user.role == "admin" and bool(user.is_active):
        if next_role != "admin" or not bool(next_is_active):
            if admin_count <= 1:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot remove or deactivate the last active admin user.",
                )

    changes = {}
    full_name_provided = "full_name" in payload.model_fields_set
    tenant_id_provided = "tenant_id" in payload.model_fields_set
    if tenant_id_provided:
        next_tenant_id = str(payload.tenant_id or "").strip() or None
        if next_tenant_id is None:
            raise HTTPException(status_code=400, detail="tenant_id cannot be empty")
        tenant = db.query(Tenant).filter(Tenant.id == next_tenant_id, Tenant.is_active.is_(True)).first()
        if tenant is None:
            raise HTTPException(status_code=400, detail=f"Invalid tenant: {next_tenant_id}")
        if next_tenant_id != tenant_ctx.tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden tenant scope")
        if user.tenant_id != next_tenant_id:
            changes["tenant_id"] = {"from": user.tenant_id, "to": next_tenant_id}
            user.tenant_id = next_tenant_id

    if full_name_provided and user.full_name != payload.full_name:
        changes["full_name"] = {"from": user.full_name, "to": payload.full_name}
        user.full_name = payload.full_name
    if payload.role is not None and user.role != payload.role:
        changes["role"] = {"from": user.role, "to": payload.role}
        user.role = payload.role
    if payload.is_active is not None and bool(user.is_active) != bool(payload.is_active):
        changes["is_active"] = {"from": bool(user.is_active), "to": bool(payload.is_active)}
        user.is_active = bool(payload.is_active)
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
        changes["password_reset"] = True

    if not changes:
        return UserOut.model_validate(user)

    db.add(user)
    db.commit()
    db.refresh(user)

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="auth.user.update",
        resource_type="user",
        resource_id=user.id,
        details={"email": user.email, "changes": changes},
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )
    return UserOut.model_validate(user)


@router.delete(
    "/users/{user_id}",
    response_model=UserDeleteResponse,
    summary="Delete a user (admin only)",
)
def delete_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
    tenant_ctx: TenantContext = Depends(get_tenant_context),
) -> UserDeleteResponse:
    user = db.query(User).filter(User.id == user_id, User.tenant_id == tenant_ctx.tenant_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    if user.role == "admin" and bool(user.is_active):
        active_admin_count = (
            db.query(User)
            .filter(
                User.tenant_id == tenant_ctx.tenant_id,
                User.role == "admin",
                User.is_active.is_(True),
            )
            .count()
        )
        if active_admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last active admin user.")

    target_email = str(user.email)
    revoked_sessions = AuthService.logout_all(db=db, user=user)
    db.delete(user)
    db.commit()

    write_audit(
        db=db,
        request=request,
        actor=current_user,
        action="auth.user.delete",
        resource_type="user",
        resource_id=user_id,
        details={
            "deleted_user_email": target_email,
            "revoked_sessions": revoked_sessions,
        },
        success=True,
        tenant_id=tenant_ctx.tenant_id,
    )

    return UserDeleteResponse(
        success=True,
        detail="User deleted.",
        user_id=user_id,
        email=target_email,
    )


@router.get(
    "/tenants",
    response_model=TenantListResponse,
    summary="List accessible tenants and current tenant context",
)
def list_tenants(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TenantListResponse:
    tenants = list_accessible_tenants(db=db, current_user=current_user)
    current_tenant_id = resolve_user_tenant_id(current_user)
    return TenantListResponse(
        current_tenant_id=current_tenant_id,
        tenants=[TenantSummary.model_validate(row) for row in tenants],
    )
