from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Iterator

_current_service: ContextVar[str] = ContextVar("current_service", default="")
_current_tenant_id: ContextVar[str] = ContextVar("current_tenant_id", default="")
_current_role: ContextVar[str] = ContextVar("current_role", default="")


def set_current_service(value: str) -> Token:
    return _current_service.set(value or "")


def reset_current_service(token: Token) -> None:
    _current_service.reset(token)


def get_current_service() -> str:
    return _current_service.get()


def set_current_tenant_id(value: str) -> Token:
    return _current_tenant_id.set(value or "")


def reset_current_tenant_id(token: Token) -> None:
    _current_tenant_id.reset(token)


def get_current_tenant_id() -> str:
    return _current_tenant_id.get()


def set_current_role(value: str) -> Token:
    return _current_role.set((value or "").strip().lower())


def reset_current_role(token: Token) -> None:
    _current_role.reset(token)


def get_current_role() -> str:
    return _current_role.get()


_UNSET = object()


@contextmanager
def sql_service_context(
    service: str,
    *,
    tenant_id: str | object = _UNSET,
    role: str | object = _UNSET,
) -> Iterator[None]:
    """
    Temporarily assign an internal SQL-enforcement service identity.

    Authentication, bootstrap, and WebSocket authentication use fixed ORM
    queries but can run outside HTTP middleware. These contexts let the SQL
    enforcer apply scoped policy without treating safe internal lookups as an
    anonymous caller. They do not bypass SQL analysis or parameterisation checks.
    """
    service_token = set_current_service(service)
    tenant_token: Token | None = None
    role_token: Token | None = None
    if tenant_id is not _UNSET:
        tenant_token = set_current_tenant_id(str(tenant_id or ""))
    if role is not _UNSET:
        role_token = set_current_role(str(role or ""))

    try:
        yield
    finally:
        if role_token is not None:
            reset_current_role(role_token)
        if tenant_token is not None:
            reset_current_tenant_id(tenant_token)
        reset_current_service(service_token)
