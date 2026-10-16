"""add_multi_tenant_foundation

Revision ID: b8d2f3a4c5d6
Revises: a7c9d1e2f3b4
Create Date: 2026-04-02 23:10:00.000000

"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b8d2f3a4c5d6"
down_revision: Union[str, None] = "a7c9d1e2f3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


DEFAULT_TENANT_ID = "tenant-primary"
DEFAULT_TENANT_SLUG = "primary"
DEFAULT_TENANT_NAME = "Primary Tenant"

_TENANT_SCOPED_TABLES: list[tuple[str, str]] = [
    ("alerts", "ix_alerts_tenant_id"),
    ("sql_analysis_logs", "ix_sql_analysis_logs_tenant_id"),
    ("spam_analysis_logs", "ix_spam_analysis_logs_tenant_id"),
    ("file_analysis_logs", "ix_file_analysis_logs_tenant_id"),
    ("auth_sessions", "ix_auth_sessions_tenant_id"),
    ("audit_logs", "ix_audit_logs_tenant_id"),
    ("security_cases", "ix_security_cases_tenant_id"),
    ("security_case_notes", "ix_security_case_notes_tenant_id"),
    ("alert_case_links", "ix_alert_case_links_tenant_id"),
    ("defender_feedback", "ix_defender_feedback_tenant_id"),
    ("defender_model_registry", "ix_defender_model_registry_tenant_id"),
    ("defender_training_jobs", "ix_defender_training_jobs_tenant_id"),
]


def _table_exists(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _column_exists(inspector: sa.Inspector, table_name: str, column_name: str) -> bool:
    if not _table_exists(inspector, table_name):
        return False
    return any(col.get("name") == column_name for col in inspector.get_columns(table_name))


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    if not _table_exists(inspector, table_name):
        return False
    return any(idx.get("name") == index_name for idx in inspector.get_indexes(table_name))


def _ensure_default_tenant_row(bind: sa.Connection) -> None:
    existing = bind.execute(
        sa.text("SELECT id FROM tenants WHERE id = :tenant_id"),
        {"tenant_id": DEFAULT_TENANT_ID},
    ).fetchone()
    if existing is not None:
        return
    bind.execute(
        sa.text(
            "INSERT INTO tenants (id, slug, name, is_active, created_at) "
            "VALUES (:id, :slug, :name, :is_active, :created_at)"
        ),
        {
            "id": DEFAULT_TENANT_ID,
            "slug": DEFAULT_TENANT_SLUG,
            "name": DEFAULT_TENANT_NAME,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        },
    )


def _add_tenant_column_if_missing(table_name: str, index_name: str) -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not _table_exists(inspector, table_name):
        return

    if not _column_exists(inspector, table_name, "tenant_id"):
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.add_column(
                sa.Column(
                    "tenant_id",
                    sa.String(),
                    nullable=True,
                    server_default=DEFAULT_TENANT_ID,
                )
            )

    bind.execute(
        sa.text(
            f"UPDATE {table_name} "
            "SET tenant_id = :tenant_id "
            "WHERE tenant_id IS NULL OR tenant_id = ''"
        ),
        {"tenant_id": DEFAULT_TENANT_ID},
    )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, table_name, index_name):
        op.create_index(index_name, table_name, ["tenant_id"], unique=False)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _table_exists(inspector, "tenants"):
        op.create_table(
            "tenants",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("slug", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("slug", name="uq_tenants_slug"),
        )
        op.create_index(op.f("ix_tenants_id"), "tenants", ["id"], unique=False)
        op.create_index(op.f("ix_tenants_slug"), "tenants", ["slug"], unique=False)
        op.create_index(op.f("ix_tenants_is_active"), "tenants", ["is_active"], unique=False)

    _ensure_default_tenant_row(bind)

    # Users are always tenant-bound.
    if _table_exists(inspector, "users"):
        if not _column_exists(inspector, "users", "tenant_id"):
            with op.batch_alter_table("users") as batch_op:
                batch_op.add_column(
                    sa.Column(
                        "tenant_id",
                        sa.String(),
                        nullable=True,
                        server_default=DEFAULT_TENANT_ID,
                    )
                )
        bind.execute(
            sa.text(
                "UPDATE users SET tenant_id = :tenant_id "
                "WHERE tenant_id IS NULL OR tenant_id = ''"
            ),
            {"tenant_id": DEFAULT_TENANT_ID},
        )
        inspector = sa.inspect(bind)
        if not _index_exists(inspector, "users", "ix_users_tenant_id"):
            op.create_index("ix_users_tenant_id", "users", ["tenant_id"], unique=False)

    for table_name, index_name in _TENANT_SCOPED_TABLES:
        _add_tenant_column_if_missing(table_name, index_name)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for table_name, index_name in reversed(_TENANT_SCOPED_TABLES):
        if not _table_exists(inspector, table_name):
            continue
        if _index_exists(inspector, table_name, index_name):
            op.drop_index(index_name, table_name=table_name)
        if _column_exists(inspector, table_name, "tenant_id"):
            with op.batch_alter_table(table_name) as batch_op:
                batch_op.drop_column("tenant_id")
        inspector = sa.inspect(bind)

    if _table_exists(inspector, "users"):
        if _index_exists(inspector, "users", "ix_users_tenant_id"):
            op.drop_index("ix_users_tenant_id", table_name="users")
        if _column_exists(inspector, "users", "tenant_id"):
            with op.batch_alter_table("users") as batch_op:
                batch_op.drop_column("tenant_id")
        inspector = sa.inspect(bind)

    if _table_exists(inspector, "tenants"):
        for idx_name in ["ix_tenants_is_active", "ix_tenants_slug", "ix_tenants_id"]:
            if _index_exists(inspector, "tenants", idx_name):
                op.drop_index(idx_name, table_name="tenants")
        op.drop_table("tenants")
