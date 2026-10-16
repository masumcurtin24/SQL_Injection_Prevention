"""add_security_cases_table

Revision ID: f7b1e2c3d4a5
Revises: d4e9c7a1b2f6
Create Date: 2026-04-01 07:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f7b1e2c3d4a5"
down_revision: Union[str, None] = "d4e9c7a1b2f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_cases",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="new"),
        sa.Column("severity", sa.String(), nullable=False, server_default="Medium"),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("source_type", sa.String(), nullable=True),
        sa.Column("source_id", sa.String(), nullable=True),
        sa.Column("owner_user_id", sa.String(), nullable=True),
        sa.Column("created_by_user_id", sa.String(), nullable=False),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("timeline", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_security_cases_id"), "security_cases", ["id"], unique=False)
    op.create_index(op.f("ix_security_cases_created_at"), "security_cases", ["created_at"], unique=False)
    op.create_index(op.f("ix_security_cases_updated_at"), "security_cases", ["updated_at"], unique=False)
    op.create_index(op.f("ix_security_cases_status"), "security_cases", ["status"], unique=False)
    op.create_index(op.f("ix_security_cases_severity"), "security_cases", ["severity"], unique=False)
    op.create_index(op.f("ix_security_cases_domain"), "security_cases", ["domain"], unique=False)
    op.create_index(op.f("ix_security_cases_source_type"), "security_cases", ["source_type"], unique=False)
    op.create_index(op.f("ix_security_cases_source_id"), "security_cases", ["source_id"], unique=False)
    op.create_index(op.f("ix_security_cases_owner_user_id"), "security_cases", ["owner_user_id"], unique=False)
    op.create_index(op.f("ix_security_cases_created_by_user_id"), "security_cases", ["created_by_user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_security_cases_created_by_user_id"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_owner_user_id"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_source_id"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_source_type"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_domain"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_severity"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_status"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_updated_at"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_created_at"), table_name="security_cases")
    op.drop_index(op.f("ix_security_cases_id"), table_name="security_cases")
    op.drop_table("security_cases")
