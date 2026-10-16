"""add_user_full_name

Revision ID: e1a2b3c4d5e6
Revises: f7b1e2c3d4a5
Create Date: 2026-04-02 12:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "e1a2b3c4d5e6"
down_revision: Union[str, None] = "f7b1e2c3d4a5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("full_name", sa.String(), nullable=True, comment="User display full name."))


def downgrade() -> None:
    op.drop_column("users", "full_name")

