"""add_defender_training_jobs

Revision ID: b2f4d9c0e6a1
Revises: 9f3d2cbe7a4d
Create Date: 2026-03-25 16:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b2f4d9c0e6a1"
down_revision: Union[str, None] = "9f3d2cbe7a4d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "defender_training_jobs",
        sa.Column("id", sa.String(), nullable=False, comment="UUID string identifier."),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, comment="Job creation timestamp (UTC)."),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True, comment="Job execution start timestamp (UTC)."),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True, comment="Job completion timestamp (UTC)."),
        sa.Column("status", sa.String(), nullable=False, comment="Job lifecycle status: queued|running|succeeded|failed."),
        sa.Column("domain", sa.String(), nullable=False, comment="Target domain: sql|spam|file|all."),
        sa.Column("requested_by", sa.String(), nullable=True, comment="User id that triggered the job."),
        sa.Column("min_feedback_samples", sa.Integer(), nullable=False, comment="Minimum feedback samples required per domain."),
        sa.Column("promote_if_better", sa.Boolean(), nullable=False, comment="Whether auto-promotion gate should run after training."),
        sa.Column("notes", sa.Text(), nullable=True, comment="Operator notes for this run."),
        sa.Column("result", sa.Text(), nullable=True, comment="JSON serialized training result payload."),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_defender_training_jobs_id"), "defender_training_jobs", ["id"], unique=False)
    op.create_index(op.f("ix_defender_training_jobs_timestamp"), "defender_training_jobs", ["timestamp"], unique=False)
    op.create_index(op.f("ix_defender_training_jobs_status"), "defender_training_jobs", ["status"], unique=False)
    op.create_index(op.f("ix_defender_training_jobs_domain"), "defender_training_jobs", ["domain"], unique=False)
    op.create_index(op.f("ix_defender_training_jobs_requested_by"), "defender_training_jobs", ["requested_by"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_defender_training_jobs_requested_by"), table_name="defender_training_jobs")
    op.drop_index(op.f("ix_defender_training_jobs_domain"), table_name="defender_training_jobs")
    op.drop_index(op.f("ix_defender_training_jobs_status"), table_name="defender_training_jobs")
    op.drop_index(op.f("ix_defender_training_jobs_timestamp"), table_name="defender_training_jobs")
    op.drop_index(op.f("ix_defender_training_jobs_id"), table_name="defender_training_jobs")
    op.drop_table("defender_training_jobs")
