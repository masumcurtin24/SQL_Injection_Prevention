"""add_defender_feedback_and_registry

Revision ID: 9f3d2cbe7a4d
Revises: 41377bd0711c
Create Date: 2026-03-18 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9f3d2cbe7a4d"
down_revision: Union[str, None] = "41377bd0711c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "defender_feedback",
        sa.Column("id", sa.String(), nullable=False, comment="UUID string identifier."),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, comment="Feedback submission timestamp (UTC)."),
        sa.Column("domain", sa.String(), nullable=False, comment="Detection domain: sql|spam|file."),
        sa.Column("analysis_id", sa.String(), nullable=True, comment="Optional analysis ID associated with this feedback."),
        sa.Column("predicted_label", sa.String(), nullable=True, comment="Original model/system label before feedback."),
        sa.Column("true_label", sa.String(), nullable=False, comment="Human-validated ground-truth label."),
        sa.Column("confidence", sa.Float(), nullable=True, comment="Optional confidence value from original prediction (0..1)."),
        sa.Column("source", sa.String(), nullable=False, comment="Feedback source (human|system)."),
        sa.Column("notes", sa.Text(), nullable=True, comment="Optional analyst notes."),
        sa.Column("processed", sa.Boolean(), nullable=False, comment="Whether this sample has been consumed by retraining pipeline."),
        sa.Column("sample_payload", sa.Text(), nullable=False, comment="JSON payload used for labeling/training."),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_defender_feedback_id"), "defender_feedback", ["id"], unique=False)
    op.create_index(op.f("ix_defender_feedback_timestamp"), "defender_feedback", ["timestamp"], unique=False)
    op.create_index(op.f("ix_defender_feedback_domain"), "defender_feedback", ["domain"], unique=False)
    op.create_index(op.f("ix_defender_feedback_analysis_id"), "defender_feedback", ["analysis_id"], unique=False)
    op.create_index(op.f("ix_defender_feedback_predicted_label"), "defender_feedback", ["predicted_label"], unique=False)
    op.create_index(op.f("ix_defender_feedback_true_label"), "defender_feedback", ["true_label"], unique=False)
    op.create_index(op.f("ix_defender_feedback_source"), "defender_feedback", ["source"], unique=False)
    op.create_index(op.f("ix_defender_feedback_processed"), "defender_feedback", ["processed"], unique=False)

    op.create_table(
        "defender_model_registry",
        sa.Column("id", sa.String(), nullable=False, comment="UUID string identifier."),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, comment="Registry entry creation timestamp (UTC)."),
        sa.Column("domain", sa.String(), nullable=False, comment="Model domain: sql|spam|file."),
        sa.Column("model_name", sa.String(), nullable=False, comment="Model family/name."),
        sa.Column("version", sa.String(), nullable=False, comment="Model version identifier."),
        sa.Column("stage", sa.String(), nullable=False, comment="Lifecycle stage: candidate|active|retired."),
        sa.Column("artifact_path", sa.String(), nullable=False, comment="Filesystem path to model artifact."),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True, comment="Promotion timestamp when stage becomes active."),
        sa.Column("notes", sa.Text(), nullable=True, comment="Optional free-text notes."),
        sa.Column("metrics", sa.Text(), nullable=True, comment="JSON-serialized evaluation metrics."),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_defender_model_registry_id"), "defender_model_registry", ["id"], unique=False)
    op.create_index(op.f("ix_defender_model_registry_timestamp"), "defender_model_registry", ["timestamp"], unique=False)
    op.create_index(op.f("ix_defender_model_registry_domain"), "defender_model_registry", ["domain"], unique=False)
    op.create_index(op.f("ix_defender_model_registry_version"), "defender_model_registry", ["version"], unique=False)
    op.create_index(op.f("ix_defender_model_registry_stage"), "defender_model_registry", ["stage"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_defender_model_registry_stage"), table_name="defender_model_registry")
    op.drop_index(op.f("ix_defender_model_registry_version"), table_name="defender_model_registry")
    op.drop_index(op.f("ix_defender_model_registry_domain"), table_name="defender_model_registry")
    op.drop_index(op.f("ix_defender_model_registry_timestamp"), table_name="defender_model_registry")
    op.drop_index(op.f("ix_defender_model_registry_id"), table_name="defender_model_registry")
    op.drop_table("defender_model_registry")

    op.drop_index(op.f("ix_defender_feedback_processed"), table_name="defender_feedback")
    op.drop_index(op.f("ix_defender_feedback_source"), table_name="defender_feedback")
    op.drop_index(op.f("ix_defender_feedback_true_label"), table_name="defender_feedback")
    op.drop_index(op.f("ix_defender_feedback_predicted_label"), table_name="defender_feedback")
    op.drop_index(op.f("ix_defender_feedback_analysis_id"), table_name="defender_feedback")
    op.drop_index(op.f("ix_defender_feedback_domain"), table_name="defender_feedback")
    op.drop_index(op.f("ix_defender_feedback_timestamp"), table_name="defender_feedback")
    op.drop_index(op.f("ix_defender_feedback_id"), table_name="defender_feedback")
    op.drop_table("defender_feedback")
