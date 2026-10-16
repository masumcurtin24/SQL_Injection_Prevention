"""add_denormalized_dashboard_fields

Revision ID: c8d5f0a1e2b3
Revises: b2f4d9c0e6a1
Create Date: 2026-03-28 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c8d5f0a1e2b3"
down_revision: Union[str, None] = "b2f4d9c0e6a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQL logs denormalized fields
    op.add_column("sql_analysis_logs", sa.Column("risk_level", sa.String(), nullable=True, comment="Denormalized overall risk level."))
    op.add_column("sql_analysis_logs", sa.Column("suggested_action", sa.String(), nullable=True, comment="Denormalized suggested action."))
    op.add_column("sql_analysis_logs", sa.Column("category", sa.String(), nullable=True, comment="Dashboard category safe|suspicious|blocked."))
    op.add_column("sql_analysis_logs", sa.Column("is_malicious", sa.Boolean(), nullable=True, comment="Denormalized malicious indicator."))
    op.create_index("ix_sql_analysis_logs_risk_level", "sql_analysis_logs", ["risk_level"], unique=False)
    op.create_index("ix_sql_analysis_logs_suggested_action", "sql_analysis_logs", ["suggested_action"], unique=False)
    op.create_index("ix_sql_analysis_logs_category", "sql_analysis_logs", ["category"], unique=False)
    op.create_index("ix_sql_analysis_logs_is_malicious", "sql_analysis_logs", ["is_malicious"], unique=False)
    op.create_index("ix_sql_analysis_logs_timestamp_category", "sql_analysis_logs", ["timestamp", "category"], unique=False)

    # File logs denormalized fields
    op.add_column("file_analysis_logs", sa.Column("overall_status", sa.String(), nullable=True, comment="Denormalized overall status."))
    op.add_column("file_analysis_logs", sa.Column("recommended_action", sa.String(), nullable=True, comment="Denormalized recommended action."))
    op.add_column("file_analysis_logs", sa.Column("risk_score_value", sa.Float(), nullable=True, comment="Denormalized risk score."))
    op.add_column("file_analysis_logs", sa.Column("category", sa.String(), nullable=True, comment="Dashboard category safe|suspicious|blocked."))
    op.create_index("ix_file_analysis_logs_overall_status", "file_analysis_logs", ["overall_status"], unique=False)
    op.create_index("ix_file_analysis_logs_recommended_action", "file_analysis_logs", ["recommended_action"], unique=False)
    op.create_index("ix_file_analysis_logs_risk_score_value", "file_analysis_logs", ["risk_score_value"], unique=False)
    op.create_index("ix_file_analysis_logs_category", "file_analysis_logs", ["category"], unique=False)
    op.create_index("ix_file_analysis_logs_timestamp_category", "file_analysis_logs", ["timestamp", "category"], unique=False)

    # Spam logs denormalized fields
    op.add_column("spam_analysis_logs", sa.Column("is_spam", sa.Boolean(), nullable=True, comment="Denormalized spam indicator."))
    op.add_column("spam_analysis_logs", sa.Column("spam_score", sa.Float(), nullable=True, comment="Denormalized spam score."))
    op.add_column("spam_analysis_logs", sa.Column("classification_label", sa.String(), nullable=True, comment="Denormalized classification label."))
    op.add_column("spam_analysis_logs", sa.Column("category", sa.String(), nullable=True, comment="Dashboard category safe|suspicious|blocked."))
    op.create_index("ix_spam_analysis_logs_is_spam", "spam_analysis_logs", ["is_spam"], unique=False)
    op.create_index("ix_spam_analysis_logs_spam_score", "spam_analysis_logs", ["spam_score"], unique=False)
    op.create_index("ix_spam_analysis_logs_classification_label", "spam_analysis_logs", ["classification_label"], unique=False)
    op.create_index("ix_spam_analysis_logs_category", "spam_analysis_logs", ["category"], unique=False)
    op.create_index("ix_spam_analysis_logs_timestamp_category", "spam_analysis_logs", ["timestamp", "category"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_spam_analysis_logs_timestamp_category", table_name="spam_analysis_logs")
    op.drop_index("ix_spam_analysis_logs_category", table_name="spam_analysis_logs")
    op.drop_index("ix_spam_analysis_logs_classification_label", table_name="spam_analysis_logs")
    op.drop_index("ix_spam_analysis_logs_spam_score", table_name="spam_analysis_logs")
    op.drop_index("ix_spam_analysis_logs_is_spam", table_name="spam_analysis_logs")
    op.drop_column("spam_analysis_logs", "category")
    op.drop_column("spam_analysis_logs", "classification_label")
    op.drop_column("spam_analysis_logs", "spam_score")
    op.drop_column("spam_analysis_logs", "is_spam")

    op.drop_index("ix_file_analysis_logs_timestamp_category", table_name="file_analysis_logs")
    op.drop_index("ix_file_analysis_logs_category", table_name="file_analysis_logs")
    op.drop_index("ix_file_analysis_logs_risk_score_value", table_name="file_analysis_logs")
    op.drop_index("ix_file_analysis_logs_recommended_action", table_name="file_analysis_logs")
    op.drop_index("ix_file_analysis_logs_overall_status", table_name="file_analysis_logs")
    op.drop_column("file_analysis_logs", "category")
    op.drop_column("file_analysis_logs", "risk_score_value")
    op.drop_column("file_analysis_logs", "recommended_action")
    op.drop_column("file_analysis_logs", "overall_status")

    op.drop_index("ix_sql_analysis_logs_timestamp_category", table_name="sql_analysis_logs")
    op.drop_index("ix_sql_analysis_logs_is_malicious", table_name="sql_analysis_logs")
    op.drop_index("ix_sql_analysis_logs_category", table_name="sql_analysis_logs")
    op.drop_index("ix_sql_analysis_logs_suggested_action", table_name="sql_analysis_logs")
    op.drop_index("ix_sql_analysis_logs_risk_level", table_name="sql_analysis_logs")
    op.drop_column("sql_analysis_logs", "is_malicious")
    op.drop_column("sql_analysis_logs", "category")
    op.drop_column("sql_analysis_logs", "suggested_action")
    op.drop_column("sql_analysis_logs", "risk_level")
