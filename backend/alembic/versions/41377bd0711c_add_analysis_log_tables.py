"""add_analysis_log_tables

Revision ID: 41377bd0711c
Revises: 4bf7a6b6f313
Create Date: 2025-05-17 20:41:51.317551

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '41377bd0711c'
down_revision: Union[str, None] = '4bf7a6b6f313'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### Alembic migration commands - please adjust if needed. ###
    op.create_table('file_analysis_logs',
    sa.Column('id', sa.String(), nullable=False, comment='Corresponds to analysis_id from FileAnalysisResponse.'),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True, comment='Timestamp of the analysis (UTC).'),
    sa.Column('filename', sa.String(), nullable=False, comment='Name of the analyzed file.'),
    sa.Column('filesize_kb', sa.Float(), nullable=False, comment='Size of the file in kilobytes.'),
    sa.Column('file_details', sa.Text(), nullable=False, comment='JSON of FileAnalysisDetails (excluding filename & size as they are separate columns).'),
    sa.Column('overall_assessment', sa.Text(), nullable=False, comment='JSON of FileAnalysisOverallAssessment.'),
    sa.Column('errors', sa.Text(), nullable=True, comment='JSON list of error strings encountered.'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_file_analysis_logs_id'), 'file_analysis_logs', ['id'], unique=False)
    op.create_index(op.f('ix_file_analysis_logs_timestamp'), 'file_analysis_logs', ['timestamp'], unique=False)
    op.create_table('spam_analysis_logs',
    sa.Column('id', sa.String(), nullable=False, comment='Corresponds to analysis_id from EmailAnalysisResponse.'),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True, comment='Timestamp of the analysis (UTC).'),
    sa.Column('received_subject', sa.String(), nullable=True, comment='Subject of the analyzed email.'),
    sa.Column('spam_classification_result', sa.Text(), nullable=False, comment='JSON of SpamClassificationResult.'),
    sa.Column('errors', sa.Text(), nullable=True, comment='JSON list of error strings encountered.'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_spam_analysis_logs_id'), 'spam_analysis_logs', ['id'], unique=False)
    op.create_index(op.f('ix_spam_analysis_logs_timestamp'), 'spam_analysis_logs', ['timestamp'], unique=False)
    op.create_table('sql_analysis_logs',
    sa.Column('id', sa.String(), nullable=False, comment='Corresponds to analysis_id from AnalysisResponse.'),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True, comment='Timestamp of the analysis (UTC).'),
    sa.Column('query_received', sa.Text(), nullable=False, comment='The SQL query that was analyzed.'),
    sa.Column('anomaly_detection_result', sa.Text(), nullable=False, comment='JSON of AnomalyDetectionResult.'),
    sa.Column('query_validation_result', sa.Text(), nullable=True, comment='JSON of QueryValidationResult.'),
    sa.Column('combined_assessment', sa.Text(), nullable=True, comment='JSON of CombinedRiskAssessment.'),
    sa.Column('errors', sa.Text(), nullable=True, comment='JSON list of error strings encountered during analysis.'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sql_analysis_logs_id'), 'sql_analysis_logs', ['id'], unique=False)
    op.create_index(op.f('ix_sql_analysis_logs_timestamp'), 'sql_analysis_logs', ['timestamp'], unique=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### Alembic migration commands - please adjust if needed. ###
    op.drop_index(op.f('ix_sql_analysis_logs_timestamp'), table_name='sql_analysis_logs')
    op.drop_index(op.f('ix_sql_analysis_logs_id'), table_name='sql_analysis_logs')
    op.drop_table('sql_analysis_logs')
    op.drop_index(op.f('ix_spam_analysis_logs_timestamp'), table_name='spam_analysis_logs')
    op.drop_index(op.f('ix_spam_analysis_logs_id'), table_name='spam_analysis_logs')
    op.drop_table('spam_analysis_logs')
    op.drop_index(op.f('ix_file_analysis_logs_timestamp'), table_name='file_analysis_logs')
    op.drop_index(op.f('ix_file_analysis_logs_id'), table_name='file_analysis_logs')
    op.drop_table('file_analysis_logs')
    # ### end Alembic commands ###
