"""create_alerts_table

Revision ID: 4bf7a6b6f313
Revises: 
Create Date: 2025-05-17 11:27:58.019863

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4bf7a6b6f313'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### Alembic migration commands - please adjust if needed. ###
    op.create_table('alerts',
    sa.Column('id', sa.String(), nullable=False, comment='Unique identifier for the alert (e.g., UUID).'),
    sa.Column('timestamp', sa.DateTime(), nullable=True, comment='Timestamp of when the alert was created (UTC).'),
    sa.Column('severity', sa.String(), nullable=False, comment="Severity level (e.g., 'Critical', 'High', 'Medium', 'Low', 'Info')."),
    sa.Column('title', sa.String(), nullable=False, comment='A concise title for the alert.'),
    sa.Column('message', sa.Text(), nullable=False, comment='A detailed message describing the alert.'),
    sa.Column('source_ip', sa.String(), nullable=True, comment='Source IP address related to the alert, if applicable.'),
    sa.Column('target', sa.String(), nullable=True, comment='Target system or component related to the alert, if applicable.'),
    sa.Column('query', sa.Text(), nullable=True, comment='Associated SQL query, if applicable.'),
    sa.Column('acknowledged', sa.Boolean(), nullable=False, comment='Whether the alert has been acknowledged by an admin.'),
    sa.Column('tags', sa.Text(), nullable=True, comment='JSON string representation of a list of tags.'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_acknowledged'), 'alerts', ['acknowledged'], unique=False)
    op.create_index(op.f('ix_alerts_id'), 'alerts', ['id'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_source_ip'), 'alerts', ['source_ip'], unique=False)
    op.create_index(op.f('ix_alerts_timestamp'), 'alerts', ['timestamp'], unique=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### Alembic migration commands - please adjust if needed. ###
    op.drop_index(op.f('ix_alerts_timestamp'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_source_ip'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_severity'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_acknowledged'), table_name='alerts')
    op.drop_table('alerts')
    # ### end Alembic commands ###
