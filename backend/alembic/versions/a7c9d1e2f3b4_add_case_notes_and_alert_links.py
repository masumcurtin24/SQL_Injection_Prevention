"""add_case_notes_and_alert_links

Revision ID: a7c9d1e2f3b4
Revises: e1a2b3c4d5e6
Create Date: 2026-04-02 15:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a7c9d1e2f3b4"
down_revision: Union[str, None] = "e1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


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


def _ensure_index(inspector: sa.Inspector, table_name: str, index_name: str, columns: list[str], *, unique: bool = False) -> None:
    if not _index_exists(inspector, table_name, index_name):
        op.create_index(index_name, table_name, columns, unique=unique)


def _ensure_security_case_notes(inspector: sa.Inspector) -> None:
    if not _table_exists(inspector, "security_case_notes"):
        op.create_table(
            "security_case_notes",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("case_id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("author_user_id", sa.String(), nullable=False),
            sa.Column("note", sa.Text(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
    else:
        with op.batch_alter_table("security_case_notes") as batch_op:
            if not _column_exists(inspector, "security_case_notes", "id"):
                batch_op.add_column(sa.Column("id", sa.String(), nullable=False))
            if not _column_exists(inspector, "security_case_notes", "case_id"):
                batch_op.add_column(sa.Column("case_id", sa.String(), nullable=False))
            if not _column_exists(inspector, "security_case_notes", "created_at"):
                batch_op.add_column(sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
            if not _column_exists(inspector, "security_case_notes", "author_user_id"):
                batch_op.add_column(sa.Column("author_user_id", sa.String(), nullable=False))
            if not _column_exists(inspector, "security_case_notes", "note"):
                batch_op.add_column(sa.Column("note", sa.Text(), nullable=False))
    inspector = sa.inspect(op.get_bind())
    _ensure_index(inspector, "security_case_notes", op.f("ix_security_case_notes_id"), ["id"], unique=False)
    _ensure_index(inspector, "security_case_notes", op.f("ix_security_case_notes_case_id"), ["case_id"], unique=False)
    _ensure_index(inspector, "security_case_notes", op.f("ix_security_case_notes_created_at"), ["created_at"], unique=False)
    _ensure_index(inspector, "security_case_notes", op.f("ix_security_case_notes_author_user_id"), ["author_user_id"], unique=False)


def _ensure_alert_case_links(inspector: sa.Inspector) -> None:
    if not _table_exists(inspector, "alert_case_links"):
        op.create_table(
            "alert_case_links",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("case_id", sa.String(), nullable=False),
            sa.Column("alert_id", sa.String(), nullable=False),
            sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("linked_by_user_id", sa.String(), nullable=False),
            sa.Column("note", sa.Text(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("case_id", "alert_id", name="uq_alert_case_links_case_alert"),
        )
    else:
        with op.batch_alter_table("alert_case_links") as batch_op:
            if not _column_exists(inspector, "alert_case_links", "id"):
                batch_op.add_column(sa.Column("id", sa.String(), nullable=False))
            if not _column_exists(inspector, "alert_case_links", "case_id"):
                batch_op.add_column(sa.Column("case_id", sa.String(), nullable=False))
            if not _column_exists(inspector, "alert_case_links", "alert_id"):
                batch_op.add_column(sa.Column("alert_id", sa.String(), nullable=False))
            if not _column_exists(inspector, "alert_case_links", "linked_at"):
                batch_op.add_column(sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False))
            if not _column_exists(inspector, "alert_case_links", "linked_by_user_id"):
                batch_op.add_column(sa.Column("linked_by_user_id", sa.String(), nullable=False))
            if not _column_exists(inspector, "alert_case_links", "note"):
                batch_op.add_column(sa.Column("note", sa.Text(), nullable=True))
    inspector = sa.inspect(op.get_bind())
    _ensure_index(inspector, "alert_case_links", op.f("ix_alert_case_links_id"), ["id"], unique=False)
    _ensure_index(inspector, "alert_case_links", op.f("ix_alert_case_links_case_id"), ["case_id"], unique=False)
    _ensure_index(inspector, "alert_case_links", op.f("ix_alert_case_links_alert_id"), ["alert_id"], unique=False)
    _ensure_index(inspector, "alert_case_links", op.f("ix_alert_case_links_linked_at"), ["linked_at"], unique=False)
    _ensure_index(inspector, "alert_case_links", op.f("ix_alert_case_links_linked_by_user_id"), ["linked_by_user_id"], unique=False)


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    _ensure_security_case_notes(inspector)
    inspector = sa.inspect(op.get_bind())
    _ensure_alert_case_links(inspector)


def downgrade() -> None:
    op.drop_index(op.f("ix_alert_case_links_linked_by_user_id"), table_name="alert_case_links")
    op.drop_index(op.f("ix_alert_case_links_linked_at"), table_name="alert_case_links")
    op.drop_index(op.f("ix_alert_case_links_alert_id"), table_name="alert_case_links")
    op.drop_index(op.f("ix_alert_case_links_case_id"), table_name="alert_case_links")
    op.drop_index(op.f("ix_alert_case_links_id"), table_name="alert_case_links")
    op.drop_table("alert_case_links")

    op.drop_index(op.f("ix_security_case_notes_author_user_id"), table_name="security_case_notes")
    op.drop_index(op.f("ix_security_case_notes_created_at"), table_name="security_case_notes")
    op.drop_index(op.f("ix_security_case_notes_case_id"), table_name="security_case_notes")
    op.drop_index(op.f("ix_security_case_notes_id"), table_name="security_case_notes")
    op.drop_table("security_case_notes")
