"""Add notification idempotency and attempt metadata

Revision ID: 005
Revises: 004
Create Date: 2026-04-06
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "notifications",
        sa.Column("idempotency_key", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "notifications",
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "notifications",
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    op.add_column(
        "notifications",
        sa.Column("delivery_result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    op.execute("UPDATE notifications SET attempted_at = sent_at")
    op.execute("UPDATE notifications SET idempotency_key = 'legacy:' || id::text")

    op.alter_column("notifications", "attempted_at", nullable=False)
    op.alter_column("notifications", "idempotency_key", nullable=False)
    op.alter_column(
        "notifications",
        "sent_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
    )
    op.create_index(
        "ix_notifications_idempotency_key",
        "notifications",
        ["idempotency_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_notifications_idempotency_key", table_name="notifications")
    op.alter_column(
        "notifications",
        "sent_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )
    op.drop_column("notifications", "delivery_result")
    op.drop_column("notifications", "error_message")
    op.drop_column("notifications", "attempted_at")
    op.drop_column("notifications", "idempotency_key")
