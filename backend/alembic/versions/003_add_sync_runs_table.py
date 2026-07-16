"""Add sync_runs table

Revision ID: 003
Revises: 002
Create Date: 2026-04-06
"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sync_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_name", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="running"),
        sa.Column("trigger_source", sa.String(50), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_sync_runs_job_name_started", "sync_runs", ["job_name", "started_at"])
    op.create_index(
        "idx_sync_runs_job_name_status_finished",
        "sync_runs",
        ["job_name", "status", "finished_at"],
    )


def downgrade() -> None:
    op.drop_table("sync_runs")
