"""Add NVD match context columns to cve_affected_products

Revision ID: 004
Revises: 003
Create Date: 2026-04-06
"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "cve_affected_products",
        sa.Column("condition_group", sa.String(100), nullable=True),
    )
    op.add_column(
        "cve_affected_products",
        sa.Column("config_path", sa.Text(), nullable=True),
    )
    op.add_column(
        "cve_affected_products",
        sa.Column("is_vulnerable_match", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column(
        "cve_affected_products",
        sa.Column("match_context", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("cve_affected_products", "match_context")
    op.drop_column("cve_affected_products", "is_vulnerable_match")
    op.drop_column("cve_affected_products", "config_path")
    op.drop_column("cve_affected_products", "condition_group")
