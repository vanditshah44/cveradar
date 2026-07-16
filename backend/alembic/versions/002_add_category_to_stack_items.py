"""Add category column to stack_items

Revision ID: 002
Revises: 001
Create Date: 2026-04-06
"""
from alembic import op
import sqlalchemy as sa

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable — existing rows will have NULL, which is fine.
    # The frontend just won't show a category badge for items added before this migration.
    op.add_column(
        'stack_items',
        sa.Column('category', sa.String(100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('stack_items', 'category')
