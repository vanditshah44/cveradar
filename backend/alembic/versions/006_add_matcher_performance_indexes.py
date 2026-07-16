"""Add matcher performance indexes

Revision ID: 006
Revises: 005
Create Date: 2026-04-06
"""
from typing import Sequence, Union

from alembic import op

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "idx_stack_items_vendor_product_user",
        "stack_items",
        ["vendor", "cpe_product", "user_id"],
        unique=False,
    )
    op.create_index(
        "idx_cve_affected_vendor_product_cve",
        "cve_affected_products",
        ["vendor", "product", "cve_id"],
        unique=False,
    )
    op.create_index(
        "idx_cve_affected_cve_group",
        "cve_affected_products",
        ["cve_id", "condition_group"],
        unique=False,
    )
    op.create_index(
        "idx_user_cve_matches_user_cve",
        "user_cve_matches",
        ["user_id", "cve_id"],
        unique=False,
    )
    op.create_index(
        "idx_user_cve_matches_cve_stack_item",
        "user_cve_matches",
        ["cve_id", "stack_item_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("idx_user_cve_matches_cve_stack_item", table_name="user_cve_matches")
    op.drop_index("idx_user_cve_matches_user_cve", table_name="user_cve_matches")
    op.drop_index("idx_cve_affected_cve_group", table_name="cve_affected_products")
    op.drop_index("idx_cve_affected_vendor_product_cve", table_name="cve_affected_products")
    op.drop_index("idx_stack_items_vendor_product_user", table_name="stack_items")
