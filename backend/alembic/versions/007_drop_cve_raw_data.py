"""Drop cves.raw_data to reclaim storage

The full NVD JSON blob was stored per-CVE in cves.raw_data (JSONB). Across the
NVD corpus this was the dominant on-disk cost and overran the free-tier database.
Nothing reads it — everything needed is flattened into typed columns during
ingestion — so it is dropped here. It can always be re-fetched from NVD.

After running this migration, reclaim the freed pages on PostgreSQL with:
    VACUUM FULL cves;
(VACUUM FULL takes an exclusive lock and rewrites the table; run it in a
maintenance window. A plain autovacuum will reclaim space more slowly without
returning it to the OS.)

Revision ID: 007
Revises: 006
Create Date: 2026-07-14
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("cves", "raw_data")


def downgrade() -> None:
    op.add_column("cves", sa.Column("raw_data", JSONB(), nullable=True))
