"""Make email notifications opt-in

Both notification preferences shipped defaulting to True (001_initial_schema),
so every new signup was subscribed to the daily digest and instant KEV alerts
without asking. That is unsolicited email to an address that has only just
proven it exists — the fastest way to get a sending domain flagged as spam, and
not what a user expects from a fresh account.

This flips the column defaults to false so new accounts start silent, and turns
the preferences off for existing accounts as well, so nobody keeps receiving
mail they never opted into. Users enable whichever they want from Settings,
which already reads and writes these columns.

The downgrade restores the old defaults but deliberately does NOT re-enable the
preferences for existing users — silently opting people back into email on a
rollback would be worse than leaving them off.

Revision ID: 008
Revises: 007
Create Date: 2026-07-22
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # New accounts start with email off.
    op.alter_column("users", "daily_digest", server_default=sa.text("false"))
    op.alter_column("users", "instant_alerts", server_default=sa.text("false"))

    # Existing accounts were subscribed without asking — unsubscribe them too.
    op.execute("UPDATE users SET daily_digest = false, instant_alerts = false")


def downgrade() -> None:
    op.alter_column("users", "daily_digest", server_default=sa.text("true"))
    op.alter_column("users", "instant_alerts", server_default=sa.text("true"))
    # Intentionally no data backfill — see module docstring.
