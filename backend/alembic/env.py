"""
Alembic env.py — tells Alembic how to connect to the DB and where to find models.

We use the SYNC URL here because Alembic runs as a CLI tool, not inside
an async event loop. The async engine is only for runtime (FastAPI).

autogenerate=True means Alembic compares your models to the actual DB schema
and generates the diff as a migration file. Run:
  alembic revision --autogenerate -m "describe your change"
  alembic upgrade head
"""
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# This import triggers all model imports through __init__.py,
# giving Alembic visibility of every table.
from app.models import *  # noqa: F401, F403
from app.database import Base
from app.config import settings

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# This is the MetaData object Alembic inspects to find all tables
target_metadata = Base.metadata


def get_url() -> str:
    # Use the sync URL for Alembic CLI operations
    return settings.SYNC_DATABASE_URL


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (generates SQL script)."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live DB connection."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # don't pool for migrations
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,       # detect column type changes
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
