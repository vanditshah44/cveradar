"""
database.py — SQLAlchemy engine + session setup.

Two session factories:
  AsyncSessionLocal  → used in FastAPI route handlers (async/await)
  SyncSessionLocal   → used in Celery tasks (sync, no event loop)

Both point to the same PostgreSQL database, just different drivers.
The Base class is shared — all models inherit from it.
"""
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import create_engine

from app.config import settings


class Base(DeclarativeBase):
    """All ORM models inherit from this. Alembic uses it to detect schema changes."""
    pass


# ── Async (FastAPI) ───────────────────────────────────────────────────────────
# expire_on_commit=False: after a commit, don't expire ORM objects — lets us
# still access attributes in the response without triggering a new DB query.
async_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,  # log SQL in debug mode
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_recycle=settings.DB_POOL_RECYCLE,  # replace connections a shared host may have silently killed
    pool_timeout=settings.DB_POOL_TIMEOUT,  # fail fast instead of hanging when the pool is saturated
    pool_pre_ping=True,  # drop stale connections immediately rather than hanging
)
AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncSession:
    """FastAPI dependency. Injects a DB session into route handlers.

    Usage in a route:
        async def my_route(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(User))
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Sync (Celery) ─────────────────────────────────────────────────────────────
# Celery tasks run in a regular thread pool, not an async event loop.
# Using sync SQLAlchemy here avoids the complexity of running asyncio inside Celery.
sync_engine = create_engine(
    settings.SYNC_DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=settings.DB_SYNC_POOL_SIZE,
    max_overflow=settings.DB_SYNC_MAX_OVERFLOW,
    pool_recycle=settings.DB_POOL_RECYCLE,  # avoid "server closed the connection" on idle workers
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_pre_ping=True,  # test connection before using it from pool
)
SyncSessionLocal = sessionmaker(bind=sync_engine, expire_on_commit=False)
