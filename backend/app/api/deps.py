"""
deps.py — FastAPI dependency functions.

Dependencies are injected into route handlers via Depends().
This keeps auth logic out of the route handlers themselves.

Usage:
    @router.get("/stack")
    async def get_stack(
        current_user: User = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db),
    ):
"""
from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.services.auth import get_current_user


async def get_current_user_dep(
    session_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Require an authenticated user. Raises 401 if not logged in."""
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    user = await get_current_user(db, session_token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")

    return user
