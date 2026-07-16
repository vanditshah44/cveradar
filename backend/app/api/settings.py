"""
settings.py — User notification preference endpoints.

GET    /api/settings  → get preferences
PUT    /api/settings  → update preferences
DELETE /api/account   → delete account and all data
"""
import logging

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user_dep
from app.database import get_db
from app.models.user import User
from app.schemas.settings import NotificationSettings
from app.services.structured_logging import log_structured_event

router = APIRouter(tags=["settings"])
logger = logging.getLogger(__name__)


@router.get("/api/settings", response_model=NotificationSettings)
async def get_settings(current_user: User = Depends(get_current_user_dep)):
    return NotificationSettings(
        daily_digest=current_user.daily_digest,
        instant_alerts=current_user.instant_alerts,
    )


@router.put("/api/settings", response_model=NotificationSettings)
async def update_settings(
    body: NotificationSettings,
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    current_user.daily_digest = body.daily_digest
    current_user.instant_alerts = body.instant_alerts
    await db.flush()
    log_structured_event(
        logger,
        logging.INFO,
        "settings_updated",
        user_id=current_user.id,
        daily_digest=current_user.daily_digest,
        instant_alerts=current_user.instant_alerts,
    )
    return NotificationSettings(
        daily_digest=current_user.daily_digest,
        instant_alerts=current_user.instant_alerts,
    )


@router.delete("/api/account", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    response: Response,
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    """Delete account and all associated data. Cascades to all related tables."""
    await db.delete(current_user)
    await db.flush()
    log_structured_event(
        logger,
        logging.INFO,
        "account_deleted",
        user_id=current_user.id,
        email=current_user.email,
    )
    response.delete_cookie("session_token")
