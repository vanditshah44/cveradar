"""
auth.py — Authentication endpoints.

POST /api/auth/magic-link  → send magic link to email
GET  /api/auth/verify      → verify token, set session cookie, redirect to dashboard
POST /api/auth/logout      → clear session cookie
GET  /api/auth/me          → get current user info
"""
import hashlib
import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from redis import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user_dep
from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import MagicLinkRequest, UserOut
from app.services.auth import (
    create_session_token,
    get_or_create_user,
    send_magic_link,
    verify_magic_link_token,
)

logger = logging.getLogger(__name__)


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, preferring X-Forwarded-For set by the proxy.

    Validates the extracted IP to prevent spoofed headers from bypassing rate limits.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        raw = forwarded.split(",")[0].strip()
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            pass  # malformed header — fall through to direct client IP
    return request.client.host if request.client else "unknown"


def _check_magic_link_rate_limit(ip: str) -> bool:
    """Allow at most 5 magic-link requests per IP per hour. Returns True if allowed."""
    key = f"rate_limit:magic_link:{hashlib.sha256(ip.encode()).hexdigest()[:16]}"
    client = None
    try:
        client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, 3600)
        count, _ = pipe.execute()
        return int(count) <= 5
    except Exception:
        logger.error("Redis unavailable — denying magic-link request to protect rate limit")
        return False  # fail closed — deny rather than allow unlimited requests
    finally:
        if client is not None:
            client.close()

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/magic-link", status_code=status.HTTP_200_OK)
async def request_magic_link(body: MagicLinkRequest, request: Request):
    """Send a magic link to the provided email address.

    In dev (no RESEND_API_KEY set), returns the link directly in the response
    so you can test the full auth flow without configuring email.
    In production, always returns the same 200 regardless of email existence
    (prevents email enumeration attacks).
    """
    client_ip = _get_client_ip(request)
    if not _check_magic_link_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many sign-in attempts. Try again in an hour.",
        )

    from app.services.auth import create_magic_link_token
    token = create_magic_link_token(str(body.email))
    link = f"{settings.FRONTEND_URL}/auth/verify?token={token}"

    # Email is configured if EITHER provider is set: Resend (RESEND_API_KEY) or
    # SMTP (SMTP_HOST). The app sends via SMTP, so this must not gate on Resend alone.
    email_configured = bool(settings.RESEND_API_KEY) or bool(settings.SMTP_HOST)
    if not email_configured:
        if not settings.DEBUG:
            # Production with no email provider configured — refuse rather than leaking the token
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Email service is not configured. Contact the administrator.",
            )
        # Dev only: return the link directly so the full auth flow can be tested locally
        return {
            "message": "Dev mode: no email provider set. Use the link below to sign in.",
            "dev_link": link,
        }

    await send_magic_link(str(body.email))
    return {"message": "Check your email for a sign-in link."}


@router.get("/verify")
async def verify_magic_link(
    token: str,
    response: Response,
    db: AsyncSession = Depends(get_db),
    next: str = "/dashboard",
):
    """Verify magic link token, create session, redirect to destination.

    The optional `next` parameter allows email links to deep-link into the app
    (e.g. straight to a CVE detail page). It is validated to be a relative path
    to prevent open-redirect attacks — any external URL is silently ignored.
    """
    # Validate redirect target — must be a relative path, never an external URL
    safe_redirect = next if (next.startswith("/") and not next.startswith("//")) else "/dashboard"

    email = verify_magic_link_token(token)
    if not email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired link")

    user = await get_or_create_user(db, email)
    session_token = create_session_token(str(user.id), user.email)

    redirect = RedirectResponse(url=f"{settings.FRONTEND_URL}{safe_redirect}", status_code=302)
    redirect.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=settings.FRONTEND_URL.startswith("https://"),
        samesite="lax",
        max_age=60 * 60 * 24 * settings.SESSION_EXPIRE_DAYS,
    )
    return redirect


@router.post("/logout")
async def logout(response: Response):
    """Clear session cookie."""
    response.delete_cookie(
        "session_token",
        httponly=True,
        secure=settings.FRONTEND_URL.startswith("https://"),
        samesite="lax",
    )
    return {"message": "Logged out"}


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user_dep)):
    """Get current authenticated user."""
    return current_user
