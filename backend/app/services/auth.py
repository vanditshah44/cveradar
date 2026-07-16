"""
auth.py — Magic link authentication service.

How magic link auth works:
  1. User enters email → POST /api/auth/magic-link
  2. We generate a signed JWT token with the email + expiry (15 min)
  3. We send an email with a link: /auth/verify?token=<jwt>
  4. User clicks the link → GET /api/auth/verify?token=<jwt>
  5. We verify the JWT, look up or create the user, set an HTTP-only session cookie
  6. User is now authenticated

Why no passwords?
  - No password storage = no password breach risk
  - No password reset flow to build
  - Email is already a trusted channel for this user base
  - Magic links feel modern for a security-conscious tool

The token is a JWT signed with SECRET_KEY. It contains:
  - sub: the email address
  - purpose: "magic_link" (prevents session tokens from being used as magic links)
  - exp: expiry timestamp
"""
import hashlib
import logging
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from redis import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.models.user import User
from app.services.email import send_email

logger = logging.getLogger(__name__)


def _redis_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


def _magic_link_used_key(token: str) -> str:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return f"magic_link:used:{token_hash}"


def create_magic_link_token(email: str) -> str:
    """Generate a short-lived JWT for magic link authentication."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.MAGIC_LINK_EXPIRE_MINUTES)
    payload = {
        "sub": email,
        "purpose": "magic_link",
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_session_token(user_id: str, email: str) -> str:
    """Generate a long-lived session token (stored in HTTP-only cookie)."""
    expire = datetime.now(timezone.utc) + timedelta(days=settings.SESSION_EXPIRE_DAYS)
    payload = {
        "sub": str(user_id),
        "email": email,
        "purpose": "session",
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_magic_link_token(token: str) -> str | None:
    """Verify a magic link token and return the email, or None if invalid/used.

    Tokens are single-use: after a successful verification the token is marked
    as consumed in Redis for the remainder of its TTL so it cannot be replayed.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("purpose") != "magic_link":
            return None
        email = payload.get("sub")
        if not email:
            return None
    except JWTError:
        return None

    # Mark token as used atomically. SET NX returns True only if the key was
    # newly created, meaning the token has not been used before.
    key = _magic_link_used_key(token)
    ttl = settings.MAGIC_LINK_EXPIRE_MINUTES * 60
    client = None
    try:
        client = _redis_client()
        if not client.set(key, "1", nx=True, ex=ttl):
            logger.warning("Magic link replay attempt blocked for %s", email)
            return None  # already used
    except Exception:
        # Fail closed — deny rather than allow potential replay during Redis outage.
        # The 15-min JWT window is not enough protection on its own if an attacker
        # intercepted a link and Redis is down.
        logger.error("Redis unavailable during magic link check; denying verification")
        return None
    finally:
        if client is not None:
            client.close()

    return email


def verify_session_token(token: str) -> dict | None:
    """Verify a session token. Returns {user_id, email} or None."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("purpose") != "session":
            return None
        return {"user_id": payload.get("sub"), "email": payload.get("email")}
    except JWTError:
        return None


async def send_magic_link(email: str) -> None:
    """Generate and send a magic link email."""
    token = create_magic_link_token(email)
    link = f"{settings.FRONTEND_URL}/auth/verify?token={token}"

    html = f"""
    <div style="font-family: system-ui, sans-serif; max-width: 500px; margin: 0 auto; padding: 24px;">
      <h2 style="margin: 0 0 8px;">Sign in to CVE Radar</h2>
      <p style="color: #6b7280; margin: 0 0 24px;">Click the button below to sign in. This link expires in {settings.MAGIC_LINK_EXPIRE_MINUTES} minutes.</p>
      <a href="{link}" style="background: #111; color: white; padding: 12px 24px;
         text-decoration: none; border-radius: 6px; display: inline-block;">
        Sign in →
      </a>
      <p style="color: #9ca3af; font-size: 12px; margin-top: 24px;">
        If you didn't request this, you can ignore this email.
      </p>
    </div>
    """

    send_email(to=email, subject="Sign in to CVE Radar", html=html)
    logger.info("Magic link sent to %s", email)


async def get_or_create_user(db: AsyncSession, email: str) -> User:
    """Look up a user by email, or create a new account if first login."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        user = User(email=email)
        db.add(user)
        await db.flush()  # flush to get the generated UUID without committing
        logger.info("New user created: %s", email)

    user.last_login_at = datetime.now(timezone.utc)
    return user


async def get_current_user(db: AsyncSession, token: str) -> User | None:
    """Validate session token and return the authenticated user."""
    claims = verify_session_token(token)
    if not claims:
        return None

    result = await db.execute(select(User).where(User.id == claims["user_id"]))
    return result.scalar_one_or_none()
