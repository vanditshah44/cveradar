from datetime import datetime, timedelta, timezone

from jose import jwt

from app.config import settings
from app.services.auth import (
    create_magic_link_token,
    create_session_token,
    verify_magic_link_token,
    verify_session_token,
)


def test_magic_link_token_round_trip_returns_email():
    token = create_magic_link_token("user@example.com")

    assert verify_magic_link_token(token) == "user@example.com"


def test_session_token_round_trip_returns_claims():
    token = create_session_token("user-123", "user@example.com")

    assert verify_session_token(token) == {
        "user_id": "user-123",
        "email": "user@example.com",
    }


def test_magic_link_verifier_rejects_session_token():
    token = create_session_token("user-123", "user@example.com")

    assert verify_magic_link_token(token) is None


def test_session_verifier_rejects_magic_link_token():
    token = create_magic_link_token("user@example.com")

    assert verify_session_token(token) is None


def test_expired_magic_link_token_returns_none():
    expired_token = jwt.encode(
        {
            "sub": "user@example.com",
            "purpose": "magic_link",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    assert verify_magic_link_token(expired_token) is None
