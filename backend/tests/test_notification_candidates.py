from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.tasks.notifications import (
    _candidate_daily_digest_matches,
    _candidate_user_ids_for_kev_matches,
)


def test_candidate_user_ids_for_kev_matches_deduplicates_users():
    user_a = uuid4()
    user_b = uuid4()
    matches = [
        SimpleNamespace(user_id=user_a),
        SimpleNamespace(user_id=user_a),
        SimpleNamespace(user_id=user_b),
    ]

    result = _candidate_user_ids_for_kev_matches(matches)

    assert result == sorted([user_a, user_b], key=str)


def test_candidate_daily_digest_matches_excludes_seen_dismissed_and_old_matches():
    now = datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc)
    cutoff = now - timedelta(hours=24)
    eligible = SimpleNamespace(seen_at=None, dismissed=False, matched_at=now - timedelta(hours=2))
    seen = SimpleNamespace(seen_at=now - timedelta(minutes=1), dismissed=False, matched_at=now - timedelta(hours=2))
    dismissed = SimpleNamespace(seen_at=None, dismissed=True, matched_at=now - timedelta(hours=2))
    old = SimpleNamespace(seen_at=None, dismissed=False, matched_at=now - timedelta(days=2))

    result = _candidate_daily_digest_matches([eligible, seen, dismissed, old], cutoff)

    assert result == [eligible]
