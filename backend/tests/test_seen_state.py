from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.seen_state import (
    count_new_since_last_visit,
    is_new_since_last_visit,
    resolve_seen_at,
)


def make_match(*, matched_at: datetime, seen_at: datetime | None):
    return SimpleNamespace(matched_at=matched_at, seen_at=seen_at)


def test_resolve_seen_at_preserves_existing_timestamp():
    original_seen_at = datetime(2026, 4, 6, 9, 0, tzinfo=timezone.utc)
    new_attempt = datetime(2026, 4, 6, 10, 0, tzinfo=timezone.utc)

    assert resolve_seen_at(original_seen_at, new_attempt) == original_seen_at


def test_is_new_since_last_visit_true_for_unseen_recent_match():
    last_seen_at = datetime(2026, 4, 6, 8, 0, tzinfo=timezone.utc)
    matched_at = datetime(2026, 4, 6, 9, 0, tzinfo=timezone.utc)

    assert is_new_since_last_visit(
        matched_at=matched_at,
        seen_at=None,
        last_seen_at=last_seen_at,
    ) is True


def test_is_new_since_last_visit_false_once_marked_seen():
    last_seen_at = datetime(2026, 4, 6, 8, 0, tzinfo=timezone.utc)
    matched_at = datetime(2026, 4, 6, 9, 0, tzinfo=timezone.utc)
    seen_at = datetime(2026, 4, 6, 9, 5, tzinfo=timezone.utc)

    assert is_new_since_last_visit(
        matched_at=matched_at,
        seen_at=seen_at,
        last_seen_at=last_seen_at,
    ) is False


def test_count_new_since_last_visit_counts_only_unseen_matches_after_cutoff():
    last_seen_at = datetime.now(timezone.utc)
    matches = [
        make_match(matched_at=last_seen_at - timedelta(minutes=5), seen_at=None),
        make_match(matched_at=last_seen_at + timedelta(minutes=5), seen_at=None),
        make_match(matched_at=last_seen_at + timedelta(minutes=10), seen_at=last_seen_at + timedelta(minutes=11)),
    ]

    assert count_new_since_last_visit(matches, last_seen_at) == 1
