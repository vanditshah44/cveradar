"""
seen_state.py — helpers for dashboard read/unread semantics.

We intentionally track two different concepts:
- last_seen_at: when the user last visited the dashboard
- seen_at: when the user actually opened or explicitly marked a CVE as seen
"""
from datetime import datetime


def resolve_seen_at(existing_seen_at: datetime | None, now: datetime) -> datetime:
    """Keep the original seen timestamp once a CVE has been read."""
    return existing_seen_at or now


def is_new_since_last_visit(
    *,
    matched_at: datetime,
    seen_at: datetime | None,
    last_seen_at: datetime | None,
) -> bool:
    """A CVE is 'new since last visit' only if it is still unseen and arrived later."""
    if seen_at is not None:
        return False
    if last_seen_at is None:
        return True
    return matched_at > last_seen_at


def count_new_since_last_visit(matches: list[object], last_seen_at: datetime | None) -> int:
    """Count unseen matches created after the user's previous dashboard visit."""
    return sum(
        1
        for match in matches
        if is_new_since_last_visit(
            matched_at=match.matched_at,
            seen_at=match.seen_at,
            last_seen_at=last_seen_at,
        )
    )
