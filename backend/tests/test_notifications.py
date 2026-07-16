from uuid import uuid4

from app.tasks.notifications import (
    _build_notification_idempotency_key,
    _normalize_cve_ids,
)


def test_normalize_cve_ids_deduplicates_and_sorts():
    assert _normalize_cve_ids(["CVE-2", "CVE-1", "CVE-2"]) == ["CVE-1", "CVE-2"]


def test_daily_digest_idempotency_key_is_stable_for_same_cve_set():
    user_id = uuid4()

    key_a = _build_notification_idempotency_key(
        "daily_digest",
        user_id,
        ["CVE-2024-0002", "CVE-2024-0001", "CVE-2024-0002"],
        digest_bucket="2026-04-06",
    )
    key_b = _build_notification_idempotency_key(
        "daily_digest",
        user_id,
        ["CVE-2024-0001", "CVE-2024-0002"],
        digest_bucket="2026-04-06",
    )

    assert key_a == key_b


def test_instant_kev_idempotency_key_is_specific_to_single_cve():
    user_id = uuid4()

    key = _build_notification_idempotency_key(
        "instant_kev",
        user_id,
        ["CVE-2024-9999"],
    )

    assert key == f"instant_kev:{user_id}:CVE-2024-9999"
