"""
Tests for matcher pipeline helpers.

These focus on the important correctness rules:
- exact version matching
- bounded version matching
- non-matching versions
- AND groups must be satisfied by the same user
- one CVE can legitimately create matches for multiple stack items
"""
from types import SimpleNamespace
from uuid import uuid4

from app.tasks import matcher
from app.tasks.matcher import (
    _eligible_target_stack_items,
    _normalize_cve_ids,
    _stack_item_matches_requirement,
    queue_matcher_for_cves,
)


def make_stack_item(*, vendor: str, product: str, version: str, user_id=None, stack_item_id=None):
    return SimpleNamespace(
        id=stack_item_id or uuid4(),
        user_id=user_id or uuid4(),
        vendor=vendor,
        cpe_product=product,
        version=version,
    )


def make_requirement(
    *,
    vendor: str,
    product: str,
    version_start=None,
    version_start_including=True,
    version_end=None,
    version_end_including=False,
    single_version=None,
    is_vulnerable_match=True,
    requirement_id=None,
):
    return SimpleNamespace(
        id=requirement_id or uuid4(),
        vendor=vendor,
        product=product,
        version_start=version_start,
        version_start_including=version_start_including,
        version_end=version_end,
        version_end_including=version_end_including,
        single_version=single_version,
        is_vulnerable_match=is_vulnerable_match,
    )


class TestStackItemMatchesRequirement:
    def test_exact_version_match(self):
        stack_item = make_stack_item(vendor="nginx", product="nginx", version="1.24.0")
        requirement = make_requirement(
            vendor="nginx",
            product="nginx",
            single_version="1.24.0",
        )

        assert _stack_item_matches_requirement(stack_item, requirement) is True

    def test_bounded_version_range_match(self):
        stack_item = make_stack_item(vendor="nginx", product="nginx", version="1.22.0")
        requirement = make_requirement(
            vendor="nginx",
            product="nginx",
            version_start="1.20.0",
            version_start_including=True,
            version_end="1.24.3",
            version_end_including=False,
        )

        assert _stack_item_matches_requirement(stack_item, requirement) is True

    def test_non_matching_version(self):
        stack_item = make_stack_item(vendor="nginx", product="nginx", version="1.25.0")
        requirement = make_requirement(
            vendor="nginx",
            product="nginx",
            version_start="1.20.0",
            version_start_including=True,
            version_end="1.24.3",
            version_end_including=False,
        )

        assert _stack_item_matches_requirement(stack_item, requirement) is False


class TestEligibleTargetStackItems:
    def test_and_group_requires_same_user(self):
        user_a = uuid4()
        user_b = uuid4()

        target_requirement = make_requirement(vendor="acme", product="webapp", is_vulnerable_match=True)
        env_requirement = make_requirement(vendor="microsoft", product="windows_10", is_vulnerable_match=False)

        user_a_target = make_stack_item(vendor="acme", product="webapp", version="1.0.0", user_id=user_a)
        user_b_env = make_stack_item(vendor="microsoft", product="windows_10", version="1607", user_id=user_b)

        requirement_matches = {
            target_requirement.id: [user_a_target],
            env_requirement.id: [user_b_env],
        }

        eligible = _eligible_target_stack_items(
            [target_requirement, env_requirement],
            requirement_matches,
        )

        assert eligible == []

    def test_multiple_stack_items_for_one_user_can_satisfy_one_group(self):
        user_id = uuid4()

        target_requirement = make_requirement(vendor="acme", product="webapp", is_vulnerable_match=True)
        env_requirement = make_requirement(vendor="microsoft", product="windows_10", is_vulnerable_match=False)

        user_target = make_stack_item(vendor="acme", product="webapp", version="1.0.0", user_id=user_id)
        user_env = make_stack_item(vendor="microsoft", product="windows_10", version="1607", user_id=user_id)

        requirement_matches = {
            target_requirement.id: [user_target],
            env_requirement.id: [user_env],
        }

        eligible = _eligible_target_stack_items(
            [target_requirement, env_requirement],
            requirement_matches,
        )

        assert eligible == [user_target]

    def test_same_cve_can_match_multiple_user_products(self):
        user_id = uuid4()

        product_a = make_requirement(vendor="acme", product="frontend", is_vulnerable_match=True)
        product_b = make_requirement(vendor="acme", product="backend", is_vulnerable_match=True)

        frontend_item = make_stack_item(vendor="acme", product="frontend", version="1.0.0", user_id=user_id)
        backend_item = make_stack_item(vendor="acme", product="backend", version="2.0.0", user_id=user_id)

        requirement_matches = {
            product_a.id: [frontend_item],
            product_b.id: [backend_item],
        }

        eligible = _eligible_target_stack_items(
            [product_a, product_b],
            requirement_matches,
        )

        assert {item.id for item in eligible} == {frontend_item.id, backend_item.id}


def test_normalize_cve_ids_preserves_order_while_deduplicating():
    assert _normalize_cve_ids(["CVE-3", "CVE-1", "CVE-3", "CVE-2"]) == [
        "CVE-3",
        "CVE-1",
        "CVE-2",
    ]


def test_queue_matcher_for_cves_chunks_large_rematch_requests(monkeypatch):
    queued_chunks = []

    def fake_delay(cve_ids):
        queued_chunks.append(list(cve_ids))
        return SimpleNamespace(id=f"task-{len(queued_chunks)}")

    monkeypatch.setattr(matcher, "MATCHER_QUEUE_CHUNK_SIZE", 2)
    monkeypatch.setattr(matcher.run_matcher_for_cves, "delay", fake_delay)

    result = queue_matcher_for_cves(
        ["CVE-1", "CVE-2", "CVE-1", "CVE-3", "CVE-4"],
        reason="test-rematch",
    )

    assert queued_chunks == [["CVE-1", "CVE-2"], ["CVE-3", "CVE-4"]]
    assert result["queued"] is True
    assert result["task_count"] == 2
    assert result["cves_queued"] == 4
    assert result["chunk_size"] == 2
