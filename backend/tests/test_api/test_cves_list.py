from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.api.cves import _aggregate_cve_rows, _sort_cve_items


def make_match(*, cve_id: str, product_name: str, priority_score: float, matched_at: datetime, seen_at=None):
    match = SimpleNamespace(
        priority_score=priority_score,
        matched_at=matched_at,
        seen_at=seen_at,
        dismissed=False,
    )
    cve = SimpleNamespace(
        cve_id=cve_id,
        description=f"Description for {cve_id}",
        cvss_score=8.8,
        cvss_vector=None,
        epss_score=0.42,
        kev_flag=False,
        kev_date_added=None,
        published_at=matched_at,
    )
    stack_item = SimpleNamespace(
        id=uuid4(),
        product_name=product_name,
    )
    return match, cve, stack_item


def test_aggregate_cve_rows_deduplicates_and_preserves_product_context():
    now = datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc)
    rows = [
        make_match(
            cve_id="CVE-2026-0001",
            product_name="Nginx",
            priority_score=72.0,
            matched_at=now,
            seen_at=None,
        ),
        make_match(
            cve_id="CVE-2026-0001",
            product_name="OpenResty",
            priority_score=72.0,
            matched_at=now,
            seen_at=now,
        ),
    ]

    items = _aggregate_cve_rows(rows)

    assert len(items) == 1
    assert items[0].cve_id == "CVE-2026-0001"
    assert items[0].product_count == 2
    assert items[0].product_names == ["Nginx", "OpenResty"]
    assert items[0].primary_product_name == "Nginx"
    assert items[0].seen_at is None


def test_sort_cve_items_can_sort_by_product_name():
    now = datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc)
    rows = [
        make_match(
            cve_id="CVE-2026-0002",
            product_name="PostgreSQL",
            priority_score=85.0,
            matched_at=now,
        ),
        make_match(
            cve_id="CVE-2026-0003",
            product_name="Apache HTTP Server",
            priority_score=60.0,
            matched_at=now,
        ),
    ]

    items = _aggregate_cve_rows(rows)
    sorted_items = _sort_cve_items(items, "product")

    assert [item.primary_product_name for item in sorted_items] == [
        "Apache HTTP Server",
        "PostgreSQL",
    ]


def test_sort_cve_items_defaults_to_priority_descending():
    now = datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc)
    rows = [
        make_match(
            cve_id="CVE-2026-0004",
            product_name="Redis",
            priority_score=40.0,
            matched_at=now,
        ),
        make_match(
            cve_id="CVE-2026-0005",
            product_name="Nginx",
            priority_score=90.0,
            matched_at=now,
        ),
    ]

    items = _aggregate_cve_rows(rows)
    sorted_items = _sort_cve_items(items, "priority")

    assert [item.cve_id for item in sorted_items] == [
        "CVE-2026-0005",
        "CVE-2026-0004",
    ]
