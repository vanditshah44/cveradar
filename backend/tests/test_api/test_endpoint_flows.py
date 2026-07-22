from datetime import date, datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api import cves as cves_api
from app.api import stack as stack_api
from app.api import stats as stats_api
from app.schemas.stack import StackItemCreate, StackItemUpdate
from app.services.matching import MatchDispatchResult


class ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value

    def all(self):
        # The stats endpoint's severity-distribution and top-product queries
        # consume their results with .all() rather than a scalar accessor.
        return self.value if isinstance(self.value, list) else [self.value]


class SequenceSession:
    def __init__(self, values):
        self.values = list(values)

    async def execute(self, statement):
        return ScalarResult(self.values.pop(0))


class StackCreateSession:
    def __init__(self):
        self.item = None
        self.committed = False

    def add(self, item):
        if getattr(item, "id", None) is None:
            item.id = uuid4()
        if getattr(item, "added_at", None) is None:
            item.added_at = datetime.now(timezone.utc)
        self.item = item

    async def flush(self):
        return None

    async def commit(self):
        self.committed = True

    async def refresh(self, item):
        return None

    async def rollback(self):
        return None


class StackLookupResult:
    def __init__(self, item):
        self.item = item

    def scalar_one_or_none(self):
        return self.item


class StackUpdateSession:
    def __init__(self, item):
        self.item = item
        self.committed = False

    async def execute(self, statement):
        return StackLookupResult(self.item)

    async def commit(self):
        self.committed = True

    async def refresh(self, item):
        return None


class RowResult:
    def __init__(self, rows=None, scalar_rows=None):
        self.rows = rows or []
        self.scalar_rows = scalar_rows or []

    def all(self):
        return self.rows

    def scalars(self):
        # Callers reach ORM entities through .scalars().all(); those live in
        # scalar_rows, not rows. Returning self here made .scalars().all() hand
        # back the (empty) row list, so the CVE detail endpoint saw no affected
        # products and silently fell back to None.
        return RowResult(rows=self.scalar_rows)

    def first(self):
        return self.rows[0] if self.rows else None


class CveDetailSession:
    def __init__(self, match_rows, affected_rows):
        self.calls = 0
        self.match_rows = match_rows
        self.affected_rows = affected_rows

    async def execute(self, statement):
        self.calls += 1
        if self.calls == 1:
            return RowResult(rows=self.match_rows)
        return RowResult(scalar_rows=self.affected_rows)


class FailingAffectedProductsSession(CveDetailSession):
    async def execute(self, statement):
        self.calls += 1
        if self.calls == 1:
            return RowResult(rows=self.match_rows)
        raise RuntimeError("affected product columns unavailable")


@pytest.mark.asyncio
async def test_add_stack_item_returns_saved_item_and_matching_status(monkeypatch):
    session = StackCreateSession()
    user = SimpleNamespace(id=uuid4())
    monkeypatch.setattr(
        stack_api,
        "trigger_matching_for_user",
        lambda user_id: MatchDispatchResult(queued=True, message="queued"),
    )

    result = await stack_api.add_to_stack(
        StackItemCreate(
            product_name="Nginx",
            vendor="nginx",
            cpe_product="nginx",
            version="1.24.0",
            cpe_string="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
            category="web_server",
        ),
        current_user=user,
        db=session,
    )

    assert session.committed is True
    assert result.product_name == "Nginx"
    assert result.matching_queued is True
    assert result.matching_message == "queued"


@pytest.mark.asyncio
async def test_update_stack_item_returns_updated_version_and_dispatch_state(monkeypatch):
    item = SimpleNamespace(
        id=uuid4(),
        user_id=uuid4(),
        product_name="Nginx",
        vendor="nginx",
        cpe_product="nginx",
        version="1.24.0",
        cpe_string="old",
        category="web_server",
        added_at=datetime.now(timezone.utc),
    )
    session = StackUpdateSession(item)
    monkeypatch.setattr(
        stack_api,
        "trigger_matching_for_user",
        lambda user_id: MatchDispatchResult(queued=False, message="worker unavailable"),
    )

    result = await stack_api.update_stack_item(
        item.id,
        StackItemUpdate(version="1.24.1", cpe_string="new"),
        current_user=SimpleNamespace(id=item.user_id),
        db=session,
    )

    assert session.committed is True
    assert item.version == "1.24.1"
    assert result.version == "1.24.1"
    assert result.matching_queued is False
    assert result.matching_message == "worker unavailable"


@pytest.mark.asyncio
async def test_stats_endpoint_returns_distinct_cve_counts():
    # Queries in order: total, critical, kev, new-since-last-visit, then the
    # severity-distribution rows and the top-exposed-product rows.
    severity_rows = [("CVE-1", 9.8), ("CVE-2", 9.1), ("CVE-3", 7.4), ("CVE-4", 5.0)]
    product_rows = [
        SimpleNamespace(product_name="nginx", cve_count=3, crit_count=2, kev_count=1),
        SimpleNamespace(product_name="redis", cve_count=1, crit_count=0, kev_count=0),
    ]
    session = SequenceSession([5, 2, 1, 3, severity_rows, product_rows])
    user = SimpleNamespace(id=uuid4(), last_seen_at=datetime.now(timezone.utc))

    result = await stats_api.get_stats(current_user=user, db=session)

    assert result.total_cves == 5
    assert result.critical_count == 2
    assert result.kev_count == 1
    assert result.new_since_last_visit == 3

    # 9.8 and 9.1 are Critical, 7.4 is High, 5.0 is Medium; empty buckets are dropped.
    assert [(item.severity, item.count) for item in result.severity_distribution] == [
        ("Critical", 2),
        ("High", 1),
        ("Medium", 1),
    ]
    assert [item.name for item in result.top_products] == ["nginx", "redis"]
    assert result.top_products[0].crit_count == 2


@pytest.mark.asyncio
async def test_cve_detail_endpoint_returns_references_matches_and_affected_ranges():
    user_id = uuid4()
    stack_item_id = uuid4()
    match_rows = [
        (
            SimpleNamespace(priority_score=91.0, matched_at=datetime(2026, 4, 6, 10, 0, tzinfo=timezone.utc), seen_at=None, dismissed=False),
            SimpleNamespace(
                cve_id="CVE-2026-9999",
                description="Critical issue in nginx",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                epss_score=0.91,
                kev_flag=True,
                kev_date_added=date(2026, 4, 5),
                published_at=datetime(2026, 4, 4, 12, 0, tzinfo=timezone.utc),
                references=[
                    {"url": "https://example.com/notes", "source": "Example", "tags": ["Release Notes"]},
                    {"url": "https://vendor.example.com/advisory", "source": "Vendor", "tags": ["Vendor Advisory"]},
                ],
            ),
            SimpleNamespace(
                id=stack_item_id,
                product_name="Nginx",
                vendor="nginx",
                cpe_product="nginx",
                version="1.24.0",
                category="web_server",
            ),
        ),
        (
            SimpleNamespace(priority_score=91.0, matched_at=datetime(2026, 4, 6, 11, 0, tzinfo=timezone.utc), seen_at=None, dismissed=False),
            SimpleNamespace(
                cve_id="CVE-2026-9999",
                description="Critical issue in nginx",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                epss_score=0.91,
                kev_flag=True,
                kev_date_added=date(2026, 4, 5),
                published_at=datetime(2026, 4, 4, 12, 0, tzinfo=timezone.utc),
                references=[
                    {"url": "https://example.com/notes", "source": "Example", "tags": ["Release Notes"]},
                    {"url": "https://vendor.example.com/advisory", "source": "Vendor", "tags": ["Vendor Advisory"]},
                ],
            ),
            SimpleNamespace(
                id=uuid4(),
                product_name="OpenResty",
                vendor="nginx",
                cpe_product="nginx",
                version="1.24.0",
                category="proxy",
            ),
        ),
    ]
    affected_rows = [
        SimpleNamespace(
            vendor="nginx",
            product="nginx",
            version_start="1.20.0",
            version_start_including=True,
            version_end="1.24.3",
            version_end_including=False,
            single_version=None,
            condition_group="group-1",
            config_path="nodes[0].cpeMatch[0]",
            is_vulnerable_match=True,
            match_context=None,
        )
    ]
    session = CveDetailSession(match_rows, affected_rows)

    result = await cves_api.get_cve_detail(
        "CVE-2026-9999",
        current_user=SimpleNamespace(id=user_id),
        db=session,
    )

    assert result.cve_id == "CVE-2026-9999"
    assert result.priority_score == 91.0
    assert len(result.matched_stack_items) == 2
    assert result.useful_reference is not None
    assert result.useful_reference.url == "https://vendor.example.com/advisory"
    assert result.affected_products[0].range_display == "≥ 1.20.0 and < 1.24.3"


@pytest.mark.asyncio
async def test_cve_detail_endpoint_normalizes_reference_and_match_context_shapes():
    user_id = uuid4()
    match_rows = [
        (
            SimpleNamespace(priority_score=55.0, matched_at=datetime(2026, 4, 6, 10, 0, tzinfo=timezone.utc), seen_at=None, dismissed=False),
            SimpleNamespace(
                cve_id="CVE-2026-7777",
                description="Odd reference shapes",
                cvss_score=5.6,
                cvss_vector=None,
                epss_score=0.25,
                kev_flag=False,
                kev_date_added=None,
                published_at=datetime(2026, 4, 4, 12, 0, tzinfo=timezone.utc),
                references=[
                    {"url": "https://vendor.example.com/advisory", "source": "Vendor", "tags": "Vendor Advisory"},
                    {"url": "https://example.com/raw", "source": None, "tags": None},
                ],
            ),
            SimpleNamespace(
                id=uuid4(),
                product_name="Nginx",
                vendor="nginx",
                cpe_product="nginx",
                version="1.24.0",
                category="web_server",
            ),
        ),
    ]
    affected_rows = [
        SimpleNamespace(
            vendor="nginx",
            product="nginx",
            version_start=None,
            version_start_including=True,
            version_end=None,
            version_end_including=False,
            single_version="1.24.0",
            condition_group="group-1",
            config_path="nodes[0].cpeMatch[0]",
            is_vulnerable_match=True,
            match_context=["unexpected"],
        )
    ]

    result = await cves_api.get_cve_detail(
        "CVE-2026-7777",
        current_user=SimpleNamespace(id=user_id),
        db=CveDetailSession(match_rows, affected_rows),
    )

    assert result.references is not None
    assert result.references[0].tags == ["Vendor Advisory"]
    assert result.useful_reference is not None
    assert result.useful_reference.tags == ["Vendor Advisory"]
    assert result.affected_products is not None
    assert result.affected_products[0].match_context is None


@pytest.mark.asyncio
async def test_cve_detail_endpoint_still_loads_when_affected_products_query_fails():
    user_id = uuid4()
    match_rows = [
        (
            SimpleNamespace(priority_score=80.0, matched_at=datetime(2026, 4, 6, 10, 0, tzinfo=timezone.utc), seen_at=None, dismissed=False),
            SimpleNamespace(
                cve_id="CVE-2026-5555",
                description="Fallback detail response",
                cvss_score=8.2,
                cvss_vector=None,
                epss_score=0.4,
                kev_flag=False,
                kev_date_added=None,
                published_at=datetime(2026, 4, 4, 12, 0, tzinfo=timezone.utc),
                references=[],
            ),
            SimpleNamespace(
                id=uuid4(),
                product_name="PostgreSQL",
                vendor="postgresql",
                cpe_product="postgresql",
                version="16.2",
                category="database",
            ),
        ),
    ]

    result = await cves_api.get_cve_detail(
        "CVE-2026-5555",
        current_user=SimpleNamespace(id=user_id),
        db=FailingAffectedProductsSession(match_rows, []),
    )

    assert result.cve_id == "CVE-2026-5555"
    assert result.affected_products is None
