import uuid
from datetime import datetime
from pydantic import BaseModel


class CveListItemOut(BaseModel):
    """What the dashboard displays for each deduplicated CVE entry."""
    cve_id: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    kev_flag: bool
    kev_date_added: str | None
    published_at: datetime | None
    severity: str
    priority_score: float
    matched_at: datetime
    seen_at: datetime | None
    dismissed: bool
    primary_product_name: str
    product_names: list[str]
    product_count: int

    model_config = {"from_attributes": True}


class CveListOut(BaseModel):
    items: list[CveListItemOut]
    page: int
    per_page: int
    total_items: int
    total_pages: int
    sort_by: str


class CveReferenceOut(BaseModel):
    url: str | None
    source: str | None
    tags: list[str] | None


class MatchedStackItemOut(BaseModel):
    id: uuid.UUID
    product_name: str
    vendor: str
    cpe_product: str
    version: str
    category: str | None
    matched_at: datetime
    seen_at: datetime | None


class AffectedProductOut(BaseModel):
    vendor: str
    product: str
    version_start: str | None
    version_start_including: bool
    version_end: str | None
    version_end_including: bool
    single_version: str | None
    condition_group: str | None
    config_path: str | None
    is_vulnerable_match: bool
    match_context: dict | None
    range_display: str


class CveMatchOut(BaseModel):
    """What the dashboard displays for each CVE match."""
    cve_id: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    kev_flag: bool
    kev_date_added: str | None
    published_at: datetime | None
    severity: str           # "Critical" | "High" | "Medium" | "Low" | "Unknown"
    priority_score: float   # 0–100
    matched_at: datetime
    seen_at: datetime | None
    dismissed: bool
    stack_item_id: uuid.UUID
    product_name: str       # which product in user's stack triggered this

    model_config = {"from_attributes": True}


class CveDetailOut(CveMatchOut):
    """Full CVE detail page — adds references and affected products."""
    references: list[CveReferenceOut] | None
    useful_reference: CveReferenceOut | None
    matched_stack_items: list[MatchedStackItemOut]
    affected_products: list[AffectedProductOut] | None


class SeverityDistributionItem(BaseModel):
    severity: str
    count: int


class TopProductItem(BaseModel):
    name: str
    count: int
    crit_count: int
    kev_count: int


class StatsOut(BaseModel):
    total_cves: int
    critical_count: int
    kev_count: int
    new_since_last_visit: int
    severity_distribution: list[SeverityDistributionItem] = []
    top_products: list[TopProductItem] = []
