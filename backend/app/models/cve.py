"""
CVE and CveAffectedProduct models.

CVE is intentionally denormalized — CVSS, EPSS, and KEV all come from
different external feeds but are flattened into one row. This makes
the matcher query fast (one table join instead of three).

CveAffectedProduct is the most complex table. Each row represents one
"affected range" from NVD's CPE configuration data. A single CVE often
has multiple rows here — e.g., "affects nginx 1.20.0 through 1.24.2"
AND "affects nginx 1.25.0 only".

The version range fields encode all four flavors:
  >= start  →  version_start_including=True,  version_start != None
  >  start  →  version_start_including=False, version_start != None
  <= end    →  version_end_including=True,    version_end != None
  <  end    →  version_end_including=False,   version_end != None
"""
import uuid
from datetime import datetime, date, timezone

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Cve(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)  # "CVE-2024-1234"
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)       # 0.0–10.0
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)  # "CVSS:3.1/AV:N/..."
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)       # 0.0–1.0 probability
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0.0–1.0
    kev_flag: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # references: [{url, source, tags}] — stored as JSON for flexibility
    references: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    affected_products: Mapped[list["CveAffectedProduct"]] = relationship(
        "CveAffectedProduct", back_populates="cve", cascade="all, delete-orphan"
    )
    user_matches: Mapped[list["UserCveMatch"]] = relationship(
        "UserCveMatch", back_populates="cve", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<CVE {self.cve_id} cvss={self.cvss_score} kev={self.kev_flag}>"


class CveAffectedProduct(Base):
    __tablename__ = "cve_affected_products"
    __table_args__ = (
        # Matcher does: WHERE vendor = ? AND product = ?  — this index is critical
        Index("idx_cve_affected_vendor_product", "vendor", "product"),
        Index("idx_cve_affected_vendor_product_cve", "vendor", "product", "cve_id"),
        Index("idx_cve_affected_cve_id", "cve_id"),
        Index("idx_cve_affected_cve_group", "cve_id", "condition_group"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False
    )
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    cpe_string: Mapped[str] = mapped_column(Text, nullable=False)
    version_start: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_start_including: Mapped[bool] = mapped_column(Boolean, default=True)
    version_end: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version_end_including: Mapped[bool] = mapped_column(Boolean, default=False)
    # single_version: when a CPE matches exactly one version (no range)
    single_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    condition_group: Mapped[str | None] = mapped_column(String(100), nullable=True)
    config_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_vulnerable_match: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    match_context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    cve: Mapped["Cve"] = relationship("Cve", back_populates="affected_products")

    def __repr__(self) -> str:
        return (
            f"<AffectedProduct {self.cve_id} {self.vendor}/{self.product} "
            f"group={self.condition_group} vulnerable={self.is_vulnerable_match}>"
        )
