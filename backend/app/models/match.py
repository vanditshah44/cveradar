"""
UserCveMatch — the pre-computed join table between users and CVEs.

This is the table that makes the dashboard fast. When the matcher runs,
it populates this table. The dashboard just reads from it — no live
matching on every page load.

The UNIQUE constraint on (user_id, cve_id, stack_item_id) means if the
matcher runs again, it won't create duplicate rows — it'll update the
existing ones (ON CONFLICT DO UPDATE in the upsert logic).

dismissed: user manually hid this CVE from their dashboard.
seen_at: NULL = new/unseen. The "3 new CVEs" badge counts rows where seen_at IS NULL.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserCveMatch(Base):
    __tablename__ = "user_cve_matches"
    __table_args__ = (
        UniqueConstraint("user_id", "cve_id", "stack_item_id", name="uq_match"),
        Index("idx_user_cve_matches_user", "user_id", "dismissed"),
        Index("idx_user_cve_matches_user_cve", "user_id", "cve_id"),
        Index("idx_user_cve_matches_cve_stack_item", "cve_id", "stack_item_id"),
        # Partial index — only indexes unseen rows, making "new count" query fast
        Index(
            "idx_user_cve_matches_unseen",
            "user_id",
            "seen_at",
            postgresql_where="seen_at IS NULL",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False
    )
    stack_item_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("stack_items.id", ondelete="CASCADE"), nullable=False
    )
    # Computed once at match time. Higher = more urgent. Formula: kev(30) + epss*40 + cvss_norm*30
    priority_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dismissed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="cve_matches")
    cve: Mapped["Cve"] = relationship("Cve", back_populates="user_matches")
    stack_item: Mapped["StackItem"] = relationship("StackItem", back_populates="cve_matches")

    def __repr__(self) -> str:
        return f"<Match user={self.user_id} cve={self.cve_id} score={self.priority_score:.1f}>"
