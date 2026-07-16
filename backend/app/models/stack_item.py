"""
StackItem model — what software a user says they run.

Key design: we store BOTH the human-readable name ("nginx") AND the CPE
components (vendor="nginx", cpe_product="nginx", cpe_string="cpe:2.3:a:...").

This separation matters:
- product_name is what the user sees and typed
- vendor + cpe_product are what the matcher uses
- cpe_string is the full canonical identifier

The UNIQUE constraint on (user_id, cpe_product, version) prevents a user
from adding "nginx 1.24.0" twice, even if they type it two different ways.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class StackItem(Base):
    __tablename__ = "stack_items"
    __table_args__ = (
        UniqueConstraint("user_id", "cpe_product", "version", name="uq_stack_user_product_version"),
        Index("idx_stack_items_vendor_product_user", "vendor", "cpe_product", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    product_name: Mapped[str] = mapped_column(String(255), nullable=False)        # "Nginx"
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)             # "nginx" (from CPE)
    cpe_product: Mapped[str] = mapped_column(String(255), nullable=False)        # "nginx" (CPE product field)
    version: Mapped[str] = mapped_column(String(100), nullable=False)            # "1.24.0"
    cpe_string: Mapped[str] = mapped_column(Text, nullable=False)                # "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)     # "web_server" (from ProductCatalog)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped["User"] = relationship("User", back_populates="stack_items")
    cve_matches: Mapped[list["UserCveMatch"]] = relationship(
        "UserCveMatch", back_populates="stack_item", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<StackItem {self.product_name} {self.version} (user={self.user_id})>"
