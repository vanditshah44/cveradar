"""
ProductCatalog — the ~50 curated products we support at launch.

This exists because the full NVD CPE dictionary has 1M+ entries.
We don't expose all of them to users — we maintain a curated list of
products that homelabbers actually run, with manually verified
vendor/cpe_product mappings.

This table drives the autocomplete on the stack page. When a user
types "ngi", we search display_name and return matching catalog entries.
The user picks one, and we know exactly which CPE fields to use for matching.
"""
import uuid

from sqlalchemy import Boolean, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ProductCatalog(Base):
    __tablename__ = "product_catalog"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)   # "Nginx"
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)         # "nginx"
    cpe_product: Mapped[str] = mapped_column(String(255), nullable=False)    # "nginx"
    category: Mapped[str | None] = mapped_column(String(100), nullable=True) # "web_server"
    icon_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    popular: Mapped[bool] = mapped_column(Boolean, default=False)

    def __repr__(self) -> str:
        return f"<ProductCatalog {self.display_name} ({self.vendor}/{self.cpe_product})>"
