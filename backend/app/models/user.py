"""
User model.

Magic-link auth means no password column — we never store credentials.
last_seen_at drives the "N new since your last visit" badge on the dashboard.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Updated on each dashboard visit; used to compute 'new since last visit'"
    )
    daily_digest: Mapped[bool] = mapped_column(Boolean, default=True)
    instant_alerts: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships (back_populates = bidirectional, lazy="select" = load on access)
    stack_items: Mapped[list["StackItem"]] = relationship(
        "StackItem", back_populates="user", cascade="all, delete-orphan"
    )
    cve_matches: Mapped[list["UserCveMatch"]] = relationship(
        "UserCveMatch", back_populates="user", cascade="all, delete-orphan"
    )
    notifications: Mapped[list["Notification"]] = relationship(
        "Notification", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"
