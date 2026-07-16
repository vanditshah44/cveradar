"""
Notification — audit log of every email sent.

Two types:
  'instant_kev'   — sent within 1 hour when a KEV-flagged CVE matches a user's stack
  'daily_digest'  — sent once/day with all new matches from the last 24 hours

cve_ids stores the list of CVE IDs included in that email (as JSON array).
This lets us answer "why didn't I get an alert for CVE-2024-1234?" —
we can check if it was included in a notification.

idempotency_key prevents duplicate sends when Celery retries or the same task
is queued twice.

status tracks delivery: 'processing', 'sent', 'previewed', 'failed', 'skipped'
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    notification_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'instant_kev' | 'daily_digest'
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    cve_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)           # ["CVE-2024-1234", ...]
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="processing")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivery_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="notifications")

    def __repr__(self) -> str:
        return f"<Notification {self.notification_type} user={self.user_id} status={self.status}>"
