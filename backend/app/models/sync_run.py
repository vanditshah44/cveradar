"""
SyncRun — audit trail for data pipeline jobs.

We record a row for each sync or recovery run so we can answer:
- When did NVD/KEV/EPSS last succeed?
- Is a job currently running?
- What happened during the last bootstrap?
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SyncRun(Base):
    __tablename__ = "sync_runs"
    __table_args__ = (
        Index("idx_sync_runs_job_name_started", "job_name", "started_at"),
        Index("idx_sync_runs_job_name_status_finished", "job_name", "status", "finished_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    trigger_source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<SyncRun job={self.job_name} status={self.status}>"
