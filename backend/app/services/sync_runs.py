"""
Helpers for recording and inspecting sync pipeline runs.
"""
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select, update

from app.database import SyncSessionLocal
from app.models.sync_run import SyncRun

logger = logging.getLogger(__name__)

# A run still marked "running" after this long lost its worker (deploy, OOM,
# hard restart) and will never finish. nvd_full sat "running" from April to
# July, permanently reporting an in-flight sync that no longer existed.
STALE_RUN_AFTER = timedelta(hours=6)

SYNC_JOB_NAMES = (
    "nvd_incremental",
    "nvd_full",
    "kev_sync",
    "epss_sync",
    "match_rebuild_all",
)


def start_sync_run(
    job_name: str,
    *,
    trigger_source: str = "manual",
    details: Mapping[str, Any] | None = None,
) -> str | None:
    """Create a SyncRun row and return its id, or None on tracking failure."""
    try:
        with SyncSessionLocal() as db:
            run = SyncRun(
                job_name=job_name,
                status="running",
                trigger_source=trigger_source,
                details=dict(details) if details else None,
            )
            db.add(run)
            db.commit()
            db.refresh(run)
            return str(run.id)
    except Exception as exc:
        logger.warning(
            "Could not record sync run start for %s: %s",
            job_name,
            exc,
            exc_info=True,
        )
        return None


def finish_sync_run(
    run_id: str | None,
    *,
    status: str,
    details: Mapping[str, Any] | None = None,
    error_message: str | None = None,
) -> None:
    """Update an existing SyncRun row. No-op if tracking was not created."""
    if not run_id:
        return

    try:
        with SyncSessionLocal() as db:
            run = db.get(SyncRun, UUID(run_id))
            if not run:
                return
            run.status = status
            run.details = dict(details) if details else None
            run.error_message = error_message
            from datetime import datetime, timezone

            run.finished_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as exc:
        logger.warning(
            "Could not record sync run completion for %s: %s",
            run_id,
            exc,
            exc_info=True,
        )


def reap_stale_runs(older_than: timedelta = STALE_RUN_AFTER) -> int:
    """Mark abandoned "running" rows as failed. Returns how many were reaped.

    Nothing guards against a worker dying mid-run, so a killed process leaves its
    SyncRun row "running" forever — which reads on the dashboard as a sync that
    is still in flight and suppresses the real "last succeeded" signal.
    """
    cutoff = datetime.now(timezone.utc) - older_than
    try:
        with SyncSessionLocal() as db:
            result = db.execute(
                update(SyncRun)
                .where(SyncRun.status == "running", SyncRun.started_at < cutoff)
                .values(
                    status="failed",
                    finished_at=datetime.now(timezone.utc),
                    error_message="Abandoned: no completion recorded before the staleness cutoff.",
                )
            )
            db.commit()
            reaped = result.rowcount or 0
    except Exception as exc:
        logger.warning("Could not reap stale sync runs: %s", exc, exc_info=True)
        return 0

    if reaped:
        logger.info("Reaped %d stale sync run(s) older than %s", reaped, older_than)
    return reaped


def latest_sync_statuses(job_names: tuple[str, ...] = SYNC_JOB_NAMES) -> dict[str, dict[str, Any]]:
    """Return the latest run and latest successful run for each tracked job."""
    reap_stale_runs()
    with SyncSessionLocal() as db:
        summary: dict[str, dict[str, Any]] = {}

        for job_name in job_names:
            latest_run = db.execute(
                select(SyncRun)
                .where(SyncRun.job_name == job_name)
                .order_by(SyncRun.started_at.desc())
                .limit(1)
            ).scalar_one_or_none()

            latest_success = db.execute(
                select(SyncRun)
                .where(SyncRun.job_name == job_name, SyncRun.status == "success")
                .order_by(SyncRun.finished_at.desc(), SyncRun.started_at.desc())
                .limit(1)
            ).scalar_one_or_none()

            summary[job_name] = {
                "last_status": latest_run.status if latest_run else None,
                "last_started_at": latest_run.started_at.isoformat() if latest_run else None,
                "last_finished_at": latest_run.finished_at.isoformat() if latest_run and latest_run.finished_at else None,
                "last_success_at": latest_success.finished_at.isoformat() if latest_success and latest_success.finished_at else None,
                "last_error": latest_run.error_message if latest_run else None,
            }

        return summary
