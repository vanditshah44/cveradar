"""
kev_sync.py — CISA Known Exploited Vulnerabilities (KEV) sync.

CISA maintains a catalog of vulnerabilities that are actively being
exploited in the wild. Being in KEV is the strongest signal we have
that a CVE is dangerous right now.

Source: single JSON endpoint — no pagination, just download and process.
Runs hourly (CISA updates the catalog throughout the day).

After updating KEV flags, we:
1. Re-run the matcher to update priority scores (KEV adds +30 to score)
2. Trigger instant alerts for users whose stack matches a newly KEV'd CVE
"""
import logging
from datetime import date, datetime, timezone

import httpx
from celery import shared_task
from sqlalchemy import update

from app.config import settings
from app.database import SyncSessionLocal
from app.models.cve import Cve
from app.services.structured_logging import log_structured_event
from app.services.sync_runs import finish_sync_run, start_sync_run

logger = logging.getLogger(__name__)


def _queue_follow_up(task_name: str, fn, *args) -> dict[str, str | bool | None]:
    try:
        task = fn.delay(*args)
    except Exception as exc:
        logger.warning("Could not queue %s: %s", task_name, exc, exc_info=True)
        return {"queued": False, "task_id": None, "message": str(exc)}

    return {"queued": True, "task_id": task.id, "message": None}


@shared_task(
    name="app.tasks.kev_sync.sync_kev",
    bind=True,
    max_retries=3,
    default_retry_delay=120,
)
def sync_kev(self) -> dict:
    """Download CISA KEV catalog and update kev_flag on matching CVEs."""
    logger.info("Starting CISA KEV sync")
    run_id = start_sync_run(
        "kev_sync",
        trigger_source="celery_task",
    )
    log_structured_event(logger, logging.INFO, "kev_sync_started", run_id=run_id)

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.get(settings.KEV_URL)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        log_structured_event(logger, logging.ERROR, "kev_sync_failed", run_id=run_id, error=str(exc))
        logger.error("Failed to fetch KEV catalog: %s", exc)
        finish_sync_run(run_id, status="failed", error_message=str(exc))
        raise self.retry(exc=exc)

    vulnerabilities = data.get("vulnerabilities", [])
    logger.info("KEV catalog has %d entries", len(vulnerabilities))

    updated_count = 0
    newly_kev_cve_ids = []
    matcher_queue = {"queued": False, "task_id": None, "message": None}
    alerts_queue = {"queued": False, "task_id": None, "message": None}

    with SyncSessionLocal() as db:
        for entry in vulnerabilities:
            cve_id = entry.get("cveID")
            date_added_str = entry.get("dateAdded")

            if not cve_id:
                continue

            kev_date = None
            if date_added_str:
                try:
                    kev_date = date.fromisoformat(date_added_str)
                except ValueError:
                    pass

            # Check if this CVE exists in our DB and isn't already KEV-flagged
            existing = db.get(Cve, cve_id)
            if existing and not existing.kev_flag:
                newly_kev_cve_ids.append(cve_id)

            # Bulk update: set kev_flag=True for all CVEs in the KEV list
            # Only update CVEs we already have in our DB
            result = db.execute(
                update(Cve)
                .where(Cve.cve_id == cve_id)
                .values(
                    kev_flag=True,
                    kev_date_added=kev_date,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            if result.rowcount > 0:
                updated_count += 1

        db.commit()

    newly_kev_cve_ids = list(dict.fromkeys(newly_kev_cve_ids))

    # Re-run matcher and notifications only for newly KEV'd CVEs.
    # Existing KEV CVEs stay out of this path so we do not re-alert users every hour.
    if newly_kev_cve_ids:
        logger.info("Queueing KEV follow-up work for %d newly flagged CVEs", len(newly_kev_cve_ids))
        from app.tasks.matcher import queue_matcher_for_cves
        matcher_queue = queue_matcher_for_cves(newly_kev_cve_ids, reason="KEV rematch")

        # Trigger instant alert notifications for the same newly flagged CVEs only.
        from app.tasks.notifications import send_instant_kev_alerts
        alerts_queue = _queue_follow_up("instant KEV alerts", send_instant_kev_alerts, newly_kev_cve_ids)

    result = {
        "kev_total": len(vulnerabilities),
        "updated_in_db": updated_count,
        "newly_flagged": len(newly_kev_cve_ids),
        "matcher_queue": matcher_queue,
        "alerts_queue": alerts_queue,
    }
    finish_sync_run(run_id, status="success", details=result)
    log_structured_event(logger, logging.INFO, "kev_sync_finished", run_id=run_id, **result)
    logger.info("KEV sync complete: %s", result)
    return result
