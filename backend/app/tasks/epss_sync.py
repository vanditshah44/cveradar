"""
epss_sync.py — EPSS (Exploit Prediction Scoring System) sync.

EPSS is a daily-updated probability score from FIRST.org that predicts
the likelihood a CVE will be exploited in the next 30 days.
Range: 0.0 (very unlikely) to 1.0 (near-certain).

Source: FIRST.org API — we query in batches of CVE IDs we already have.
Runs daily at 2am UTC (EPSS updates once per day).

Why batch by existing CVEs instead of downloading the full EPSS dataset?
  The full EPSS CSV is ~200MB/day. We only need scores for CVEs in our DB.
  FIRST.org API supports querying up to 2000 CVEs per request.
"""
import logging
from datetime import datetime, timezone

import httpx
from celery import shared_task
from sqlalchemy import select, update

from app.config import settings
from app.database import SyncSessionLocal
from app.models.cve import Cve
from app.services.structured_logging import log_structured_event
from app.services.sync_runs import finish_sync_run, start_sync_run

logger = logging.getLogger(__name__)

# CVE ids travel in the query string, and api.first.org has two separate traps
# measured on 2026-07-22:
#   1. Past ~2.3 KB of URL it returns HTTP 200 with an EMPTY result set — no
#      error, just silently zero rows. (140 ids/2286 B works, 145/2366 B does
#      not.) Only past ~7.5 KB does it finally return 414 URI Too Long.
#   2. `limit` defaults to 100, so any batch over 100 is truncated unless the
#      request passes limit explicitly.
# This shipped as 2000, so every batch blew past both limits and no CVE ever
# received a score, while the task still reported success.
# 100 ids is ~1.6 KB — well clear of the silent-truncation cliff.
EPSS_BATCH_SIZE = 100

# Hard ceiling for a single request URL. Stay far below the ~2.3 KB cliff.
EPSS_MAX_URL_BYTES = 2000


@shared_task(
    name="app.tasks.epss_sync.sync_epss",
    bind=True,
    max_retries=3,
    default_retry_delay=300,
    time_limit=1800,
)
def sync_epss(self) -> dict:
    """Fetch EPSS scores for all CVEs in our database and update them."""
    logger.info("Starting EPSS sync")
    run_id = start_sync_run(
        "epss_sync",
        trigger_source="celery_task",
    )
    log_structured_event(logger, logging.INFO, "epss_sync_started", run_id=run_id)

    # Get all CVE IDs we have
    with SyncSessionLocal() as db:
        cve_ids = db.execute(select(Cve.cve_id)).scalars().all()

    logger.info("Fetching EPSS scores for %d CVEs", len(cve_ids))

    total_updated = 0
    total_errors = 0
    matcher_queue = {"queued": False, "task_id": None, "message": None}
    updated_cve_ids: list[str] = []

    # Process in batches — FIRST.org API limit is 2000/request
    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i : i + EPSS_BATCH_SIZE]

        try:
            scores = _fetch_epss_batch(batch)
        except Exception as e:
            logger.error("EPSS batch %d failed: %s", i // EPSS_BATCH_SIZE, e)
            total_errors += len(batch)
            continue

        with SyncSessionLocal() as db:
            for cve_id, epss_score, epss_percentile in scores:
                db.execute(
                    update(Cve)
                    .where(Cve.cve_id == cve_id)
                    .values(
                        epss_score=epss_score,
                        epss_percentile=epss_percentile,
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                total_updated += 1
                updated_cve_ids.append(cve_id)
            db.commit()

        logger.info(
            "EPSS batch %d/%d processed (%d updated)",
            i // EPSS_BATCH_SIZE + 1,
            (len(cve_ids) // EPSS_BATCH_SIZE) + 1,
            len(scores),
        )

    # After EPSS update, re-run matcher for every CVE whose EPSS values changed.
    # Limiting this to "high EPSS only" leaves stale priority scores behind.
    from app.tasks.matcher import queue_matcher_for_cves
    rematch_cve_ids = list(dict.fromkeys(updated_cve_ids))

    if rematch_cve_ids:
        matcher_queue = queue_matcher_for_cves(rematch_cve_ids, reason="EPSS rematch")

    result = {
        "cves_processed": len(cve_ids),
        "updated": total_updated,
        "errors": total_errors,
        "matcher_queue": matcher_queue,
    }

    # Only claim success when every batch landed. This previously reported
    # "success" unconditionally, so the 414 failures above stayed invisible on
    # the diagnostics dashboard while no CVE ever received an EPSS score.
    failed = total_errors > 0
    error_message = (
        f"{total_errors} of {len(cve_ids)} CVEs could not be scored "
        f"({total_updated} updated)"
    ) if failed else None
    finish_sync_run(
        run_id,
        status="failed" if failed else "success",
        details=result,
        error_message=error_message,
    )
    log_structured_event(
        logger,
        logging.ERROR if failed else logging.INFO,
        "epss_sync_finished",
        run_id=run_id,
        **result,
    )
    logger.info("EPSS sync complete: %s", result)
    return result


def _fetch_epss_batch(cve_ids: list[str]) -> list[tuple[str, float, float]]:
    """Fetch EPSS scores for a batch of CVE IDs from FIRST.org API.

    Returns list of (cve_id, epss_score, epss_percentile) tuples.

    Splits the batch if the request URL would approach the length at which the
    API starts returning empty results instead of an error (see the constants
    above). `limit` is always sent explicitly, otherwise the API caps the
    response at 100 rows and drops the remainder without saying so.
    """
    if not cve_ids:
        return []

    # API supports ?cve=CVE-1,CVE-2,... (comma-separated)
    params = {"cve": ",".join(cve_ids), "limit": len(cve_ids)}

    approx_url_len = len(settings.EPSS_URL) + len(params["cve"]) + 32
    if approx_url_len > EPSS_MAX_URL_BYTES and len(cve_ids) > 1:
        mid = len(cve_ids) // 2
        return _fetch_epss_batch(cve_ids[:mid]) + _fetch_epss_batch(cve_ids[mid:])

    with httpx.Client(timeout=60.0) as client:
        response = client.get(settings.EPSS_URL, params=params)
        response.raise_for_status()
        data = response.json()

    results = []
    for item in data.get("data", []):
        cve_id = item.get("cve")
        epss = item.get("epss")
        percentile = item.get("percentile")
        if cve_id and epss is not None:
            results.append((cve_id, float(epss), float(percentile) if percentile else None))

    return results
