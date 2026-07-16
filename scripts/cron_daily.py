#!/usr/bin/env python3
"""
cron_daily.py — Run once per day via DirectAdmin Cron Manager.

What it does:
  1. EPSS sync      (exploitation probability scores — updates daily)
  2. Daily digest   (email each user their CVE summary)

DirectAdmin Cron setup:
  Command:  /home/USERNAME/.local/bin/python3 /home/USERNAME/cve-radar/scripts/cron_daily.py >> /home/USERNAME/logs/cve-daily.log 2>&1
  Schedule: Daily at 02:00  (minute: 0, hour: 2, day: *, month: *, weekday: *)

  Run digest at 07:30 separately if you want to separate sync from email:
  Command:  /home/USERNAME/.local/bin/python3 /home/USERNAME/cve-radar/scripts/cron_daily.py --digest-only >> /home/USERNAME/logs/cve-digest.log 2>&1
  Schedule: Daily at 07:30 (minute: 30, hour: 7, day: *, month: *, weekday: *)
"""
import sys
import os
import logging
import time
import argparse

# ── Path + environment setup ──────────────────────────────────────────────────
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPTS_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

sys.path.insert(0, BACKEND_DIR)
os.chdir(BACKEND_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("cron_daily")

# ── Celery eager mode ─────────────────────────────────────────────────────────
from app.tasks.celery_app import celery_app  # noqa: E402
celery_app.conf.task_always_eager = True
celery_app.conf.task_eager_propagates = True

from app.tasks.epss_sync import sync_epss                         # noqa: E402
from app.tasks.notifications import send_daily_digests             # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--digest-only", action="store_true", help="Skip EPSS sync, only send digest")
    parser.add_argument("--epss-only", action="store_true", help="Only run EPSS sync")
    args = parser.parse_args()

    start = time.monotonic()
    logger.info("=== Daily tasks starting ===")

    if not args.digest_only:
        try:
            result = sync_epss()
            logger.info("EPSS sync done: %s", result)
        except Exception as exc:
            logger.error("EPSS sync failed: %s", exc, exc_info=True)

    if not args.epss_only:
        try:
            result = send_daily_digests()
            logger.info("Daily digest done: %s", result)
        except Exception as exc:
            logger.error("Daily digest failed: %s", exc, exc_info=True)

    elapsed = time.monotonic() - start
    logger.info("=== Daily tasks finished in %.1fs ===", elapsed)


if __name__ == "__main__":
    main()
