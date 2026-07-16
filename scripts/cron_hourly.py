#!/usr/bin/env python3
"""
cron_hourly.py — Run every hour via DirectAdmin Cron Manager.

What it does:
  1. NVD incremental sync  (CVEs modified in last 2 hours)
  2. KEV sync              (CISA known-exploited list)
  3. Matcher               (finds which users are affected by updated CVEs)

Celery is set to task_always_eager=True so all .delay() calls run
synchronously in this process — no broker / Redis task queue needed.

DirectAdmin Cron setup:
  Command:  /home/USERNAME/.local/bin/python3 /home/USERNAME/cve-radar/scripts/cron_hourly.py >> /home/USERNAME/logs/cve-hourly.log 2>&1
  Schedule: Every hour  (minute: 5, hour: *, day: *, month: *, weekday: *)
"""
import sys
import os
import logging
import time

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
logger = logging.getLogger("cron_hourly")

# ── Celery eager mode — run tasks in-process, no broker connection needed ─────
from app.tasks.celery_app import celery_app  # noqa: E402
celery_app.conf.task_always_eager = True
celery_app.conf.task_eager_propagates = True  # surface exceptions instead of swallowing

# ── Task imports ──────────────────────────────────────────────────────────────
from app.tasks.nvd_sync import sync_nvd_incremental  # noqa: E402
from app.tasks.kev_sync import sync_kev              # noqa: E402


def main() -> None:
    start = time.monotonic()
    logger.info("=== Hourly sync starting ===")

    # 1. NVD sync (also triggers matcher internally via task_always_eager)
    try:
        result = sync_nvd_incremental()
        logger.info("NVD sync done: %s", result)
    except Exception as exc:
        logger.error("NVD sync failed: %s", exc, exc_info=True)

    # 2. KEV sync
    try:
        result = sync_kev()
        logger.info("KEV sync done: %s", result)
    except Exception as exc:
        logger.error("KEV sync failed: %s", exc, exc_info=True)

    elapsed = time.monotonic() - start
    logger.info("=== Hourly sync finished in %.1fs ===", elapsed)


if __name__ == "__main__":
    main()
