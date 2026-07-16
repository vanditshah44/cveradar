#!/usr/bin/env python3
"""
init_db.py — One-time database initialisation + catalog seed.

Run this ONCE after deploying to create all tables and load the product catalog.
Safe to re-run — migrations are idempotent and catalog upserts won't duplicate.

Usage:
  python3 scripts/init_db.py

What it does:
  1. Runs Alembic migrations (creates all tables)
  2. Seeds the product_catalog table from data/seed/product_catalog.json
"""
import sys
import os
import logging
import subprocess

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPTS_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

sys.path.insert(0, BACKEND_DIR)
os.chdir(BACKEND_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("init_db")


def run_migrations() -> None:
    logger.info("Running Alembic migrations...")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.error("Migration failed:\n%s", result.stderr)
        sys.exit(1)
    logger.info("Migrations complete:\n%s", result.stdout or "(no output)")


def seed_catalog() -> None:
    logger.info("Seeding product catalog...")
    seed_script = os.path.join(PROJECT_ROOT, "scripts", "seed_catalog.py")
    if not os.path.exists(seed_script):
        logger.warning("seed_catalog.py not found — skipping catalog seed")
        return

    result = subprocess.run(
        [sys.executable, seed_script],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
        env={**os.environ},
    )
    if result.returncode != 0:
        logger.error("Catalog seed failed:\n%s", result.stderr)
    else:
        logger.info("Catalog seed done:\n%s", result.stdout or "(no output)")


def trigger_first_sync() -> None:
    """Optionally kick off the first NVD sync right now."""
    answer = input("\nRun first NVD sync now? This downloads ~250k CVEs (takes 15-30 min). [y/N] ").strip().lower()
    if answer != "y":
        logger.info("Skipping first sync. Run scripts/cron_hourly.py manually when ready.")
        return

    logger.info("Starting first NVD full sync (this will take a while)...")
    # Set up the same path/env as cron scripts
    from app.tasks.celery_app import celery_app
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True

    from app.tasks.nvd_sync import sync_nvd_full
    result = sync_nvd_full()
    logger.info("First sync complete: %s", result)


if __name__ == "__main__":
    run_migrations()
    seed_catalog()
    logger.info("\n=== Database initialized successfully ===")
    logger.info("Next steps:")
    logger.info("  1. Start your Python app in DirectAdmin (points to backend/passenger_wsgi.py)")
    logger.info("  2. Start your Node.js app in DirectAdmin (runs: npm start in frontend/)")
    logger.info("  3. Add cron jobs in DirectAdmin Cron Manager (see scripts/cron_hourly.py header)")
    trigger_first_sync()
