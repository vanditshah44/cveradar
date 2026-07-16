"""
celery_app.py — Celery application instance + beat schedule.

Celery has two components:
  1. The worker: executes tasks
  2. Beat: the scheduler that fires tasks on a schedule

Beat sends a message to Redis like "run nvd_sync now".
The worker picks it up from Redis and runs it.

Schedule:
  NVD sync   — every hour (incremental, ~5 minutes of changes)
  KEV sync   — every hour (CISA updates the list throughout the day)
  EPSS sync  — daily at 2am UTC (EPSS updates once per day)
  Matcher    — 10 minutes after NVD/KEV sync completes (triggered by the tasks themselves)
"""
from celery import Celery
from celery.schedules import crontab
from celery.signals import beat_init, celeryd_init

from app.config import settings
from app.services.observability import (
    configure_application_logging,
    init_sentry,
    log_runtime_warnings,
    register_celery_observability,
)

configure_application_logging()
register_celery_observability()

celery_app = Celery(
    "cve_radar",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.tasks.nvd_sync",
        "app.tasks.kev_sync",
        "app.tasks.epss_sync",
        "app.tasks.matcher",
        "app.tasks.notifications",
        "app.tasks.diagnostics",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Retry failed tasks up to 3 times with exponential backoff
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Prevent tasks from running forever (NVD sync should finish in <10 min)
    task_time_limit=600,        # hard kill after 10 minutes
    task_soft_time_limit=540,   # send SIGTERM after 9 minutes
)

celery_app.conf.beat_schedule = {
    # NVD incremental sync — runs every hour, fetches CVEs modified in the last 2 hours
    "nvd-sync-hourly": {
        "task": "app.tasks.nvd_sync.sync_nvd_incremental",
        "schedule": crontab(minute="5"),  # :05 past every hour
    },
    # CISA KEV sync — hourly
    "kev-sync-hourly": {
        "task": "app.tasks.kev_sync.sync_kev",
        "schedule": crontab(minute="15"),  # :15 past every hour
    },
    # EPSS sync — daily at 2am UTC (scores update once per day)
    "epss-sync-daily": {
        "task": "app.tasks.epss_sync.sync_epss",
        "schedule": crontab(hour="2", minute="0"),
    },
    # Daily digest — send each morning after overnight feed updates complete
    "daily-digest-morning": {
        "task": "app.tasks.notifications.send_daily_digests",
        "schedule": crontab(hour="7", minute="30"),
    },
    # Beat heartbeat — lets the API detect whether the scheduler is still alive
    "beat-heartbeat": {
        "task": "app.tasks.diagnostics.record_beat_heartbeat",
        "schedule": 60.0,
    },
}


@celeryd_init.connect(weak=False)
def _configure_celery_worker(**kwargs):
    configure_application_logging()
    init_sentry("worker")
    log_runtime_warnings("worker")


@beat_init.connect(weak=False)
def _configure_celery_beat(**kwargs):
    configure_application_logging()
    init_sentry("beat")
    log_runtime_warnings("beat")
