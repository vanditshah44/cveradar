"""
diagnostics.py — periodic operational heartbeat tasks.
"""
import json
import logging
from datetime import datetime, timezone

from celery import shared_task
from redis import Redis

from app.config import settings
from app.services.diagnostics import BEAT_HEARTBEAT_KEY, BEAT_HEARTBEAT_TTL_SECONDS
from app.services.structured_logging import log_structured_event

logger = logging.getLogger(__name__)


@shared_task(name="app.tasks.diagnostics.record_beat_heartbeat", bind=True)
def record_beat_heartbeat(self) -> dict:
    """Write a beat heartbeat so the API can detect stale schedulers."""
    recorded_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "recorded_at": recorded_at,
        "task_id": getattr(self.request, "id", None),
        "hostname": getattr(self.request, "hostname", None),
    }

    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.set(BEAT_HEARTBEAT_KEY, json.dumps(payload), ex=BEAT_HEARTBEAT_TTL_SECONDS)
    finally:
        client.close()

    log_structured_event(logger, logging.INFO, "beat_heartbeat_recorded", **payload)
    return payload
