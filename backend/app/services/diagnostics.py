"""
diagnostics.py — operational health and pipeline snapshot helpers.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from redis import Redis
from sqlalchemy import func, select, text

from app.config import settings
from app.database import SyncSessionLocal
from app.models.cve import Cve
from app.models.match import UserCveMatch
from app.models.notification import Notification
from app.services.observability import collect_runtime_warnings
from app.services.sync_runs import latest_sync_statuses
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

BEAT_HEARTBEAT_KEY = "diagnostics:beat_heartbeat"
BEAT_HEARTBEAT_MAX_AGE_SECONDS = 180
BEAT_HEARTBEAT_TTL_SECONDS = 600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _redis_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


def evaluate_beat_heartbeat(
    recorded_at: datetime | None,
    *,
    now: datetime | None = None,
    max_age_seconds: int = BEAT_HEARTBEAT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Classify beat health from the last known heartbeat timestamp."""
    now = now or _utcnow()

    if recorded_at is None:
        return {
            "ok": False,
            "status": "missing",
            "last_heartbeat_at": None,
            "age_seconds": None,
        }

    age_seconds = max(0, int((now - recorded_at).total_seconds()))
    return {
        "ok": age_seconds <= max_age_seconds,
        "status": "ok" if age_seconds <= max_age_seconds else "stale",
        "last_heartbeat_at": recorded_at.isoformat(),
        "age_seconds": age_seconds,
    }


def _latest_nvd_success(sync_statuses: dict[str, dict[str, Any]]) -> str | None:
    candidates = [
        sync_statuses.get("nvd_incremental", {}).get("last_success_at"),
        sync_statuses.get("nvd_full", {}).get("last_success_at"),
    ]
    candidates = [candidate for candidate in candidates if candidate]
    return max(candidates) if candidates else None


def check_database_health() -> dict[str, Any]:
    try:
        with SyncSessionLocal() as db:
            db.execute(text("SELECT 1"))
        return {"ok": True, "status": "ok"}
    except Exception as exc:
        return {"ok": False, "status": "down", "error": str(exc)}


def check_redis_health() -> dict[str, Any]:
    client = None
    try:
        client = _redis_client()
        ping_result = bool(client.ping())
        return {"ok": ping_result, "status": "ok" if ping_result else "down"}
    except Exception as exc:
        return {"ok": False, "status": "down", "error": str(exc)}
    finally:
        if client is not None:
            client.close()


def check_celery_worker_health() -> dict[str, Any]:
    try:
        inspect = celery_app.control.inspect(timeout=1.0)
        response = inspect.ping() or {}
        workers = sorted(response.keys()) if isinstance(response, dict) else []
        return {
            "ok": bool(workers),
            "status": "ok" if workers else "down",
            "workers": workers,
        }
    except Exception as exc:
        return {"ok": False, "status": "down", "error": str(exc), "workers": []}


def check_celery_beat_health() -> dict[str, Any]:
    client = None
    try:
        client = _redis_client()
        raw = client.get(BEAT_HEARTBEAT_KEY)
        if not raw:
            return evaluate_beat_heartbeat(None)

        payload = json.loads(raw)
        recorded_at_raw = payload.get("recorded_at")
        recorded_at = datetime.fromisoformat(recorded_at_raw) if recorded_at_raw else None
        result = evaluate_beat_heartbeat(recorded_at)
        result["heartbeat"] = payload
        return result
    except Exception as exc:
        return {"ok": False, "status": "down", "error": str(exc)}
    finally:
        if client is not None:
            client.close()


def collect_readiness_status() -> dict[str, Any]:
    """Return readiness state for core local services."""
    checked_at = _utcnow().isoformat()
    components = {
        "api": {"ok": True, "status": "ok"},
        "database": check_database_health(),
        "redis": check_redis_health(),
        "celery_worker": check_celery_worker_health(),
    }

    if components["redis"]["ok"]:
        components["celery_beat"] = check_celery_beat_health()
    else:
        components["celery_beat"] = {
            "ok": False,
            "status": "unknown",
            "error": "Redis is unavailable, so beat heartbeat cannot be checked.",
        }

    overall_ok = all(component.get("ok", False) for component in components.values())
    return {
        "status": "ready" if overall_ok else "degraded",
        "ok": overall_ok,
        "checked_at": checked_at,
        "components": components,
    }


def collect_pipeline_state() -> dict[str, Any]:
    """Return a compact debug snapshot of the data pipeline state."""
    snapshot = {
        "checked_at": _utcnow().isoformat(),
        "services": collect_readiness_status(),
        "status": "ok",
        "warnings": collect_runtime_warnings("api"),
    }

    try:
        sync_statuses = latest_sync_statuses()

        with SyncSessionLocal() as db:
            cve_count = db.execute(select(func.count(Cve.cve_id))).scalar_one()
            match_count = db.execute(select(func.count(UserCveMatch.id))).scalar_one()
            notification_count = db.execute(select(func.count(Notification.id))).scalar_one()
    except Exception as exc:
        snapshot["status"] = "error"
        snapshot["error"] = str(exc)
        snapshot["syncs"] = {}
        snapshot["counts"] = {
            "cves": None,
            "matches": None,
            "notifications": None,
        }
        snapshot["last_nvd_sync_at"] = None
        snapshot["last_nvd_incremental_sync_at"] = None
        snapshot["last_nvd_full_sync_at"] = None
        snapshot["last_kev_sync_at"] = None
        snapshot["last_epss_sync_at"] = None
        return snapshot

    snapshot["syncs"] = {
        "nvd_incremental": sync_statuses.get("nvd_incremental"),
        "nvd_full": sync_statuses.get("nvd_full"),
        "kev_sync": sync_statuses.get("kev_sync"),
        "epss_sync": sync_statuses.get("epss_sync"),
        "match_rebuild_all": sync_statuses.get("match_rebuild_all"),
    }
    snapshot["last_nvd_sync_at"] = _latest_nvd_success(sync_statuses)
    snapshot["last_nvd_incremental_sync_at"] = sync_statuses.get("nvd_incremental", {}).get("last_success_at")
    snapshot["last_nvd_full_sync_at"] = sync_statuses.get("nvd_full", {}).get("last_success_at")
    snapshot["last_kev_sync_at"] = sync_statuses.get("kev_sync", {}).get("last_success_at")
    snapshot["last_epss_sync_at"] = sync_statuses.get("epss_sync", {}).get("last_success_at")
    snapshot["counts"] = {
        "cves": cve_count,
        "matches": match_count,
        "notifications": notification_count,
    }
    return snapshot
