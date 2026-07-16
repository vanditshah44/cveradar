"""
matching.py — Matching service called from API routes.

When a user adds a stack item via the API, we need to immediately trigger
matching so their dashboard populates. This is a thin wrapper that calls
the Celery task asynchronously — the user doesn't wait for matching to finish.
"""
from dataclasses import dataclass
import logging

from app.tasks.matcher import run_matcher_for_user
from app.services.structured_logging import log_structured_event

logger = logging.getLogger(__name__)


@dataclass
class MatchDispatchResult:
    queued: bool
    message: str | None = None


def trigger_matching_for_user(user_id: str) -> MatchDispatchResult:
    """Enqueue a matching job for a user.

    The API should still succeed if Redis/Celery is temporarily unavailable.
    In that case we return a warning so the caller can surface a non-blocking
    message to the user.
    """
    task_name = "app.tasks.matcher.run_matcher_for_user"
    try:
        run_matcher_for_user.delay(str(user_id))
    except Exception as exc:
        log_structured_event(
            logger,
            logging.WARNING,
            "matcher_dispatch_failed",
            service="api",
            task_name=task_name,
            user_id=user_id,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return MatchDispatchResult(
            queued=False,
            message=(
                "Saved successfully, but background CVE matching could not be queued right now. "
                "Your dashboard may update after the worker reconnects or after the next sync."
            ),
        )

    log_structured_event(
        logger,
        logging.INFO,
        "matcher_dispatched",
        service="api",
        task_name=task_name,
        user_id=user_id,
    )
    return MatchDispatchResult(
        queued=True,
        message=(
            "Saved successfully. CVE matching is now running in the background. "
            "Your dashboard should start updating shortly."
        ),
    )
