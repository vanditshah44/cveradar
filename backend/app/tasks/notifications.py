"""
notifications.py — Email notification tasks.

Two types of notifications:
  1. Instant KEV alert: when a CVE is added to CISA KEV and matches a user's stack
     → send within 1 hour, regardless of daily_digest preference
     → only if user has instant_alerts=True

  2. Daily digest: summary of all new CVEs from last 24h affecting user's stack
     → sent every morning (Celery beat schedule)
     → only if user has daily_digest=True
     → only if there are new unseen matches

Both use the shared email delivery layer, which can either send via Resend
or write local preview files in development.
"""
import logging
from hashlib import sha256
from datetime import datetime, timedelta, timezone

from celery import shared_task
from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.database import SyncSessionLocal
from app.models.match import UserCveMatch
from app.models.notification import Notification
from app.models.user import User
from app.models.cve import Cve
from app.services.notification_email import build_daily_digest_email, build_kev_alert_email
from app.services.structured_logging import log_structured_event

logger = logging.getLogger(__name__)


def _normalize_cve_ids(cve_ids: list[str]) -> list[str]:
    """Return a stable, deduplicated CVE list for logging and idempotency."""
    return sorted(dict.fromkeys(cve_ids))


def _candidate_user_ids_for_kev_matches(matches: list[UserCveMatch]) -> list:
    """Return one user id per logical KEV notification target."""
    return sorted({match.user_id for match in matches}, key=str)


def _candidate_daily_digest_matches(matches: list[UserCveMatch], cutoff: datetime) -> list[UserCveMatch]:
    """Filter raw matches down to the ones eligible for a daily digest."""
    return [
        match
        for match in matches
        if match.seen_at is None
        and match.dismissed is False
        and match.matched_at >= cutoff
    ]


def _build_notification_idempotency_key(
    notification_type: str,
    user_id,
    cve_ids: list[str],
    *,
    digest_bucket: str | None = None,
) -> str:
    """Build a stable idempotency key for a logical notification."""
    normalized_cve_ids = _normalize_cve_ids(cve_ids)

    if notification_type == "instant_kev" and len(normalized_cve_ids) == 1:
        return f"{notification_type}:{user_id}:{normalized_cve_ids[0]}"

    payload = ",".join(normalized_cve_ids).encode("utf-8")
    cve_hash = sha256(payload).hexdigest()[:16]

    if notification_type == "daily_digest":
        bucket = digest_bucket or datetime.now(timezone.utc).date().isoformat()
        return f"{notification_type}:{user_id}:{bucket}:{cve_hash}"

    return f"{notification_type}:{user_id}:{cve_hash}"


def _claim_notification_attempt(
    db,
    *,
    user_id,
    notification_type: str,
    cve_ids: list[str],
    idempotency_key: str,
):
    """Insert a processing record once so duplicate tasks do not re-send."""
    stmt = (
        pg_insert(Notification)
        .values(
            user_id=user_id,
            notification_type=notification_type,
            idempotency_key=idempotency_key,
            cve_ids=_normalize_cve_ids(cve_ids),
            attempted_at=datetime.now(timezone.utc),
            status="processing",
        )
        .on_conflict_do_nothing(index_elements=["idempotency_key"])
        .returning(Notification.id)
    )
    notification_id = db.execute(stmt).scalar_one_or_none()
    db.commit()
    return notification_id


def _complete_notification_attempt(
    db,
    notification_id,
    *,
    status: str,
    delivery_result: dict | None = None,
    error_message: str | None = None,
) -> None:
    """Finalize a claimed notification attempt with outcome details."""
    notification = db.get(Notification, notification_id)
    if not notification:
        return

    notification.status = status
    notification.delivery_result = delivery_result
    notification.error_message = error_message
    if status in {"sent", "previewed"}:
        notification.sent_at = datetime.now(timezone.utc)

    db.commit()


def _log_notification_attempt(
    *,
    notification_type: str,
    user_id,
    cve_ids: list[str],
    result: str,
    idempotency_key: str,
    extra: str | None = None,
) -> None:
    normalized_cve_ids = _normalize_cve_ids(cve_ids)
    fields = {
        "task_name": (
            "app.tasks.notifications.send_instant_kev_alerts"
            if notification_type == "instant_kev"
            else "app.tasks.notifications.send_daily_digests"
        ),
        "notification_type": notification_type,
        "user_id": user_id,
        "idempotency_key": idempotency_key,
        "result": result,
        "cve_count": len(normalized_cve_ids),
    }
    if len(normalized_cve_ids) == 1:
        fields["cve_id"] = normalized_cve_ids[0]
    else:
        fields["cve_ids"] = normalized_cve_ids
    if extra:
        fields["details"] = extra

    level = logging.ERROR if result == "failed" else logging.INFO
    log_structured_event(logger, level, "notification_attempt", **fields)


def _notification_status_from_delivery_state(delivery_state: str) -> str:
    if delivery_state == "sent":
        return "sent"
    if delivery_state == "preview":
        return "previewed"
    return "skipped"


def _user_received_email_in_last_24h(db, user_id) -> bool:
    """Return True if this user already received ANY email in the past 24 hours.

    This is the global SMTP abuse guard: no matter how many CVEs or tasks
    fire, each user gets at most one email per 24-hour window.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    result = db.execute(
        select(Notification.id)
        .where(
            and_(
                Notification.user_id == user_id,
                Notification.status.in_(["sent", "previewed"]),
                Notification.sent_at >= cutoff,
            )
        )
        .limit(1)
    ).scalar_one_or_none()
    return result is not None


@shared_task(name="app.tasks.notifications.send_instant_kev_alerts")
def send_instant_kev_alerts(cve_ids: list[str]) -> dict:
    """Send instant email alerts for newly KEV-flagged CVEs.

    For each CVE in the list, find all users who:
    - Have this CVE in user_cve_matches (i.e., it affects their stack)
    - Have instant_alerts=True
    - Haven't received a KEV alert for this CVE already

    Then send one email per user (batching multiple KEV CVEs if needed).
    """
    sent_count = 0
    skipped_duplicate = 0
    previewed_count = 0
    skipped_delivery = 0
    errors = 0

    with SyncSessionLocal() as db:
        for cve_id in _normalize_cve_ids(cve_ids):
            cve = db.get(Cve, cve_id)
            if not cve:
                continue

            # Find affected users
            matches = (
                db.execute(
                    select(UserCveMatch)
                    .join(User)
                    .where(
                        UserCveMatch.cve_id == cve_id,
                        UserCveMatch.dismissed == False,  # noqa: E712
                        User.instant_alerts == True,       # noqa: E712
                    )
                ).scalars().all()
            )

            user_ids_to_notify = _candidate_user_ids_for_kev_matches(matches)

            for user_id in user_ids_to_notify:
                user = db.get(User, user_id)
                if not user:
                    continue

                # Hard rate limit: 1 email per user per 24 hours
                if _user_received_email_in_last_24h(db, user_id):
                    _log_notification_attempt(
                        notification_type="instant_kev",
                        user_id=user_id,
                        cve_ids=[cve_id],
                        result="skipped_rate_limited",
                        idempotency_key=f"rate_limited:{user_id}:{cve_id}",
                    )
                    continue

                normalized_cve_ids = [cve_id]
                idempotency_key = _build_notification_idempotency_key(
                    "instant_kev",
                    user_id,
                    normalized_cve_ids,
                )
                notification_id = _claim_notification_attempt(
                    db,
                    user_id=user_id,
                    notification_type="instant_kev",
                    cve_ids=normalized_cve_ids,
                    idempotency_key=idempotency_key,
                )
                if notification_id is None:
                    skipped_duplicate += 1
                    _log_notification_attempt(
                        notification_type="instant_kev",
                        user_id=user_id,
                        cve_ids=normalized_cve_ids,
                        result="skipped_duplicate",
                        idempotency_key=idempotency_key,
                    )
                    continue

                try:
                    delivery_result = _send_kev_alert_email(db, user, cve)
                    delivery_state = delivery_result.get("delivery_state", "sent")
                    status = _notification_status_from_delivery_state(delivery_state)
                    _complete_notification_attempt(
                        db,
                        notification_id,
                        status=status,
                        delivery_result=delivery_result,
                    )
                    _log_notification_attempt(
                        notification_type="instant_kev",
                        user_id=user_id,
                        cve_ids=normalized_cve_ids,
                        result=status,
                        idempotency_key=idempotency_key,
                        extra=delivery_state,
                    )
                    if status == "sent":
                        sent_count += 1
                    elif status == "previewed":
                        previewed_count += 1
                    else:
                        skipped_delivery += 1
                except Exception as e:
                    log_structured_event(
                        logger,
                        logging.ERROR,
                        "notification_delivery_failed",
                        task_name="app.tasks.notifications.send_instant_kev_alerts",
                        notification_type="instant_kev",
                        user_id=user_id,
                        cve_id=cve_id,
                        error=str(e),
                        error_type=type(e).__name__,
                    )
                    _complete_notification_attempt(
                        db,
                        notification_id,
                        status="failed",
                        error_message=str(e),
                        delivery_result={"delivery_state": "failed"},
                    )
                    _log_notification_attempt(
                        notification_type="instant_kev",
                        user_id=user_id,
                        cve_ids=normalized_cve_ids,
                        result="failed",
                        idempotency_key=idempotency_key,
                        extra=str(e),
                    )
                    errors += 1

    return {
        "sent": sent_count,
        "previewed": previewed_count,
        "skipped_duplicate": skipped_duplicate,
        "skipped_delivery": skipped_delivery,
        "errors": errors,
    }


@shared_task(name="app.tasks.notifications.send_daily_digests")
def send_daily_digests() -> dict:
    """Send daily digest emails to all eligible users.

    Scheduled by Celery beat (morning send time configured in celery_app.py).
    """
    sent_count = 0
    skipped_no_new = 0
    skipped_duplicate = 0
    previewed_count = 0
    skipped_delivery = 0
    errors = 0

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    digest_bucket = now.date().isoformat()

    with SyncSessionLocal() as db:
        users = db.execute(
            select(User).where(User.daily_digest == True)  # noqa: E712
        ).scalars().all()

        for user in users:
            # Find new matches from last 24 hours that user hasn't seen
            raw_matches = (
                db.execute(
                    select(UserCveMatch)
                    .join(Cve)
                    .where(
                        UserCveMatch.user_id == user.id,
                        UserCveMatch.seen_at == None,       # noqa: E711
                        UserCveMatch.dismissed == False,    # noqa: E712
                        UserCveMatch.matched_at >= cutoff,
                    )
                    .order_by(UserCveMatch.priority_score.desc())
                ).scalars().all()
            )
            new_matches = _candidate_daily_digest_matches(raw_matches, cutoff)

            if not new_matches:
                skipped_no_new += 1
                continue

            # Hard rate limit: 1 email per user per 24 hours
            if _user_received_email_in_last_24h(db, user.id):
                skipped_no_new += 1
                continue

            cve_ids = _normalize_cve_ids([m.cve_id for m in new_matches])
            cves = {c.cve_id: c for c in db.execute(
                select(Cve).where(Cve.cve_id.in_(cve_ids))
            ).scalars().all()}
            idempotency_key = _build_notification_idempotency_key(
                "daily_digest",
                user.id,
                cve_ids,
                digest_bucket=digest_bucket,
            )
            notification_id = _claim_notification_attempt(
                db,
                user_id=user.id,
                notification_type="daily_digest",
                cve_ids=cve_ids,
                idempotency_key=idempotency_key,
            )
            if notification_id is None:
                skipped_duplicate += 1
                _log_notification_attempt(
                    notification_type="daily_digest",
                    user_id=user.id,
                    cve_ids=cve_ids,
                    result="skipped_duplicate",
                    idempotency_key=idempotency_key,
                )
                continue

            try:
                delivery_result = _send_digest_email(db, user, new_matches, cves)
                delivery_state = delivery_result.get("delivery_state", "sent")
                status = _notification_status_from_delivery_state(delivery_state)
                _complete_notification_attempt(
                    db,
                    notification_id,
                    status=status,
                    delivery_result=delivery_result,
                )
                _log_notification_attempt(
                    notification_type="daily_digest",
                    user_id=user.id,
                    cve_ids=cve_ids,
                    result=status,
                    idempotency_key=idempotency_key,
                    extra=delivery_state,
                )
                if status == "sent":
                    sent_count += 1
                elif status == "previewed":
                    previewed_count += 1
                else:
                    skipped_delivery += 1
            except Exception as e:
                log_structured_event(
                    logger,
                    logging.ERROR,
                    "notification_delivery_failed",
                    task_name="app.tasks.notifications.send_daily_digests",
                    notification_type="daily_digest",
                    user_id=user.id,
                    cve_ids=cve_ids,
                    error=str(e),
                    error_type=type(e).__name__,
                )
                _complete_notification_attempt(
                    db,
                    notification_id,
                    status="failed",
                    error_message=str(e),
                    delivery_result={"delivery_state": "failed"},
                )
                _log_notification_attempt(
                    notification_type="daily_digest",
                    user_id=user.id,
                    cve_ids=cve_ids,
                    result="failed",
                    idempotency_key=idempotency_key,
                    extra=str(e),
                )
                errors += 1

    return {
        "sent": sent_count,
        "previewed": previewed_count,
        "skipped_no_new": skipped_no_new,
        "skipped_duplicate": skipped_duplicate,
        "skipped_delivery": skipped_delivery,
        "errors": errors,
    }


def _send_kev_alert_email(db, user: User, cve: Cve) -> dict:
    """Send a KEV instant alert email via Resend."""
    from app.services.email import send_email

    subject, body = build_kev_alert_email(db, user, cve)
    return send_email(to=user.email, subject=subject, html=body)


def _send_digest_email(db, user: User, matches: list, cves: dict) -> dict:
    """Send daily digest email via Resend."""
    from app.services.email import send_email

    subject, body = build_daily_digest_email(db, user, matches, cves)
    return send_email(to=user.email, subject=subject, html=body)
