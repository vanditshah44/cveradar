"""
Preview or test-send notification emails using real database data.

Examples:
  python scripts/notification_email_preview.py instant-kev --user-email alice@example.com --cve-id CVE-2024-1234
  python scripts/notification_email_preview.py daily-digest --user-email alice@example.com
  python scripts/notification_email_preview.py instant-kev --user-email alice@example.com --cve-id CVE-2024-1234 --send
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SyncSessionLocal
from app.models.cve import Cve
from app.models.match import UserCveMatch
from app.models.user import User
from app.services.email import send_email, write_email_preview
from app.services.notification_email import build_daily_digest_email, build_kev_alert_email


def _get_user_by_email(db, email: str) -> User:
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        raise SystemExit(f"User not found: {email}")
    return user


def _load_digest_matches(db, user: User, *, hours: int, include_seen: bool) -> list[UserCveMatch]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    stmt = (
        select(UserCveMatch)
        .join(Cve)
        .where(
            UserCveMatch.user_id == user.id,
            UserCveMatch.dismissed == False,  # noqa: E712
            UserCveMatch.matched_at >= cutoff,
        )
        .order_by(UserCveMatch.priority_score.desc())
    )
    if not include_seen:
        stmt = stmt.where(UserCveMatch.seen_at == None)  # noqa: E711

    matches = db.execute(stmt).scalars().all()
    if not matches:
        raise SystemExit(
            f"No digest-eligible matches found for {user.email} in the last {hours} hours."
        )
    return matches


def _preview_or_send(*, recipient: str, subject: str, html: str, send: bool) -> None:
    if send:
        result = send_email(to=recipient, subject=subject, html=html)
        print(result)
        return

    preview_path = write_email_preview(to=recipient, subject=subject, html=html)
    print(
        {
            "recipient": recipient,
            "subject": subject,
            "preview_path": preview_path,
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Preview or test-send KEV and daily digest notification emails."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    kev_parser = subparsers.add_parser("instant-kev", help="Preview or send a KEV alert email.")
    kev_parser.add_argument("--user-email", required=True, help="User email to render the notification for.")
    kev_parser.add_argument("--cve-id", required=True, help="CVE to render.")
    kev_parser.add_argument("--to", help="Override the recipient email address.")
    kev_parser.add_argument(
        "--send",
        action="store_true",
        help="Use the configured email delivery mode instead of always writing a preview file.",
    )

    digest_parser = subparsers.add_parser("daily-digest", help="Preview or send a daily digest email.")
    digest_parser.add_argument("--user-email", required=True, help="User email to render the notification for.")
    digest_parser.add_argument("--to", help="Override the recipient email address.")
    digest_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="How far back to look for digest matches. Defaults to 24.",
    )
    digest_parser.add_argument(
        "--include-seen",
        action="store_true",
        help="Include matches that are already marked seen.",
    )
    digest_parser.add_argument(
        "--send",
        action="store_true",
        help="Use the configured email delivery mode instead of always writing a preview file.",
    )

    args = parser.parse_args()

    with SyncSessionLocal() as db:
        user = _get_user_by_email(db, args.user_email)
        recipient = args.to or user.email

        if args.command == "instant-kev":
            cve = db.get(Cve, args.cve_id)
            if not cve:
                raise SystemExit(f"CVE not found: {args.cve_id}")

            matches = db.execute(
                select(UserCveMatch).where(
                    UserCveMatch.user_id == user.id,
                    UserCveMatch.cve_id == cve.cve_id,
                    UserCveMatch.dismissed == False,  # noqa: E712
                )
            ).scalars().all()
            if not matches:
                raise SystemExit(
                    f"User {user.email} does not currently have a match for {cve.cve_id}."
                )

            subject, html = build_kev_alert_email(db, user, cve)
            _preview_or_send(recipient=recipient, subject=subject, html=html, send=args.send)
            return

        matches = _load_digest_matches(
            db,
            user,
            hours=args.hours,
            include_seen=args.include_seen,
        )
        cve_ids = sorted({match.cve_id for match in matches})
        cves = {
            cve.cve_id: cve
            for cve in db.execute(select(Cve).where(Cve.cve_id.in_(cve_ids))).scalars().all()
        }
        subject, html = build_daily_digest_email(db, user, matches, cves)
        _preview_or_send(recipient=recipient, subject=subject, html=html, send=args.send)


if __name__ == "__main__":
    main()
