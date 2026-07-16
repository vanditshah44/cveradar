"""
email.py — Email sending via SMTP (Etheron / any shared mail host).

Supports three delivery modes (EMAIL_DELIVERY_MODE env var):
  auto    → use SMTP if SMTP_HOST is set, otherwise write preview files
  smtp    → always send via SMTP (fails loudly if misconfigured)
  preview → always write local HTML preview files (dev / CI)

Rate-limiting note: a hard 1-email-per-user-per-24h guard lives in the
notification tasks, not here. This module only handles the wire-level send.
"""
import logging
import smtplib
import ssl
import re
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)


def _resolve_delivery_mode() -> str:
    mode = settings.EMAIL_DELIVERY_MODE.strip().lower()
    if mode == "auto":
        return "smtp" if settings.SMTP_HOST else "preview"
    if mode in {"smtp", "preview"}:
        return mode
    raise ValueError(f"Unsupported EMAIL_DELIVERY_MODE: {settings.EMAIL_DELIVERY_MODE!r}")


def _slugify_subject(subject: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", subject.lower()).strip("-")
    return slug[:80] or "email-preview"


def write_email_preview(to: str, subject: str, html: str) -> str:
    """Write a local HTML preview file; returns the file path."""
    preview_dir = Path(settings.EMAIL_PREVIEW_DIR)
    preview_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    preview_path = preview_dir / f"{timestamp}_{_slugify_subject(subject)}.html"
    wrapped = f"""<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>{escape(subject)}</title></head>
  <body style="margin:0;background:#f8fafc;">
    <div style="max-width:680px;margin:24px auto;padding:16px 20px;background:#fff;
                border:1px solid #e2e8f0;border-radius:12px;font-family:system-ui,sans-serif;">
      <p style="margin:0 0 6px;color:#0f172a;font-size:14px;"><strong>To:</strong> {escape(to)}</p>
      <p style="margin:0 0 18px;color:#0f172a;font-size:14px;"><strong>Subject:</strong> {escape(subject)}</p>
      <hr style="border:none;border-top:1px solid #e2e8f0;margin:0 0 20px;">
      {html}
    </div>
  </body>
</html>"""
    preview_path.write_text(wrapped, encoding="utf-8")
    logger.info("email_preview_written to=%s subject=%r path=%s", to, subject, preview_path)
    return str(preview_path)


def _send_via_smtp(to: str, subject: str, html: str) -> None:
    """Send a single email via SMTP. Raises on any delivery error."""
    if not settings.SMTP_HOST:
        raise RuntimeError("SMTP_HOST is not configured — cannot send email")
    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        raise RuntimeError("SMTP_USER / SMTP_PASSWORD are not configured")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.FROM_EMAIL
    msg["To"] = to
    # Attach HTML part
    msg.attach(MIMEText(html, "html", "utf-8"))

    ctx = ssl.create_default_context()

    if settings.SMTP_USE_SSL:
        # Port 465 — wrap the connection in SSL from the start
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=ctx) as server:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, [to], msg.as_string())
    else:
        # Port 587 — plain connection, then upgrade with STARTTLS
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, [to], msg.as_string())


def send_email(to: str, subject: str, html: str) -> dict:
    """Send a transactional email.

    Returns a dict describing what happened (for audit logging).
    Raises on hard delivery failures so the caller can log/retry.
    """
    mode = _resolve_delivery_mode()

    if mode == "preview":
        path = write_email_preview(to=to, subject=subject, html=html)
        return {"provider": "preview", "delivery_state": "preview", "preview_path": path}

    # mode == "smtp"
    _send_via_smtp(to=to, subject=subject, html=html)
    logger.info("email_sent provider=smtp to=%s subject=%r", to, subject)
    return {"provider": "smtp", "delivery_state": "sent"}
