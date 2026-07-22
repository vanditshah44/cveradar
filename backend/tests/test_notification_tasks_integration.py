from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql

from app.models.cve import Cve
from app.models.match import UserCveMatch
from app.models.notification import Notification
from app.models.user import User
from app.tasks import notifications


class ScalarRows:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


class FakeSyncSessionManager:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeNotificationDb:
    def __init__(self, *, users=None, daily_matches=None, kev_matches=None, cves=None,
                 rate_limited_user_ids=None):
        self.users = users or []
        self.daily_matches = daily_matches or {}
        self.kev_matches = kev_matches or {}
        self.cves = cves or {}
        # Users treated as having already received an email in the last 24h.
        self.rate_limited_user_ids = set(rate_limited_user_ids or ())

    def get(self, model, key):
        if model is User:
            return next((user for user in self.users if user.id == key), None)
        if model is Cve:
            return self.cves.get(key)
        return None

    def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        compiled = statement.compile(dialect=postgresql.dialect())
        params = compiled.params
        sql = str(compiled)

        if entity is User:
            return ScalarRows(self.users)

        if entity is UserCveMatch and "JOIN cves" in sql:
            user_id = next(value for key, value in params.items() if key.startswith("user_id"))
            return ScalarRows(self.daily_matches.get(user_id, []))

        if entity is UserCveMatch and "JOIN users" in sql:
            cve_id = next(value for key, value in params.items() if key.startswith("cve_id"))
            return ScalarRows(self.kev_matches.get(cve_id, []))

        if entity is Cve:
            return ScalarRows(list(self.cves.values()))

        # The one-email-per-user-per-24h guard.
        if entity is Notification:
            user_id = next(value for key, value in params.items() if key.startswith("user_id"))
            return ScalarRows([uuid4()] if user_id in self.rate_limited_user_ids else [])

        raise AssertionError(f"Unexpected statement: {statement}")

    def commit(self):
        return None


def test_send_daily_digests_processes_new_matches(monkeypatch):
    now = datetime.now(timezone.utc)
    user = SimpleNamespace(id=uuid4(), email="user@example.com", daily_digest=True)
    match = SimpleNamespace(
        cve_id="CVE-2026-1000",
        user_id=user.id,
        seen_at=None,
        dismissed=False,
        matched_at=now - timedelta(hours=1),
        priority_score=88.0,
    )
    cve = SimpleNamespace(cve_id="CVE-2026-1000")
    db = FakeNotificationDb(
        users=[user],
        daily_matches={user.id: [match]},
        cves={cve.cve_id: cve},
    )

    monkeypatch.setattr(notifications, "SyncSessionLocal", lambda: FakeSyncSessionManager(db))
    monkeypatch.setattr(notifications, "_claim_notification_attempt", lambda *args, **kwargs: uuid4())
    monkeypatch.setattr(notifications, "_complete_notification_attempt", lambda *args, **kwargs: None)
    monkeypatch.setattr(notifications, "_send_digest_email", lambda *args, **kwargs: {"delivery_state": "preview"})

    result = notifications.send_daily_digests()

    assert result["previewed"] == 1
    assert result["errors"] == 0
    assert result["skipped_no_new"] == 0


def _kev_cve(cve_id, cvss=9.0, epss=0.5):
    return SimpleNamespace(
        cve_id=cve_id, cvss_score=cvss, epss_score=epss, kev_flag=True
    )


def test_send_instant_kev_alerts_deduplicates_users_for_same_cve(monkeypatch):
    user = SimpleNamespace(id=uuid4(), email="user@example.com", instant_alerts=True)
    cve = _kev_cve("CVE-2026-2000")
    matches = [
        SimpleNamespace(cve_id=cve.cve_id, user_id=user.id, dismissed=False),
        SimpleNamespace(cve_id=cve.cve_id, user_id=user.id, dismissed=False),
    ]
    db = FakeNotificationDb(
        users=[user],
        kev_matches={cve.cve_id: matches},
        cves={cve.cve_id: cve},
    )

    monkeypatch.setattr(notifications, "SyncSessionLocal", lambda: FakeSyncSessionManager(db))
    monkeypatch.setattr(notifications, "_claim_notification_attempt", lambda *args, **kwargs: uuid4())
    monkeypatch.setattr(notifications, "_complete_notification_attempt", lambda *args, **kwargs: None)
    monkeypatch.setattr(notifications, "_send_kev_alert_email", lambda *args, **kwargs: {"delivery_state": "preview"})

    result = notifications.send_instant_kev_alerts([cve.cve_id])

    assert result["previewed"] == 1
    assert result["skipped_duplicate"] == 0
    assert result["errors"] == 0


def test_send_instant_kev_alerts_batches_multiple_cves_into_one_email(monkeypatch):
    """Several CVEs flagged in one KEV sync must produce ONE email covering all.

    Previously the task looped per CVE, so the one-email-per-24h guard delivered
    the first alert and silently dropped the rest — and KEV never re-reports a
    CVE whose flag already changed, so those alerts were lost permanently.
    """
    user = SimpleNamespace(id=uuid4(), email="user@example.com", instant_alerts=True)
    low = _kev_cve("CVE-2026-3001", cvss=5.0, epss=0.01)
    high = _kev_cve("CVE-2026-3002", cvss=9.8, epss=0.97)
    db = FakeNotificationDb(
        users=[user],
        kev_matches={
            low.cve_id: [SimpleNamespace(cve_id=low.cve_id, user_id=user.id, dismissed=False)],
            high.cve_id: [SimpleNamespace(cve_id=high.cve_id, user_id=user.id, dismissed=False)],
        },
        cves={low.cve_id: low, high.cve_id: high},
    )

    sent = []

    def _capture(db_, user_, cve_, also_exploited=None):
        sent.append((cve_.cve_id, [c.cve_id for c in (also_exploited or [])]))
        return {"delivery_state": "preview"}

    monkeypatch.setattr(notifications, "SyncSessionLocal", lambda: FakeSyncSessionManager(db))
    monkeypatch.setattr(notifications, "_claim_notification_attempt", lambda *args, **kwargs: uuid4())
    monkeypatch.setattr(notifications, "_complete_notification_attempt", lambda *args, **kwargs: None)
    monkeypatch.setattr(notifications, "_send_kev_alert_email", _capture)

    result = notifications.send_instant_kev_alerts([low.cve_id, high.cve_id])

    assert result["previewed"] == 1, "one email per user, not one per CVE"
    assert result["errors"] == 0
    # Highest priority leads; the other rides along instead of being dropped.
    assert sent == [(high.cve_id, [low.cve_id])]


def test_send_instant_kev_alerts_skips_rate_limited_user(monkeypatch):
    user = SimpleNamespace(id=uuid4(), email="user@example.com", instant_alerts=True)
    cve = _kev_cve("CVE-2026-4000")
    db = FakeNotificationDb(
        users=[user],
        kev_matches={cve.cve_id: [SimpleNamespace(cve_id=cve.cve_id, user_id=user.id, dismissed=False)]},
        cves={cve.cve_id: cve},
        rate_limited_user_ids={user.id},
    )

    monkeypatch.setattr(notifications, "SyncSessionLocal", lambda: FakeSyncSessionManager(db))
    monkeypatch.setattr(notifications, "_claim_notification_attempt", lambda *args, **kwargs: uuid4())
    monkeypatch.setattr(notifications, "_complete_notification_attempt", lambda *args, **kwargs: None)
    monkeypatch.setattr(notifications, "_send_kev_alert_email",
                        lambda *a, **k: pytest.fail("must not email a rate-limited user"))

    result = notifications.send_instant_kev_alerts([cve.cve_id])

    assert result["previewed"] == 0
    assert result["sent"] == 0
    assert result["errors"] == 0
