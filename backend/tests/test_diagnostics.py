from datetime import datetime, timedelta, timezone

from app.services.diagnostics import evaluate_beat_heartbeat


def test_evaluate_beat_heartbeat_reports_ok_for_fresh_timestamp():
    now = datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc)
    recorded_at = now - timedelta(seconds=30)

    result = evaluate_beat_heartbeat(recorded_at, now=now, max_age_seconds=180)

    assert result["ok"] is True
    assert result["status"] == "ok"
    assert result["age_seconds"] == 30


def test_evaluate_beat_heartbeat_reports_stale_for_old_timestamp():
    now = datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc)
    recorded_at = now - timedelta(seconds=400)

    result = evaluate_beat_heartbeat(recorded_at, now=now, max_age_seconds=180)

    assert result["ok"] is False
    assert result["status"] == "stale"
    assert result["age_seconds"] == 400


def test_evaluate_beat_heartbeat_reports_missing_without_timestamp():
    result = evaluate_beat_heartbeat(None)

    assert result["ok"] is False
    assert result["status"] == "missing"
    assert result["last_heartbeat_at"] is None
