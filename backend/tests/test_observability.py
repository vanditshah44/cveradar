from app.config import settings
from app.services.observability import collect_runtime_warnings, extract_task_log_context


def _warning_codes(warnings):
    return {warning["code"] for warning in warnings}


def test_collect_runtime_warnings_reports_common_misconfigurations(monkeypatch):
    monkeypatch.setattr(settings, "SECRET_KEY", "change-me-in-production")
    monkeypatch.setattr(settings, "NVD_API_KEY", "")
    monkeypatch.setattr(settings, "EMAIL_DELIVERY_MODE", "resend")
    monkeypatch.setattr(settings, "RESEND_API_KEY", "")
    monkeypatch.setattr(settings, "FRONTEND_URL", "http://localhost:3000")
    monkeypatch.setattr(settings, "CORS_ORIGINS", [])
    monkeypatch.setattr(settings, "LOG_FORMAT", "yaml")
    monkeypatch.setattr(settings, "SENTRY_DSN", "")

    warnings = collect_runtime_warnings("api")

    assert _warning_codes(warnings) == {
        "default_secret_key",
        "missing_nvd_api_key",
        "email_resend_without_api_key",
        "frontend_url_missing_from_cors",
        "unsupported_log_format",
        "sentry_disabled",
    }


def test_collect_runtime_warnings_marks_preview_mode_as_info(monkeypatch):
    monkeypatch.setattr(settings, "SECRET_KEY", "very-secret")
    monkeypatch.setattr(settings, "NVD_API_KEY", "nvd-key")
    monkeypatch.setattr(settings, "EMAIL_DELIVERY_MODE", "auto")
    monkeypatch.setattr(settings, "RESEND_API_KEY", "")
    monkeypatch.setattr(settings, "FRONTEND_URL", "http://localhost:3000")
    monkeypatch.setattr(settings, "CORS_ORIGINS", ["http://localhost:3000"])
    monkeypatch.setattr(settings, "LOG_FORMAT", "json")
    monkeypatch.setattr(settings, "SENTRY_DSN", "")

    warnings = collect_runtime_warnings("celery")

    preview_warning = next(
        warning for warning in warnings if warning["code"] == "email_preview_mode_active"
    )
    sentry_warning = next(
        warning for warning in warnings if warning["code"] == "sentry_disabled"
    )

    assert preview_warning["severity"] == "info"
    assert sentry_warning["severity"] == "info"


def test_extract_task_log_context_includes_user_id_for_matcher():
    context = extract_task_log_context(
        "app.tasks.matcher.run_matcher_for_user",
        ("user-123",),
        None,
    )

    assert context["task_name"] == "app.tasks.matcher.run_matcher_for_user"
    assert context["user_id"] == "user-123"


def test_extract_task_log_context_tracks_single_cve_for_notification_task():
    context = extract_task_log_context(
        "app.tasks.notifications.send_instant_kev_alerts",
        (["CVE-2026-1234"],),
        None,
    )

    assert context["task_name"] == "app.tasks.notifications.send_instant_kev_alerts"
    assert context["cve_id"] == "CVE-2026-1234"
    assert context["cve_count"] == 1


def test_extract_task_log_context_marks_daily_digest_task():
    context = extract_task_log_context(
        "app.tasks.notifications.send_daily_digests",
        (),
        None,
    )

    assert context["notification_type"] == "daily_digest"
