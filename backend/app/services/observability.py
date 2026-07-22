"""
observability.py — shared logging, request/task instrumentation, and warnings.
"""
from __future__ import annotations

import logging
from time import perf_counter
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from celery.signals import task_failure, task_postrun, task_prerun

from app.config import settings
from app.services.structured_logging import log_structured_event

logger = logging.getLogger(__name__)

_celery_signals_registered = False
_sentry_initialized_for: set[str] = set()


def _log_format_string() -> str:
    if settings.LOG_FORMAT.strip().lower() == "json":
        return "%(message)s"
    return "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_application_logging() -> None:
    """Initialize or normalize process logging for API/worker processes."""
    root_logger = logging.getLogger()
    level = logging.DEBUG if settings.DEBUG else logging.INFO
    formatter = logging.Formatter(_log_format_string())

    if not root_logger.handlers:
        logging.basicConfig(level=level, format=_log_format_string())
        return

    root_logger.setLevel(level)
    for handler in root_logger.handlers:
        handler.setLevel(level)
        handler.setFormatter(formatter)


def _warning(code: str, message: str, *, hint: str | None = None, severity: str = "warning") -> dict[str, str]:
    payload = {
        "code": code,
        "message": message,
        "severity": severity,
    }
    if hint:
        payload["hint"] = hint
    return payload


def collect_runtime_warnings(service_name: str | None = None) -> list[dict[str, str]]:
    """Return actionable warnings for common configuration pitfalls."""
    warnings: list[dict[str, str]] = []

    if settings.SECRET_KEY.startswith("change-me-in-production"):
        warnings.append(
            _warning(
                "default_secret_key",
                "SECRET_KEY is still using the default placeholder value.",
                hint="Generate a long random secret before using this outside disposable local development.",
            )
        )

    if not settings.NVD_API_KEY:
        warnings.append(
            _warning(
                "missing_nvd_api_key",
                "NVD_API_KEY is empty, so NVD bootstrap and incremental syncs will run at the public rate limit.",
                hint="Set NVD_API_KEY in .env to speed up feed ingestion significantly.",
            )
        )

    delivery_mode = settings.EMAIL_DELIVERY_MODE.strip().lower()
    if delivery_mode == "resend" and not settings.RESEND_API_KEY:
        warnings.append(
            _warning(
                "email_resend_without_api_key",
                "EMAIL_DELIVERY_MODE is set to resend, but RESEND_API_KEY is empty.",
                hint="Provide RESEND_API_KEY or switch EMAIL_DELIVERY_MODE to auto/preview.",
            )
        )
    elif delivery_mode == "auto" and not settings.RESEND_API_KEY:
        warnings.append(
            _warning(
                "email_preview_mode_active",
                "RESEND_API_KEY is empty, so outbound emails will be written to local previews instead of being delivered.",
                hint="This is expected for local development, but production needs a real RESEND_API_KEY.",
                severity="info",
            )
        )

    if settings.FRONTEND_URL not in settings.CORS_ORIGINS:
        warnings.append(
            _warning(
                "frontend_url_missing_from_cors",
                "FRONTEND_URL is not present in CORS_ORIGINS.",
                hint="Add the frontend origin to CORS_ORIGINS so browser requests can authenticate correctly.",
            )
        )

    log_format = settings.LOG_FORMAT.strip().lower()
    if log_format not in {"text", "json"}:
        warnings.append(
            _warning(
                "unsupported_log_format",
                f"LOG_FORMAT is set to '{settings.LOG_FORMAT}', which is not a supported value.",
                hint="Use LOG_FORMAT=text for local readability or LOG_FORMAT=json for structured log shipping.",
            )
        )

    if service_name in {"api", "celery", "worker", "beat"} and not settings.SENTRY_DSN:
        warnings.append(
            _warning(
                "sentry_disabled",
                "SENTRY_DSN is empty, so process errors are not being reported to Sentry.",
                hint="Set SENTRY_DSN and SENTRY_ENVIRONMENT to enable error monitoring.",
                severity="info",
            )
        )

    return warnings


def log_runtime_warnings(service_name: str) -> None:
    for warning in collect_runtime_warnings(service_name):
        level = logging.WARNING if warning["severity"] == "warning" else logging.INFO
        log_structured_event(logger, level, "runtime_warning", service=service_name, **warning)


def init_sentry(service_name: str) -> bool:
    """Initialize Sentry if configured. Safe to call multiple times."""
    if service_name in _sentry_initialized_for:
        return True

    dsn = settings.SENTRY_DSN.strip()
    if not dsn:
        return False

    try:
        import sentry_sdk

        integrations: list[Any] = []
        if service_name == "api":
            from sentry_sdk.integrations.fastapi import FastApiIntegration
            integrations.append(FastApiIntegration())
        if service_name in {"celery", "worker", "beat"}:
            from sentry_sdk.integrations.celery import CeleryIntegration
            integrations.append(CeleryIntegration())

        sentry_sdk.init(
            dsn=dsn,
            environment=settings.SENTRY_ENVIRONMENT,
            traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
            send_default_pii=False,
            integrations=integrations,
        )
        _sentry_initialized_for.add(service_name)
        log_structured_event(
            logger,
            logging.INFO,
            "sentry_initialized",
            service=service_name,
            environment=settings.SENTRY_ENVIRONMENT,
            traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
        )
        return True
    except Exception as exc:
        log_structured_event(
            logger,
            logging.WARNING,
            "sentry_init_failed",
            service=service_name,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return False


def install_fastapi_observability(app: FastAPI) -> None:
    """Add request/response logging middleware to the FastAPI app."""

    @app.middleware("http")
    async def log_requests(request: Request, call_next):  # type: ignore[misc]
        request_id = str(uuid4())
        start = perf_counter()

        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = round((perf_counter() - start) * 1000, 2)
            log_structured_event(
                logging.getLogger("app.api.request"),
                logging.ERROR,
                "api_request_failed",
                service="api",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                query=request.url.query or None,
                duration_ms=duration_ms,
                status_code=500,
                client_ip=request.client.host if request.client else None,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise

        duration_ms = round((perf_counter() - start) * 1000, 2)
        level = logging.INFO
        if response.status_code >= 500:
            level = logging.ERROR
        elif response.status_code >= 400:
            level = logging.WARNING

        response.headers["X-Request-ID"] = request_id
        log_structured_event(
            logging.getLogger("app.api.request"),
            level,
            "api_request_finished",
            service="api",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=request.url.query or None,
            duration_ms=duration_ms,
            status_code=response.status_code,
            client_ip=request.client.host if request.client else None,
        )
        return response


def extract_task_log_context(task_name: str | None, args: tuple | None, kwargs: dict | None) -> dict[str, Any]:
    """Derive common structured fields for known Celery tasks."""
    task_name = task_name or "unknown"
    args = args or ()
    kwargs = kwargs or {}
    context: dict[str, Any] = {"task_name": task_name}

    if task_name.endswith("run_matcher_for_user"):
        context["user_id"] = kwargs.get("user_id") or (args[0] if args else None)
    elif task_name.endswith("run_matcher_for_cves") or task_name.endswith("send_instant_kev_alerts"):
        cve_ids = kwargs.get("cve_ids") or (args[0] if args else [])
        if isinstance(cve_ids, list):
            context["cve_count"] = len(cve_ids)
            if len(cve_ids) == 1:
                context["cve_id"] = cve_ids[0]
            else:
                context["cve_ids"] = cve_ids[:10]
    elif task_name.endswith("send_daily_digests"):
        context["notification_type"] = "daily_digest"

    return {key: value for key, value in context.items() if value is not None}


def register_celery_observability() -> None:
    """Register Celery lifecycle logs once per process."""
    global _celery_signals_registered
    if _celery_signals_registered:
        return

    task_logger = logging.getLogger("app.celery.lifecycle")

    @task_prerun.connect(weak=False)
    def _task_prerun(task_id=None, task=None, args=None, kwargs=None, **extras):
        log_structured_event(
            task_logger,
            logging.INFO,
            "celery_task_started",
            service="celery",
            task_id=task_id,
            **extract_task_log_context(getattr(task, "name", None), args, kwargs),
        )

    @task_postrun.connect(weak=False)
    def _task_postrun(task_id=None, task=None, args=None, kwargs=None, retval=None, state=None, **extras):
        if state == "FAILURE":
            return
        extra_fields: dict[str, Any] = {}
        if isinstance(retval, dict):
            extra_fields = {
                key: value
                for key, value in retval.items()
                if isinstance(value, (str, int, float, bool)) or value is None
            }
        # A task's return dict may carry keys we also pass explicitly (e.g.
        # record_beat_heartbeat returns its own "task_id"). Drop those so they
        # can't collide — the signal's own values are authoritative.
        context = extract_task_log_context(getattr(task, "name", None), args, kwargs)
        reserved = {"service", "task_id", "state", *context}
        extra_fields = {k: v for k, v in extra_fields.items() if k not in reserved}
        log_structured_event(
            task_logger,
            logging.INFO,
            "celery_task_finished",
            service="celery",
            task_id=task_id,
            state=state,
            **context,
            **extra_fields,
        )

    @task_failure.connect(weak=False)
    def _task_failure(task_id=None, exception=None, sender=None, args=None, kwargs=None, einfo=None, **extras):
        log_structured_event(
            task_logger,
            logging.ERROR,
            "celery_task_failed",
            service="celery",
            task_id=task_id,
            error=str(exception),
            error_type=type(exception).__name__ if exception else None,
            traceback=str(einfo) if einfo else None,
            **extract_task_log_context(getattr(sender, "name", None), args, kwargs),
        )

    _celery_signals_registered = True
