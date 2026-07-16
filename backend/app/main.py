"""
main.py — FastAPI application factory.

This file creates the FastAPI app, registers all routers, and configures
middleware. It's the entry point for uvicorn:
  uvicorn app.main:app --reload
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import settings
from app.api import auth, stack, cves, diagnostics, products, stats, settings as settings_router
from app.services.observability import (
    configure_application_logging,
    init_sentry,
    install_fastapi_observability,
    log_runtime_warnings,
)

configure_application_logging()
init_sentry("api")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every API response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not settings.DEBUG:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_runtime_warnings("api")
    yield

app = FastAPI(
    title="CVE Radar API",
    description="Personalized CVE alerting for your tech stack",
    version="0.1.0",
    docs_url="/docs" if settings.DEBUG else None,  # hide Swagger in production
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

# CORS — allow the Next.js dev server to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,  # needed for cookies (session tokens)
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Cookie", "Authorization", "X-Requested-With"],
)
app.add_middleware(SecurityHeadersMiddleware)
install_fastapi_observability(app)


_DB_CONNECTION_KEYWORDS = (
    "connection refused", "could not connect", "connection failed",
    "server closed the connection", "connection reset", "temporarily unavailable",
    "can't connect", "cannot connect",
)


@app.exception_handler(OperationalError)
async def db_connection_error_handler(request: Request, exc: OperationalError) -> JSONResponse:
    """Return 503 when the database is unreachable (tunnel down / server off).
    Non-connection OperationalErrors (constraint violations, etc.) still return 500.
    """
    cause = str(exc.orig or exc).lower()
    if any(kw in cause for kw in _DB_CONNECTION_KEYWORDS):
        return JSONResponse(
            status_code=503,
            headers={"Retry-After": "30"},
            content={"detail": "maintenance"},
        )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# Register all API routers
app.include_router(auth.router)
app.include_router(stack.router)
app.include_router(cves.router)
app.include_router(products.router)
app.include_router(stats.router)
app.include_router(settings_router.router)
app.include_router(diagnostics.router)


@app.get("/health")
async def health_check():
    """Simple health check. Used by Docker healthcheck and load balancer."""
    return {"status": "ok", "version": "0.1.0"}
