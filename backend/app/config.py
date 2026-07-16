"""
config.py — All configuration loaded from environment variables.
"""
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://cveradar:cveradar@localhost:5432/cveradar"
    SYNC_DATABASE_URL: str = "postgresql+psycopg2://cveradar:cveradar@localhost:5432/cveradar"

    # ── Database connection pool ─────────────────────────────────────────────
    # These MUST be sized against your host's connection cap. The peak number
    # of DB connections the whole app can open is roughly:
    #
    #   (web processes)    × (DB_POOL_SIZE      + DB_MAX_OVERFLOW)      [async / API]
    # + (celery processes) × (DB_SYNC_POOL_SIZE + DB_SYNC_MAX_OVERFLOW) [sync / workers]
    #
    # On DirectAdmin / Passenger shared hosting the DB user is often capped at
    # ~10–20 connections AND Passenger spawns several worker processes, so keep
    # these small. Defaults below assume a tight cap; raise them on a dedicated
    # DB. Best long-term fix for scaling + latency is a pooled endpoint
    # (PgBouncer, or Neon's "-pooler" host) — then these can stay small safely.
    DB_POOL_SIZE: int = 5          # persistent async connections per web process
    DB_MAX_OVERFLOW: int = 5       # extra async connections allowed under burst
    DB_SYNC_POOL_SIZE: int = 2     # persistent sync connections per celery process
    DB_SYNC_MAX_OVERFLOW: int = 3  # extra sync connections allowed under burst
    DB_POOL_RECYCLE: int = 1800    # recycle a connection after N seconds (avoids
                                   # "server closed the connection" on idle hosts)
    DB_POOL_TIMEOUT: int = 30      # seconds to wait for a free connection before erroring

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── NVD API ───────────────────────────────────────────────────────────────
    NVD_API_KEY: str = ""

    # ── Resend (email provider — leave empty to use SMTP instead) ────────────
    RESEND_API_KEY: str = ""
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RESULTS_PER_PAGE: int = 2000

    # ── External feeds ────────────────────────────────────────────────────────
    KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL: str = "https://api.first.org/data/v1/epss"

    # ── Auth ──────────────────────────────────────────────────────────────────
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    MAGIC_LINK_EXPIRE_MINUTES: int = 15
    SESSION_EXPIRE_DAYS: int = 30

    # ── Email (SMTP) ──────────────────────────────────────────────────────────
    # Set EMAIL_DELIVERY_MODE=smtp and fill in SMTP_* to send real emails.
    # Set EMAIL_DELIVERY_MODE=preview to write HTML files locally (dev/test).
    EMAIL_DELIVERY_MODE: str = "auto"   # auto | smtp | preview
    EMAIL_PREVIEW_DIR: str = str(
        Path(__file__).resolve().parent.parent / "tmp" / "email-previews"
    )

    SMTP_HOST: str = ""           # e.g. mail.yourdomain.com
    SMTP_PORT: int = 465          # 465 = SSL, 587 = STARTTLS
    SMTP_USER: str = ""           # e.g. alerts@yourdomain.com
    SMTP_PASSWORD: str = ""       # SMTP account password
    SMTP_USE_SSL: bool = True     # True for port 465, False for 587 (STARTTLS)
    FROM_EMAIL: str = "CVE Radar <alerts@yourdomain.com>"

    # ── App ───────────────────────────────────────────────────────────────────
    DEBUG: bool = False
    FRONTEND_URL: str = "http://localhost:3000"
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    LOG_FORMAT: str = "text"  # text | json

    # ── Error Monitoring ──────────────────────────────────────────────────────
    SENTRY_DSN: str = ""
    SENTRY_ENVIRONMENT: str = "development"
    SENTRY_TRACES_SAMPLE_RATE: float = 0.0

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if not self.DEBUG and self.SECRET_KEY == "change-me-in-production":
            raise ValueError(
                "SECRET_KEY must be changed from the default before running in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return self

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def ensure_async_driver(cls, value: str) -> str:
        """Guarantee the async engine gets an async driver.

        A bare ``postgresql://`` (or ``postgres://``) URL — which is what most
        hosting panels and connection-string copy buttons hand you — would make
        ``create_async_engine`` fail with "The asyncio extension requires an
        async driver." Upgrade the scheme to asyncpg so the app boots either way.
        """
        for prefix in ("postgresql+psycopg2://", "postgresql+asyncpg://"):
            if value.startswith(prefix):
                return value
        if value.startswith("postgresql://"):
            return "postgresql+asyncpg://" + value[len("postgresql://"):]
        if value.startswith("postgres://"):
            return "postgresql+asyncpg://" + value[len("postgres://"):]
        return value

    @field_validator("SYNC_DATABASE_URL", mode="after")
    @classmethod
    def ensure_sync_driver(cls, value: str) -> str:
        """Guarantee the Celery/sync engine gets the sync psycopg2 driver."""
        if value.startswith("postgresql+psycopg2://"):
            return value
        if value.startswith("postgresql+asyncpg://"):
            return "postgresql+psycopg2://" + value[len("postgresql+asyncpg://"):]
        if value.startswith("postgresql://"):
            return "postgresql+psycopg2://" + value[len("postgresql://"):]
        if value.startswith("postgres://"):
            return "postgresql+psycopg2://" + value[len("postgres://"):]
        return value

    @field_validator("DEBUG", mode="before")
    @classmethod
    def parse_debug(cls, value):
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "debug"}:
                return True
            if normalized in {"0", "false", "no", "off", "release", "prod", "production", ""}:
                return False
        return value


settings = Settings()
