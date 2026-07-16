# CVE Radar

CVE Radar is a personalized vulnerability monitoring app for homelabs, self-hosted infrastructure, and small engineering teams.

Instead of showing every new CVE in the world, CVE Radar lets a user register the products and versions they actually run, then continuously answers a narrower question:

> Which vulnerabilities affect my stack right now, and which ones matter most?

The current project includes the full product pipeline:

- a public landing page and magic-link sign-in flow
- a curated software catalog for fast stack onboarding
- NVD ingestion with KEV and EPSS enrichment
- background matching between user stack items and affected product/version rules
- a dashboard with filters, sorting, seen/dismiss state, and CVE detail pages
- daily digest and instant KEV notification infrastructure
- operational diagnostics, sync tracking, and bootstrap tooling

![CVE Radar architecture](./cve_radar_architecture.svg)

## Why This Exists

Enterprise scanners are often too heavy, too noisy, or too expensive for people running a smaller stack. CVE Radar is meant to feel closer to a "personalized security radar":

- register what you run
- ingest public vulnerability feeds
- match only the vulnerabilities that affect that software
- prioritize using practical exploitability signals, not CVSS alone
- show the result in a clean dashboard and email workflow

## Core Product Flow

1. A user signs in with a magic link.
2. They add products and versions to their stack.
3. Background jobs ingest NVD CVEs, hourly KEV updates, and daily EPSS scores.
4. The matcher compares affected CPE/vendor/product/version rules against saved stack items.
5. Matching CVEs are ranked and shown in the dashboard.
6. Users receive instant KEV alerts and daily digests based on preferences.

## Architecture

### Runtime services

- `frontend/`: Next.js application for the landing page, onboarding, dashboard, CVE detail, and settings
- `backend/`: FastAPI API, SQLAlchemy models, Celery tasks, feed ingestion, matching, diagnostics, and email logic
- `postgres`: primary relational database
- `redis`: Celery broker and backend
- `worker`: Celery worker for sync, matching, and notification tasks
- `beat`: Celery beat scheduler for recurring jobs
- `nginx/`: production reverse proxy and TLS termination

### Main data pipeline

```text
NVD feed -----------+
                    |
CISA KEV -----------+--> ingestion + enrichment --> affected products --> matcher --> user_cve_matches
                    |                                                               |
EPSS ---------------+                                                               +--> dashboard
                                                                                    +--> CVE detail
                                                                                    +--> digest / KEV emails
```

### Scheduled background jobs

Defined in [`backend/app/tasks/celery_app.py`](./backend/app/tasks/celery_app.py):

- NVD incremental sync: hourly
- KEV sync: hourly
- EPSS sync: daily
- Daily digest send: daily
- Beat heartbeat: every minute

## Repo Layout

```text
backend/                 FastAPI app, Celery tasks, models, migrations, tests
frontend/                Next.js app
data/seed/               curated product catalog
docs/                    runbooks and project operations docs
nginx/                   production reverse proxy config
scripts/                 local bootstrap and deployment helpers
docker-compose.yml       local development stack
docker-compose.prod.yml  production-oriented container stack
```

## Local Development

### 1. Create your env file

```bash
cp .env.example .env
```

Fill in the required values, especially:

- `POSTGRES_PASSWORD`
- `REDIS_PASSWORD`
- `SECRET_KEY`
- `NVD_API_KEY` for faster full bootstrap
- SMTP settings if you want real email delivery

For local development, you can also use preview email mode:

```env
EMAIL_DELIVERY_MODE=preview
```

### 2. Run the full local bootstrap

```bash
./scripts/bootstrap_local.sh --with-data
```

That script:

- starts Postgres, Redis, API, worker, beat, and frontend
- runs Alembic migrations
- seeds the curated product catalog
- runs the full NVD bootstrap
- runs KEV and EPSS syncs
- rebuilds matches
- prints verification counts

### 3. Open the app

- Frontend: `http://localhost:3000`
- API health: `http://localhost:8000/health`
- API readiness: `http://localhost:8000/health/ready`
- Pipeline debug snapshot: `http://localhost:8000/api/debug/pipeline`

## Manual Bootstrap Commands

If you want to run each step yourself:

```bash
docker compose up -d postgres redis api worker beat frontend
docker compose exec -T api alembic upgrade head
docker compose exec -T api python scripts/seed_catalog.py
docker compose exec -T api python scripts/bootstrap_feeds.py
./scripts/verify_local.sh
```

Helpful extras:

```bash
docker compose exec -T api python scripts/show_sync_status.py
docker compose exec -T api python scripts/rebuild_matches.py
docker compose exec -T api python scripts/notification_email_preview.py daily-digest --user-email you@example.com
```

## Email Delivery

Notification delivery supports two useful modes:

- `smtp`: send real email
- `preview`: write local HTML previews to `backend/tmp/email-previews/`

The backend also supports `auto`, which falls back to previews when SMTP is not configured.

See [`docs/email-delivery.md`](./docs/email-delivery.md) for template preview and testing commands.

## Production Deployment

Two deployment paths are included:

- `docker-compose.prod.yml` for a Docker-based VPS deployment with Nginx
- `.env.directadmin.example` for a DirectAdmin/shared-hosting style environment

Production stack highlights:

- FastAPI served by Uvicorn
- Next.js frontend built for production
- Postgres + Redis as internal services
- Celery worker + beat for background processing
- Nginx reverse proxy with TLS support

## Diagnostics And Operations

The project includes operational visibility for:

- API liveness and readiness
- database, Redis, Celery worker, and Celery beat health
- latest NVD, KEV, and EPSS sync status
- counts for CVEs, matches, and notifications
- structured logs and optional Sentry integration

Relevant docs:

- [`docs/local-bootstrap.md`](./docs/local-bootstrap.md)
- [`docs/email-delivery.md`](./docs/email-delivery.md)
- [`docs/product-catalog-audit.md`](./docs/product-catalog-audit.md)
- [`docs/performance-data-correctness.md`](./docs/performance-data-correctness.md)
- [`docs/security-audit.md`](./docs/security-audit.md)

## Testing

Backend:

```bash
docker compose exec -T api pytest
```

Frontend smoke tests:

```bash
cd frontend
npm install
npm run test:smoke
```

## Notes

- The full NVD bootstrap is the heaviest first-run step. An `NVD_API_KEY` is strongly recommended.
- Sync jobs are designed to be rerunnable without duplicating CVEs or user matches.
- The curated product catalog lives in `data/seed/product_catalog.json` and is mirrored under `backend/data/seed/` for fallback packaging contexts.
- The database schema reference is included in [`cve_radar_database_schema.html`](./cve_radar_database_schema.html).

## License

No license file is included yet. Add one before publishing if you want the repository to be openly reusable.
