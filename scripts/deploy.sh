#!/bin/bash
# deploy.sh — Zero-downtime redeploy (rebuild images, restart services).
# Run this whenever you push code changes.
#
# Usage: bash scripts/deploy.sh

set -euo pipefail

echo "==> Pulling latest code..."
git pull

echo "==> Building images..."
docker compose -f docker-compose.prod.yml build --no-cache api worker beat frontend

echo "==> Running DB migrations..."
docker compose -f docker-compose.prod.yml run --rm api alembic upgrade head

echo "==> Restarting services..."
docker compose -f docker-compose.prod.yml up -d

echo "==> Seeding product catalog (safe to re-run)..."
docker compose -f docker-compose.prod.yml exec api python scripts/seed_catalog.py || true

echo "==> Done. Check logs: docker compose -f docker-compose.prod.yml logs -f --tail=50"
