#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

WITH_DATA=0
if [[ "${1:-}" == "--with-data" ]]; then
  WITH_DATA=1
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--with-data]"
  exit 1
fi

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

wait_for_api() {
  local attempts=0

  until compose exec -T api python -c "import app.main" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if (( attempts > 60 )); then
      echo "API container did not become ready in time."
      exit 1
    fi
    sleep 2
  done
}

cd "${REPO_ROOT}"

echo "Starting local CVE Radar services..."
compose up -d postgres redis api worker beat frontend

echo "Waiting for API container to become ready..."
wait_for_api

echo "Running Alembic migrations..."
compose exec -T api alembic upgrade head

echo "Seeding product catalog..."
compose exec -T api python scripts/seed_catalog.py

if (( WITH_DATA == 1 )); then
  echo "Running full data bootstrap..."
  "${SCRIPT_DIR}/bootstrap_data.sh"
else
  echo "Local bootstrap complete."
  echo
  echo "Next steps:"
  echo "  1. ${SCRIPT_DIR}/bootstrap_data.sh    # full NVD + KEV + EPSS bootstrap"
  echo "  2. ${SCRIPT_DIR}/verify_local.sh      # verify counts and service health"
fi
