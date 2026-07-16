#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

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

echo "Ensuring core services are running..."
compose up -d postgres redis api worker beat

echo "Waiting for API container to become ready..."
wait_for_api

echo "Running full NVD + KEV + EPSS bootstrap..."
compose exec -T api python scripts/bootstrap_feeds.py

echo "Verifying local bootstrap state..."
"${SCRIPT_DIR}/verify_local.sh"
