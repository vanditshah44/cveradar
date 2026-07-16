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

cd "${REPO_ROOT}"

echo "== Service Status =="
compose ps postgres redis api worker beat frontend
echo

echo "== Bootstrap Counts =="
compose exec -T api python scripts/verify_bootstrap.py
