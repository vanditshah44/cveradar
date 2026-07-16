#!/usr/bin/env bash
# db-tunnel.sh — Run on YOUR LOCAL MACHINE to serve your local PostgreSQL
# to the production server via a persistent reverse SSH tunnel.
#
# How it works:
#   autossh keeps an SSH connection to the production server alive.
#   The reverse tunnel maps production's localhost:5435 → your local
#   Docker PostgreSQL on localhost:5433.
#   The production .env uses DATABASE_URL=...@localhost:5435/cveradar.
#
# Prerequisites:
#   1. Install autossh:  sudo apt install autossh
#   2. Set up SSH key auth for your production server (no password prompts).
#   3. Add a Host alias to ~/.ssh/config (see below).
#   4. Your local docker-compose stack must be running (postgres on :5433).
#
# ~/.ssh/config entry:
#   Host cveradar-prod
#     HostName <your-server-ip-or-hostname>
#     User <your-ssh-user>
#     IdentityFile ~/.ssh/id_ed25519
#     ServerAliveInterval 30
#     ServerAliveCountMax 3
#
# Usage:
#   ./scripts/db-tunnel.sh              # uses 'cveradar-prod' alias
#   SSH_HOST=user@1.2.3.4 ./scripts/db-tunnel.sh   # override

set -euo pipefail

SSH_HOST="${SSH_HOST:-cveradar-prod}"
LOCAL_DB_PORT="${LOCAL_DB_PORT:-5433}"    # your Docker postgres port
REMOTE_DB_PORT="${REMOTE_DB_PORT:-5435}"  # port bound on production's localhost
MONITOR_PORT="${MONITOR_PORT:-20001}"     # autossh internal health-check port

echo "┌─────────────────────────────────────────────────┐"
echo "│          CVERadar DB Tunnel                     │"
echo "├─────────────────────────────────────────────────┤"
printf "│  SSH host  : %-34s│\n" "$SSH_HOST"
printf "│  Tunnel    : prod localhost:%-4s → local :%s  │\n" "$REMOTE_DB_PORT" "$LOCAL_DB_PORT"
echo "├─────────────────────────────────────────────────┤"
echo "│  While running: production uses your local DB.  │"
echo "│  Stop (Ctrl+C): production shows maintenance.   │"
echo "└─────────────────────────────────────────────────┘"
echo ""

# Verify local postgres is reachable before starting the tunnel
if ! pg_isready -h localhost -p "$LOCAL_DB_PORT" -q 2>/dev/null; then
    echo "⚠  WARNING: local PostgreSQL on port $LOCAL_DB_PORT is not responding."
    echo "   Make sure your Docker stack is running: docker compose up -d postgres"
    echo ""
fi

exec autossh \
    -M "$MONITOR_PORT" \
    -N \
    -o "ServerAliveInterval=30" \
    -o "ServerAliveCountMax=3" \
    -o "ExitOnForwardFailure=yes" \
    -o "StrictHostKeyChecking=accept-new" \
    -o "Compression=yes" \
    -R "${REMOTE_DB_PORT}:localhost:${LOCAL_DB_PORT}" \
    "$SSH_HOST"
