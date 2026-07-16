"""
passenger_wsgi.py — Entry point for Phusion Passenger (DirectAdmin Python app).

Passenger detects ASGI apps automatically in version 5+. This file exports
the FastAPI ASGI application as `application` so Passenger can serve it.

If your DirectAdmin host runs an older Passenger (< 5.0) or WSGI-only mode,
install a2wsgi:  pip install a2wsgi
Then swap the last two lines as shown in the comment below.
"""
import sys
import os

# Add the backend directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Load the SINGLE canonical .env from the project root (one level up from
# backend/). This must match what the cron scripts (scripts/cron_*.py) and
# init_db.py load, otherwise the web app and the background syncs end up
# talking to different databases. If a backend/.env exists it is intentionally
# ignored — keep exactly one .env at the project root.
from dotenv import load_dotenv
project_root = os.path.dirname(current_dir)
root_env = os.path.join(project_root, ".env")
backend_env = os.path.join(current_dir, ".env")
# Prefer the root .env; fall back to backend/.env only if no root .env exists.
load_dotenv(root_env if os.path.exists(root_env) else backend_env)

# Import the FastAPI ASGI app.
from app.main import app as _asgi_app

# ── Serve it under Passenger ─────────────────────────────────────────────────
# FastAPI is ASGI, but DirectAdmin's Passenger runs Python in WSGI mode, so it
# cannot call an ASGI app directly (the page just fails to load, often with no
# log). a2wsgi.ASGIMiddleware wraps the ASGI app in a WSGI-compatible callable,
# which Passenger CAN serve. This also works fine on Passenger builds that do
# support ASGI, so it is safe either way.
#
# Requires: pip install a2wsgi   (already added to requirements.txt)
from a2wsgi import ASGIMiddleware

application = ASGIMiddleware(_asgi_app)
