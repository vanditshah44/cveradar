"""
structured_logging.py — lightweight JSON-style event logging helpers.

We keep Python's standard logging stack, but serialize important sync/matcher
events into structured payloads so logs are easier to grep and ingest later.
"""
import json
import logging
from datetime import date, datetime
from uuid import UUID


def _json_default(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return str(value)


def log_structured_event(logger: logging.Logger, level: int, event: str, **fields) -> None:
    """Log one structured event as a single JSON object."""
    payload = {"event": event, **fields}
    logger.log(level, json.dumps(payload, sort_keys=True, default=_json_default))
