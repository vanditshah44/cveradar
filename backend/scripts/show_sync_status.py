"""
Show the latest pipeline run status for each tracked sync job.

Run:
  docker compose exec api python scripts/show_sync_status.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.sync_runs import latest_sync_statuses


def main() -> None:
    print(json.dumps(latest_sync_statuses(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
