"""
Rebuild user CVE matches for all existing users.

Useful after a full feed bootstrap so users with pre-existing stack items
immediately get dashboard results.

Run:
  docker compose exec api python scripts/rebuild_matches.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.sync_runs import latest_sync_statuses
from app.tasks.matcher import run_matcher_for_all_users


def main() -> None:
    result = run_matcher_for_all_users.run()
    print(result)
    print({"sync_status": latest_sync_statuses(("match_rebuild_all",))})


if __name__ == "__main__":
    main()
