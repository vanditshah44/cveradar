"""
Bootstrap external CVE feeds for local development.

This script runs the feed bootstrap pipeline with stage logging.

Run:
  docker compose exec api python scripts/bootstrap_feeds.py
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.sync_runs import latest_sync_statuses
from app.tasks.epss_sync import sync_epss
from app.tasks.kev_sync import sync_kev
from app.tasks.matcher import run_matcher_for_all_users
from app.tasks.nvd_sync import sync_nvd_full
from app.tasks.nvd_sync import sync_nvd_incremental


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the CVE Radar feed bootstrap pipeline.")
    parser.add_argument(
        "--nvd-mode",
        choices=("full", "incremental", "skip"),
        default="full",
        help="Choose whether to run the full NVD bootstrap, the incremental sync, or skip NVD entirely.",
    )
    parser.add_argument("--skip-kev", action="store_true", help="Skip the KEV sync stage.")
    parser.add_argument("--skip-epss", action="store_true", help="Skip the EPSS sync stage.")
    parser.add_argument(
        "--skip-rebuild-matches",
        action="store_true",
        help="Skip the full match rebuild stage.",
    )
    return parser.parse_args()


def run_stage(name: str, runner) -> dict:
    started = time.monotonic()
    print(f"[{timestamp()}] Starting stage: {name}", flush=True)
    result = runner()
    duration = time.monotonic() - started
    print(f"[{timestamp()}] Completed stage: {name} ({duration:.1f}s)", flush=True)
    print(json.dumps({name: result}, indent=2, sort_keys=True), flush=True)
    return result


def main() -> None:
    args = parse_args()

    steps: list[tuple[str, object]] = []
    if args.nvd_mode == "full":
        steps.append(("nvd_full", lambda: sync_nvd_full.run(trigger_match_rebuild=False)))
    elif args.nvd_mode == "incremental":
        steps.append(("nvd_incremental", sync_nvd_incremental.run))

    if not args.skip_kev:
        steps.append(("kev_sync", sync_kev.run))
    if not args.skip_epss:
        steps.append(("epss_sync", sync_epss.run))
    if not args.skip_rebuild_matches:
        steps.append(("match_rebuild_all", run_matcher_for_all_users.run))

    summary: dict[str, dict] = {}

    for name, runner in steps:
        summary[name] = run_stage(name, runner)

    print(f"[{timestamp()}] Feed bootstrap complete.", flush=True)
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    print(json.dumps({"sync_status": latest_sync_statuses()}, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
