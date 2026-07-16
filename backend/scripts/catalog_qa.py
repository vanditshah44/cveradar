"""
Run repeatable QA checks against the curated product catalog.

Examples:
  python scripts/catalog_qa.py
  python scripts/catalog_qa.py --with-db
  python scripts/catalog_qa.py --strict
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SyncSessionLocal
from app.services.catalog_qa import (
    audit_catalog_against_nvd,
    audit_seed_catalog,
    load_seed_catalog,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit the curated product catalog against the brief launch list and optional NVD data."
    )
    parser.add_argument(
        "--with-db",
        action="store_true",
        help="Also cross-check each vendor/cpe_product mapping against ingested cve_affected_products rows.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if launch-list coverage or mapping QA checks fail.",
    )
    args = parser.parse_args()

    items = load_seed_catalog()
    seed_audit = audit_seed_catalog(items)
    output = {"seed_audit": seed_audit}

    if args.with_db:
        with SyncSessionLocal() as db:
            output["nvd_mapping_audit"] = audit_catalog_against_nvd(db, items)

    print(json.dumps(output, indent=2, sort_keys=True))

    if not args.strict:
        return 0

    seed_ok = seed_audit["ok"]
    db_ok = True
    if args.with_db:
        db_ok = not output["nvd_mapping_audit"]["zero_match_products"]

    return 0 if (seed_ok and db_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
