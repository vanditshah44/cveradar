"""
Print bootstrap verification counts for local development.

Run:
  docker compose exec api python scripts/verify_bootstrap.py
"""
import json
import sys
from pathlib import Path

from sqlalchemy import func, select

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SyncSessionLocal
from app.models.cve import Cve, CveAffectedProduct
from app.models.match import UserCveMatch
from app.models.product_catalog import ProductCatalog
from app.models.user import User
from app.services.sync_runs import latest_sync_statuses


def main() -> None:
    with SyncSessionLocal() as db:
        summary = {
            "product_catalog_count": db.execute(select(func.count(ProductCatalog.id))).scalar_one(),
            "cve_count": db.execute(select(func.count(Cve.cve_id))).scalar_one(),
            "affected_product_count": db.execute(select(func.count(CveAffectedProduct.id))).scalar_one(),
            "user_match_count": db.execute(select(func.count(UserCveMatch.id))).scalar_one(),
            "user_count": db.execute(select(func.count(User.id))).scalar_one(),
            "sync_status": latest_sync_statuses(),
        }

    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
