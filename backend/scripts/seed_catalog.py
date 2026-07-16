"""
Seed the product_catalog table from the JSON file.

Run after running migrations:
  docker compose exec api python scripts/seed_catalog.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SyncSessionLocal
from app.models.product_catalog import ProductCatalog


def main():
    # Try repo root first (dev bind mount), fall back to copied location
    repo_root = Path(__file__).parent.parent.parent
    catalog_path = repo_root / "data" / "seed" / "product_catalog.json"
    if not catalog_path.exists():
        catalog_path = Path(__file__).parent.parent / "data" / "seed" / "product_catalog.json"
    data = json.loads(catalog_path.read_text())

    with SyncSessionLocal() as db:
        # Clear existing entries
        db.query(ProductCatalog).delete()

        for item in data:
            db.add(ProductCatalog(**item))

        db.commit()
        print(f"Seeded {len(data)} products into product_catalog")


if __name__ == "__main__":
    main()
