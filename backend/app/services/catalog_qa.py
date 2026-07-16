"""
catalog_qa.py — audit helpers for the curated product catalog.

The product catalog is small on purpose, so we can keep it trustworthy with
repeatable checks instead of relying on memory.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.cve import CveAffectedProduct

BRIEF_LAUNCH_PRODUCTS = (
    "AdGuard Home",
    "Alpine Linux",
    "Apache HTTP Server",
    "Caddy",
    "Docker Engine",
    "Forgejo",
    "Gitea",
    "Go",
    "Grafana",
    "HAProxy",
    "Home Assistant",
    "Immich",
    "Jellyfin",
    "Kubernetes",
    "MariaDB",
    "MongoDB",
    "MySQL",
    "Nextcloud",
    "Nginx",
    "Node.js",
    "OpenJDK",
    "OpenSSH",
    "OpenSSL",
    "Paperless-ngx",
    "PHP",
    "Pi-hole",
    "Plex Media Server",
    "Portainer",
    "PostgreSQL",
    "Prometheus",
    "Proxmox VE",
    "Python",
    "Redis",
    "SQLite",
    "Traefik",
    "Ubuntu",
    "Debian",
    "Vaultwarden",
    "WireGuard",
    "curl",
    "Zabbix",
)

ALLOWED_CATEGORIES = {
    "web_server",
    "database",
    "cms",
    "self_hosted",
    "container",
    "runtime",
    "os",
    "monitoring",
    "mail",
}


def catalog_seed_path() -> Path:
    repo_root = Path(__file__).resolve().parents[3]
    return repo_root / "data" / "seed" / "product_catalog.json"


def load_seed_catalog() -> list[dict[str, Any]]:
    return json.loads(catalog_seed_path().read_text())


def audit_seed_catalog(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare the seed catalog against the brief launch list and local invariants."""
    display_names = [item["display_name"] for item in items]
    mappings = [(item["vendor"], item["cpe_product"]) for item in items]

    display_name_counts = Counter(display_names)
    mapping_counts = Counter(mappings)

    missing_launch_products = sorted(set(BRIEF_LAUNCH_PRODUCTS) - set(display_names))
    extra_products = sorted(set(display_names) - set(BRIEF_LAUNCH_PRODUCTS))
    duplicate_display_names = sorted(
        name for name, count in display_name_counts.items() if count > 1
    )
    duplicate_mappings = [
        {"vendor": vendor, "cpe_product": cpe_product}
        for (vendor, cpe_product), count in mapping_counts.items()
        if count > 1
    ]
    duplicate_mappings.sort(key=lambda item: (item["vendor"], item["cpe_product"]))
    invalid_categories = [
        {
            "display_name": item["display_name"],
            "category": item.get("category"),
        }
        for item in items
        if item.get("category") not in ALLOWED_CATEGORIES
    ]
    invalid_categories.sort(key=lambda item: item["display_name"])
    malformed_mappings = [
        {
            "display_name": item["display_name"],
            "vendor": item.get("vendor"),
            "cpe_product": item.get("cpe_product"),
        }
        for item in items
        if not item.get("vendor") or not item.get("cpe_product")
    ]
    malformed_mappings.sort(key=lambda item: item["display_name"])

    return {
        "catalog_count": len(items),
        "brief_launch_count": len(BRIEF_LAUNCH_PRODUCTS),
        "missing_launch_products": missing_launch_products,
        "extra_products": extra_products,
        "duplicate_display_names": duplicate_display_names,
        "duplicate_mappings": duplicate_mappings,
        "invalid_categories": invalid_categories,
        "malformed_mappings": malformed_mappings,
        "ok": not any(
            [
                missing_launch_products,
                duplicate_display_names,
                duplicate_mappings,
                invalid_categories,
                malformed_mappings,
            ]
        ),
    }


def audit_catalog_against_nvd(db: Session, items: list[dict[str, Any]]) -> dict[str, Any]:
    """Check whether catalog mappings actually appear in ingested NVD data."""
    mapping_observations = []
    zero_match_products = []

    for item in sorted(items, key=lambda item: item["display_name"]):
        observed_cve_count = db.execute(
            select(func.count(CveAffectedProduct.id)).where(
                CveAffectedProduct.vendor == item["vendor"],
                CveAffectedProduct.product == item["cpe_product"],
            )
        ).scalar_one()
        observation = {
            "display_name": item["display_name"],
            "vendor": item["vendor"],
            "cpe_product": item["cpe_product"],
            "observed_cve_count": observed_cve_count,
        }
        mapping_observations.append(observation)
        if observed_cve_count == 0:
            zero_match_products.append(observation)

    return {
        "products_checked": len(items),
        "zero_match_count": len(zero_match_products),
        "ok": not zero_match_products,
        "zero_match_products": zero_match_products,
        "mapping_observations": mapping_observations,
    }
