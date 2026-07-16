"""
nvd_sync.py — NVD API ingestion task.

This is the core data pipeline. It fetches CVEs from the NVD REST API 2.0
and upserts them into our database.

Two modes:
  1. Incremental (default): fetch CVEs modified in the last 2 hours.
     Runs every hour via Celery beat. Fast — usually <200 CVEs.

  2. Full sync: fetch all CVEs ever published.
     Run once manually to bootstrap the database: 250,000+ CVEs, takes ~30 min.
     Usage: docker compose exec worker celery -A app.tasks.celery_app call app.tasks.nvd_sync.sync_nvd_full

NVD API rate limits (why we sleep between requests):
  Without API key: 5 requests / 30 seconds
  With API key:    50 requests / 30 seconds
  Each page can have up to 2000 results.

CPE parsing (the hard part):
  NVD gives us "configurations" which contain nested nodes with CPE matches.
  We flatten these into simple (vendor, product, version_range) rows in
  cve_affected_products. The matching engine then uses these.

  NVD config structure:
    configurations[].nodes[].cpeMatch[{
      vulnerable: bool,
      criteria: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
      versionStartIncluding: "1.20.0",
      versionEndExcluding: "1.24.3"
    }]
"""
import logging
import time
from datetime import datetime, timedelta, timezone
from itertools import product

import httpx
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import settings
from app.database import SyncSessionLocal
from app.models.cve import Cve, CveAffectedProduct
from app.models.product_catalog import ProductCatalog
from app.models.stack_item import StackItem
from app.services.structured_logging import log_structured_event
from app.services.sync_runs import finish_sync_run, start_sync_run
from app.utils.cpe import parse_cpe_string

logger = logging.getLogger(__name__)


def load_tracked_products(db: Session) -> set[tuple[str, str]]:
    """Return the (vendor, cpe_product) pairs this deployment actually monitors:
    the curated product catalog plus every product in a user's stack.

    CVERadar is a personalised tool — it only ever matches CVEs against these
    products. Scoping ingestion to this set keeps the database to the few
    thousand relevant CVEs instead of NVD's full 250k+ corpus, which is what
    overran the free-tier storage. If this set is empty (e.g. the catalog was
    never seeded) we log loudly rather than silently storing nothing.
    """
    tracked: set[tuple[str, str]] = set()
    for vendor, product in db.execute(
        select(ProductCatalog.vendor, ProductCatalog.cpe_product)
    ).all():
        tracked.add((vendor, product))
    for vendor, product in db.execute(
        select(StackItem.vendor, StackItem.cpe_product)
    ).all():
        tracked.add((vendor, product))

    if not tracked:
        logger.warning(
            "load_tracked_products returned an EMPTY set — no catalog or stack "
            "products found. Scoped NVD sync would store nothing. Seed the "
            "product catalog before syncing."
        )
    return tracked


# ── NVD API client ────────────────────────────────────────────────────────────

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=30),
    reraise=True,
)
def fetch_nvd_page(params: dict) -> dict:
    """Fetch one page from NVD API. Retries up to 3x on failure.

    tenacity handles the retry logic:
    - wait_exponential: first retry after 4s, then 8s, then 16s (capped at 30s)
    - stop_after_attempt: give up after 3 tries
    - reraise=True: if all retries fail, raise the original exception
    """
    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    with httpx.Client(timeout=30.0) as client:
        response = client.get(settings.NVD_BASE_URL, params=params, headers=headers)
        response.raise_for_status()
        return response.json()


def _rate_limit_sleep() -> None:
    """Respect NVD rate limits between paginated requests.

    Without API key: 5 req/30s = 6 seconds between requests (safe).
    With API key: 50 req/30s = 0.6 seconds (we use 1s to be safe).
    """
    if settings.NVD_API_KEY:
        time.sleep(1.0)
    else:
        time.sleep(6.5)


# ── CVE parsing ───────────────────────────────────────────────────────────────

def _extract_cvss(cve_data: dict) -> tuple[float | None, str | None]:
    """Extract CVSS score and vector from NVD metrics.

    NVD provides multiple CVSS versions (v3.1, v3.0, v2.0).
    We prefer v3.1 > v3.0 > v2.0.
    """
    metrics = cve_data.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30"]:
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            return cvss_data.get("baseScore"), cvss_data.get("vectorString")

    # Fall back to CVSS v2
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        cvss_data = entries[0].get("cvssData", {})
        return cvss_data.get("baseScore"), cvss_data.get("vectorString")

    return None, None


def _extract_description(cve_data: dict) -> str | None:
    """Get the English description from NVD."""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value")
    return None


def _extract_references(cve_data: dict) -> list[dict]:
    """Extract reference URLs with their tags."""
    return [
        {"url": ref.get("url"), "source": ref.get("source"), "tags": ref.get("tags", [])}
        for ref in cve_data.get("references", [])
    ]


def _build_affected_entry(
    cpe_match: dict,
    *,
    config_index: int,
    config_path: list[str],
    operator_path: list[str],
) -> dict | None:
    criteria = cpe_match.get("criteria", "")
    parsed = parse_cpe_string(criteria)
    if not parsed:
        return None

    vendor, product_name, cpe_version = parsed

    version_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
    version_start_including = "versionStartIncluding" in cpe_match
    version_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
    version_end_including = "versionEndIncluding" in cpe_match

    single_version = None
    if cpe_version and cpe_version != "*" and not version_start and not version_end:
        single_version = cpe_version

    cpe_parts = criteria.split(":")
    part = cpe_parts[2] if len(cpe_parts) > 2 else None

    return {
        "vendor": vendor,
        "product": product_name,
        "cpe_string": criteria,
        "version_start": version_start,
        "version_start_including": version_start_including,
        "version_end": version_end,
        "version_end_including": version_end_including,
        "single_version": single_version,
        "condition_group": None,
        "config_path": " > ".join(config_path),
        "is_vulnerable_match": bool(cpe_match.get("vulnerable", False)),
        "match_context": {
            "config_index": config_index,
            "path": config_path,
            "operator_path": operator_path,
            "match_criteria_id": cpe_match.get("matchCriteriaId"),
            "part": part,
            "vulnerable": bool(cpe_match.get("vulnerable", False)),
            "criteria": criteria,
        },
    }


def _combine_groups_and(term_group_sets: list[list[list[dict]]]) -> list[list[dict]]:
    """Return the cartesian product of term groups for AND nodes."""
    if not term_group_sets:
        return []

    combined: list[list[dict]] = [[]]
    for group_set in term_group_sets:
        combined = [left + right for left, right in product(combined, group_set)]
    return combined


def _extract_groups_from_node(
    node: dict,
    *,
    config_index: int,
    config_path: list[str],
    operator_path: list[str],
) -> list[list[dict]]:
    """Recursively flatten an NVD node tree into OR-ed conjunction groups."""
    if node.get("negate"):
        logger.warning(
            "Skipping negated NVD node at %s for config %s",
            " > ".join(config_path),
            config_index,
        )
        return []

    operator = str(node.get("operator", "OR")).upper()
    next_operator_path = operator_path + [operator]
    term_group_sets: list[list[list[dict]]] = []

    for match_index, cpe_match in enumerate(node.get("cpeMatch", [])):
        entry = _build_affected_entry(
            cpe_match,
            config_index=config_index,
            config_path=config_path + [f"cpeMatch[{match_index}]"],
            operator_path=next_operator_path,
        )
        if entry:
            term_group_sets.append([[entry]])

    for child_index, child in enumerate(node.get("children", [])):
        child_groups = _extract_groups_from_node(
            child,
            config_index=config_index,
            config_path=config_path + [f"children[{child_index}]"],
            operator_path=next_operator_path,
        )
        if child_groups:
            term_group_sets.append(child_groups)

    if not term_group_sets:
        return []

    if operator == "AND":
        return _combine_groups_and(term_group_sets)

    flattened: list[list[dict]] = []
    for group_set in term_group_sets:
        flattened.extend(group_set)
    return flattened


def _extract_affected_products(cve_data: dict) -> list[dict]:
    """Flatten NVD's nested CPE configuration tree into simple records.

    NVD configurations can be deeply nested (AND/OR logic between nodes).
    We normalize them into OR-ed groups of conjunction terms:

    - OR means any group can satisfy the CVE
    - AND means every entry in that group must be present in the user's stack

    We keep both vulnerable targets and non-vulnerable environment constraints
    so the matcher can avoid false positives for OS- or platform-specific CVEs.
    """
    flattened: list[dict] = []
    group_counter = 0

    for config_index, config in enumerate(cve_data.get("configurations", [])):
        for node_index, node in enumerate(config.get("nodes", [])):
            groups = _extract_groups_from_node(
                node,
                config_index=config_index,
                config_path=[f"configurations[{config_index}]", f"nodes[{node_index}]"],
                operator_path=[],
            )

            for group in groups:
                group_id = f"config_{config_index}_group_{group_counter}"
                group_counter += 1

                for leaf_index, entry in enumerate(group):
                    entry["condition_group"] = group_id
                    context = dict(entry.get("match_context") or {})
                    context["group_id"] = group_id
                    context["group_size"] = len(group)
                    context["group_leaf_index"] = leaf_index
                    entry["match_context"] = context
                    flattened.append(entry)

    return flattened


# ── Database upserts ──────────────────────────────────────────────────────────

def upsert_cve(
    db: Session,
    cve_data: dict,
    tracked_products: set[tuple[str, str]] | None = None,
) -> str | None:
    """Insert or update one CVE record. Returns cve_id on success, None on skip.

    When ``tracked_products`` is provided, the CVE is only persisted if at least
    one of its affected products is something we monitor (catalog + user stacks).
    Passing ``None`` disables the filter and stores the CVE unconditionally —
    used by the targeted per-product backfill, where every result is relevant by
    construction. The full NVD JSON blob is intentionally NOT stored (it was the
    dominant storage cost); anything we need is flattened into columns here.
    """
    cve_id = cve_data.get("id")
    if not cve_id:
        return None

    affected = _extract_affected_products(cve_data)

    # Relevance gate — the core of the storage fix. A CVE that touches no tracked
    # product can never appear on anyone's dashboard, so we do not store it.
    if tracked_products is not None:
        if not any((ap["vendor"], ap["product"]) in tracked_products for ap in affected):
            return None

    cvss_score, cvss_vector = _extract_cvss(cve_data)
    description = _extract_description(cve_data)
    references = _extract_references(cve_data)

    published_str = cve_data.get("published")
    modified_str = cve_data.get("lastModified")

    published_at = datetime.fromisoformat(published_str.replace("Z", "+00:00")) if published_str else None
    last_modified = datetime.fromisoformat(modified_str.replace("Z", "+00:00")) if modified_str else None

    now = datetime.now(timezone.utc)

    # PostgreSQL upsert: INSERT ... ON CONFLICT (cve_id) DO UPDATE SET ...
    # This is atomic — no race conditions between concurrent workers.
    stmt = (
        pg_insert(Cve)
        .values(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            published_at=published_at,
            last_modified=last_modified,
            references=references,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=["cve_id"],
            set_={
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "last_modified": last_modified,
                "references": references,
                "updated_at": now,
            },
        )
    )
    db.execute(stmt)

    # Delete old affected products for this CVE and re-insert.
    # This is simpler than diffing — affected products rarely change,
    # and when they do, a full replace is correct.
    db.query(CveAffectedProduct).filter(CveAffectedProduct.cve_id == cve_id).delete()

    if affected:
        now = datetime.now(timezone.utc)
        for ap in affected:
            db.add(CveAffectedProduct(cve_id=cve_id, created_at=now, **ap))

    return cve_id


def process_nvd_page(
    db: Session,
    vulnerabilities: list[dict],
    tracked_products: set[tuple[str, str]] | None = None,
) -> tuple[int, int]:
    """Process one page of NVD results. Returns (inserted_count, error_count).

    ``tracked_products`` is forwarded to :func:`upsert_cve` so irrelevant CVEs
    are skipped. CVEs skipped by the relevance gate are not counted as inserted.
    """
    inserted = 0
    errors = 0

    for item in vulnerabilities:
        cve_data = item.get("cve", {})
        try:
            cve_id = upsert_cve(db, cve_data, tracked_products)
            if cve_id:
                inserted += 1
        except Exception as e:
            logger.error("Failed to upsert CVE %s: %s", cve_data.get("id", "unknown"), e)
            errors += 1

    try:
        db.commit()
    except Exception as e:
        logger.error("Failed to commit batch: %s", e)
        db.rollback()
        errors += len(vulnerabilities)
        inserted = 0

    return inserted, errors


def _queue_full_match_rebuild() -> dict[str, str | bool | None]:
    """Queue a full match rebuild after a full NVD bootstrap."""
    from app.tasks.matcher import run_matcher_for_all_users

    try:
        task = run_matcher_for_all_users.delay()
    except Exception as exc:
        logger.warning("Could not queue full match rebuild after NVD bootstrap: %s", exc, exc_info=True)
        return {
            "queued": False,
            "task_id": None,
            "message": str(exc),
        }

    return {
        "queued": True,
        "task_id": task.id,
        "message": None,
    }


def _queue_matcher_for_cves(cve_ids: list[str], *, reason: str) -> dict[str, str | bool | int | None]:
    """Queue a targeted rematch for a list of CVEs."""
    from app.tasks.matcher import queue_matcher_for_cves

    if not cve_ids:
        return {"queued": False, "task_id": None, "message": "No CVEs to re-match."}

    return queue_matcher_for_cves(cve_ids, reason=reason)


# ── Celery tasks ──────────────────────────────────────────────────────────────

@shared_task(
    name="app.tasks.nvd_sync.sync_nvd_incremental",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def sync_nvd_incremental(self) -> dict:
    """Fetch CVEs modified in the last 2 hours. Runs hourly via Celery beat.

    We use a 2-hour window (not 1-hour) to avoid missing CVEs that were
    modified right at the boundary of the last sync window.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=2)

    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": settings.NVD_RESULTS_PER_PAGE,
        "startIndex": 0,
    }
    run_id = start_sync_run(
        "nvd_incremental",
        trigger_source="celery_task",
        details={
            "last_mod_start": params["lastModStartDate"],
            "last_mod_end": params["lastModEndDate"],
        },
    )
    log_structured_event(
        logger,
        logging.INFO,
        "nvd_sync_started",
        mode="incremental",
        run_id=run_id,
        last_mod_start=params["lastModStartDate"],
        last_mod_end=params["lastModEndDate"],
    )

    logger.info("Starting incremental NVD sync: %s to %s", start.isoformat(), now.isoformat())

    total_inserted = 0
    total_errors = 0
    cve_ids_updated = []
    matcher_queue = {"queued": False, "task_id": None, "message": None}

    try:
        data = fetch_nvd_page(params)
        total_results = data.get("totalResults", 0)
        logger.info("NVD incremental: %d CVEs to process", total_results)

        with SyncSessionLocal() as db:
            tracked_products = load_tracked_products(db)
            inserted, errors = process_nvd_page(
                db, data.get("vulnerabilities", []), tracked_products
            )
            total_inserted += inserted
            total_errors += errors
            cve_ids_updated.extend([
                v["cve"]["id"] for v in data.get("vulnerabilities", [])
                if "cve" in v and "id" in v["cve"]
            ])

        # After ingestion, trigger the matcher for updated CVEs
        if cve_ids_updated:
            matcher_queue = _queue_matcher_for_cves(cve_ids_updated, reason="NVD incremental sync")

    except Exception as exc:
        log_structured_event(
            logger,
            logging.ERROR,
            "nvd_sync_failed",
            mode="incremental",
            run_id=run_id,
            error=str(exc),
            inserted=total_inserted,
            errors=total_errors,
            cves_updated=len(cve_ids_updated),
        )
        logger.error("NVD incremental sync failed: %s", exc, exc_info=True)
        finish_sync_run(
            run_id,
            status="failed",
            details={
                "inserted": total_inserted,
                "errors": total_errors,
                "cves_updated": len(cve_ids_updated),
                "matcher_queue": matcher_queue,
            },
            error_message=str(exc),
        )
        raise self.retry(exc=exc)

    result = {
        "inserted": total_inserted,
        "errors": total_errors,
        "cves_updated": len(cve_ids_updated),
        "matcher_queue": matcher_queue,
    }
    finish_sync_run(run_id, status="success", details=result)
    log_structured_event(logger, logging.INFO, "nvd_sync_finished", mode="incremental", run_id=run_id, **result)
    logger.info("NVD incremental sync complete: %s", result)
    return result


@shared_task(
    name="app.tasks.nvd_sync.sync_nvd_full",
    bind=True,
    time_limit=3600,      # 1 hour hard limit
    soft_time_limit=3300, # 55 min soft limit
)
def sync_nvd_full(self, trigger_match_rebuild: bool = True) -> dict:
    """Full NVD sync — fetch all 250,000+ CVEs.

    Run this once to bootstrap the database:
      docker compose exec worker celery -A app.tasks.celery_app call app.tasks.nvd_sync.sync_nvd_full

    Takes 20-40 minutes depending on API key availability.
    Uses pagination: fetches 2000 CVEs per request.
    """
    logger.info("Starting FULL NVD sync — this will take 20-40 minutes")
    run_id = start_sync_run(
        "nvd_full",
        trigger_source="celery_task",
        details={
            "results_per_page": settings.NVD_RESULTS_PER_PAGE,
            "trigger_match_rebuild": trigger_match_rebuild,
        },
    )
    log_structured_event(
        logger,
        logging.INFO,
        "nvd_sync_started",
        mode="full",
        run_id=run_id,
        results_per_page=settings.NVD_RESULTS_PER_PAGE,
        trigger_match_rebuild=trigger_match_rebuild,
    )

    total_inserted = 0
    total_errors = 0
    start_index = 0
    total_results = 0

    try:
        # First request to get total count
        params = {
            "resultsPerPage": settings.NVD_RESULTS_PER_PAGE,
            "startIndex": 0,
        }
        first_page = fetch_nvd_page(params)
        total_results = first_page.get("totalResults", 0)
        logger.info("Total CVEs in NVD: %d", total_results)

        # The set of monitored products is fixed for the duration of one sync;
        # load it once and reuse it for every page. Only CVEs touching one of
        # these products are stored — this is what keeps the DB small.
        with SyncSessionLocal() as db:
            tracked_products = load_tracked_products(db)
        logger.info("Scoping full sync to %d tracked products", len(tracked_products))

        # Process first page
        with SyncSessionLocal() as db:
            inserted, errors = process_nvd_page(
                db, first_page.get("vulnerabilities", []), tracked_products
            )
            total_inserted += inserted
            total_errors += errors

        start_index = settings.NVD_RESULTS_PER_PAGE

        # Fetch remaining pages
        while start_index < total_results:
            _rate_limit_sleep()

            params["startIndex"] = start_index
            try:
                data = fetch_nvd_page(params)
            except Exception as e:
                logger.error("Failed to fetch page at startIndex=%d: %s", start_index, e)
                start_index += settings.NVD_RESULTS_PER_PAGE
                continue

            with SyncSessionLocal() as db:
                inserted, errors = process_nvd_page(
                    db, data.get("vulnerabilities", []), tracked_products
                )
                total_inserted += inserted
                total_errors += errors

            start_index += settings.NVD_RESULTS_PER_PAGE
            progress_pct = min(100, (start_index / total_results) * 100)
            logger.info(
                "NVD full sync progress: %d/%d (%.1f%%) — inserted=%d errors=%d",
                start_index, total_results, progress_pct, total_inserted, total_errors,
            )

    except Exception as exc:
        log_structured_event(
            logger,
            logging.ERROR,
            "nvd_sync_failed",
            mode="full",
            run_id=run_id,
            error=str(exc),
            total=total_results,
            inserted=total_inserted,
            errors=total_errors,
            last_start_index=start_index,
        )
        logger.error("NVD full sync failed at index %d: %s", start_index, exc, exc_info=True)
        finish_sync_run(
            run_id,
            status="failed",
            details={
                "total": total_results,
                "inserted": total_inserted,
                "errors": total_errors,
                "last_start_index": start_index,
            },
            error_message=str(exc),
        )
        raise

    match_rebuild = _queue_full_match_rebuild() if trigger_match_rebuild else {
        "queued": False,
        "task_id": None,
        "message": "Full sync completed without auto-queuing match rebuild.",
    }
    result = {
        "total": total_results,
        "inserted": total_inserted,
        "errors": total_errors,
        "match_rebuild": match_rebuild,
    }
    finish_sync_run(run_id, status="success", details=result)
    log_structured_event(logger, logging.INFO, "nvd_sync_finished", mode="full", run_id=run_id, **result)
    logger.info("NVD full sync complete: %s", result)
    return result


@shared_task(
    name="app.tasks.nvd_sync.sync_nvd_for_products",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    time_limit=600,
    soft_time_limit=540,
)
def sync_nvd_for_products(self, products: list[list[str]]) -> dict:
    """Backfill historical CVEs for specific ``(vendor, cpe_product)`` pairs.

    Because the scheduled syncs only store CVEs for already-tracked products, a
    product a user adds for the very first time would otherwise have no history
    until the next full sync. This task closes that gap: it is queued when a
    stack item is added, and pulls that product's CVEs directly from NVD via the
    ``virtualMatchString`` CPE filter. Every returned CVE matches the requested
    product by construction, so we store it unconditionally (``tracked_products``
    is intentionally ``None``). Best-effort and per-product isolated: one bad
    product does not abort the others.
    """
    pairs = [(v, p) for v, p in (tuple(item) for item in products) if v and p]
    if not pairs:
        return {"products": 0, "inserted": 0, "errors": 0, "cve_ids": []}

    total_inserted = 0
    total_errors = 0
    backfilled_cve_ids: list[str] = []

    for vendor, product in pairs:
        match_string = f"cpe:2.3:a:{vendor}:{product}"
        start_index = 0
        total_results = 0
        try:
            while True:
                params = {
                    "virtualMatchString": match_string,
                    "resultsPerPage": settings.NVD_RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
                data = fetch_nvd_page(params)
                total_results = data.get("totalResults", 0)
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                with SyncSessionLocal() as db:
                    # tracked_products=None → store every result; they all match
                    # the requested product's CPE.
                    inserted, errors = process_nvd_page(db, vulns, None)
                total_inserted += inserted
                total_errors += errors
                backfilled_cve_ids.extend(
                    v["cve"]["id"] for v in vulns if "cve" in v and "id" in v["cve"]
                )

                start_index += settings.NVD_RESULTS_PER_PAGE
                if start_index >= total_results:
                    break
                _rate_limit_sleep()
        except Exception as exc:  # noqa: BLE001 — best-effort per product
            total_errors += 1
            log_structured_event(
                logger,
                logging.WARNING,
                "nvd_product_backfill_failed",
                vendor=vendor,
                product=product,
                match_string=match_string,
                error=str(exc),
                error_type=type(exc).__name__,
            )

    # Re-match the freshly stored CVEs so dashboards populate immediately.
    if backfilled_cve_ids:
        _queue_matcher_for_cves(backfilled_cve_ids, reason="NVD per-product backfill")

    result = {
        "products": len(pairs),
        "inserted": total_inserted,
        "errors": total_errors,
        "cve_ids": len(backfilled_cve_ids),
    }
    log_structured_event(logger, logging.INFO, "nvd_product_backfill_finished", **result)
    return result
