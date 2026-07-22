"""
matcher.py — CPE matching engine (Celery task).

This task runs after every NVD/KEV ingestion. It compares every user's
stack against the newly updated CVE affected products and populates
user_cve_matches.

The matching query logic:
  1. Load affected-product rows for the target CVE(s)
  2. Cache candidate stack_items by (vendor, cpe_product) per CVE
  3. Apply version_in_range() in Python for the candidate items
  4. Bulk upsert matching rows into user_cve_matches

This runs in batch — not on every dashboard request. For a large user base,
the Python version comparison still dominates, so we keep the DB lookups
indexed and avoid repeating the same product query inside one CVE match pass.
"""
import logging
from collections import defaultdict
from datetime import datetime, timezone
import uuid

from celery import shared_task
from sqlalchemy import delete, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.database import SyncSessionLocal
from app.models.cve import Cve, CveAffectedProduct
from app.models.match import UserCveMatch
from app.models.stack_item import StackItem
from app.services.priority import compute_priority
from app.services.structured_logging import log_structured_event
from app.services.sync_runs import finish_sync_run, start_sync_run
from app.utils.version import version_in_range

logger = logging.getLogger(__name__)

MATCHER_QUEUE_CHUNK_SIZE = 250


def _normalize_cve_ids(cve_ids: list[str]) -> list[str]:
    """Deduplicate while preserving order so rematch fan-out stays predictable."""
    return list(dict.fromkeys(cve_ids))


def _iter_chunks(items: list[str], chunk_size: int):
    for start in range(0, len(items), chunk_size):
        yield items[start : start + chunk_size]


def queue_matcher_for_cves(cve_ids: list[str], *, reason: str) -> dict[str, str | bool | int | None]:
    """Queue rematching in bounded chunks so large syncs do not create one giant task."""
    normalized_cve_ids = _normalize_cve_ids(cve_ids)
    if not normalized_cve_ids:
        return {
            "queued": False,
            "task_id": None,
            "task_count": 0,
            "cves_queued": 0,
            "chunk_size": MATCHER_QUEUE_CHUNK_SIZE,
            "message": "No CVEs to re-match.",
        }

    task_ids: list[str] = []
    try:
        for chunk in _iter_chunks(normalized_cve_ids, MATCHER_QUEUE_CHUNK_SIZE):
            task = run_matcher_for_cves.delay(chunk)
            task_ids.append(task.id)
    except Exception as exc:
        cves_queued = min(len(task_ids) * MATCHER_QUEUE_CHUNK_SIZE, len(normalized_cve_ids))
        log_structured_event(
            logger,
            logging.WARNING,
            "matcher_queue_failed",
            reason=reason,
            task_name="app.tasks.matcher.run_matcher_for_cves",
            cves_requested=len(normalized_cve_ids),
            tasks_queued=len(task_ids),
            cves_queued=cves_queued,
            chunk_size=MATCHER_QUEUE_CHUNK_SIZE,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return {
            "queued": bool(task_ids),
            "task_id": task_ids[0] if task_ids else None,
            "task_count": len(task_ids),
            "cves_queued": cves_queued,
            "chunk_size": MATCHER_QUEUE_CHUNK_SIZE,
            "message": str(exc),
        }

    log_structured_event(
        logger,
        logging.INFO,
        "matcher_queue_chunked",
        reason=reason,
        task_name="app.tasks.matcher.run_matcher_for_cves",
        cves_requested=len(normalized_cve_ids),
        task_count=len(task_ids),
        chunk_size=MATCHER_QUEUE_CHUNK_SIZE,
    )
    return {
        "queued": True,
        "task_id": task_ids[0] if task_ids else None,
        "task_count": len(task_ids),
        "cves_queued": len(normalized_cve_ids),
        "chunk_size": MATCHER_QUEUE_CHUNK_SIZE,
        "message": None,
    }


def _stack_item_matches_requirement(stack_item: StackItem, requirement: CveAffectedProduct) -> bool:
    """Return True if a stack item satisfies one affected-product requirement."""
    if stack_item.vendor != requirement.vendor:
        return False
    if stack_item.cpe_product != requirement.product:
        return False

    return version_in_range(
        stack_item.version,
        requirement.version_start,
        requirement.version_start_including,
        requirement.version_end,
        requirement.version_end_including,
        requirement.single_version,
    )


def _candidate_stack_items_for_product(
    db,
    vendor: str,
    product: str,
    stack_item_cache: dict[tuple[str, str], list[StackItem]],
) -> list[StackItem]:
    cache_key = (vendor, product)
    if cache_key not in stack_item_cache:
        stack_item_cache[cache_key] = (
            db.execute(
                select(StackItem).where(
                    StackItem.vendor == vendor,
                    StackItem.cpe_product == product,
                )
            ).scalars().all()
        )
    return stack_item_cache[cache_key]


def _matching_stack_items_for_requirement(
    db,
    requirement: CveAffectedProduct,
    stack_item_cache: dict[tuple[str, str], list[StackItem]],
) -> list[StackItem]:
    """Return stack items that satisfy a single affected-product requirement."""
    stack_items = _candidate_stack_items_for_product(
        db,
        requirement.vendor,
        requirement.product,
        stack_item_cache,
    )

    return [stack_item for stack_item in stack_items if _stack_item_matches_requirement(stack_item, requirement)]


def _eligible_target_stack_items(
    requirements: list[CveAffectedProduct],
    requirement_matches: dict[uuid.UUID, list[StackItem]],
) -> list[StackItem]:
    """Return target stack items for users who satisfy every requirement in a group.

    This is the key AND/OR safety rule: every requirement in one condition_group
    must be satisfied by the same user, even if different stack items satisfy the
    individual requirements.
    """
    if not requirements:
        return []

    eligible_user_ids: set[uuid.UUID] | None = None
    for requirement in requirements:
        matches = requirement_matches.get(requirement.id, [])
        if not matches:
            return []

        matching_user_ids = {match.user_id for match in matches}
        if eligible_user_ids is None:
            eligible_user_ids = matching_user_ids
        else:
            eligible_user_ids &= matching_user_ids

        if not eligible_user_ids:
            return []

    target_requirements = [requirement for requirement in requirements if requirement.is_vulnerable_match]
    if not target_requirements or not eligible_user_ids:
        return []

    eligible_targets: list[StackItem] = []
    seen_stack_item_ids: set[uuid.UUID] = set()

    for requirement in target_requirements:
        for stack_item in requirement_matches.get(requirement.id, []):
            if stack_item.user_id not in eligible_user_ids:
                continue
            if stack_item.id in seen_stack_item_ids:
                continue
            seen_stack_item_ids.add(stack_item.id)
            eligible_targets.append(stack_item)

    return eligible_targets


def _reconcile_matches_for_cve(db, cve_id: str, matched_stack_item_ids: set[uuid.UUID]) -> None:
    """Delete stale matches for a CVE after recomputing the current truth set."""
    if matched_stack_item_ids:
        db.execute(
            delete(UserCveMatch).where(
                UserCveMatch.cve_id == cve_id,
                UserCveMatch.stack_item_id.notin_(matched_stack_item_ids),
            )
        )
        return

    db.execute(delete(UserCveMatch).where(UserCveMatch.cve_id == cve_id))


def match_cve_against_stacks(db, cve_id: str) -> int:
    """Find all users whose stack is affected by this CVE and upsert matches.

    Returns the number of new/updated matches created.
    """
    cve = db.get(Cve, cve_id)
    if not cve:
        return 0

    affected_products = (
        db.execute(
            select(CveAffectedProduct).where(CveAffectedProduct.cve_id == cve_id)
        ).scalars().all()
    )

    if not affected_products:
        _reconcile_matches_for_cve(db, cve_id, set())
        return 0

    grouped_requirements: dict[str, list[CveAffectedProduct]] = defaultdict(list)
    for affected_product in affected_products:
        group_id = affected_product.condition_group or f"ungrouped:{affected_product.id}"
        grouped_requirements[group_id].append(affected_product)

    matched_stack_item_ids: set = set()
    rows_to_upsert: dict[tuple[uuid.UUID, uuid.UUID], dict] = {}
    now = datetime.now(timezone.utc)
    priority = compute_priority(cve.cvss_score, cve.epss_score, cve.kev_flag)
    stack_item_cache: dict[tuple[str, str], list[StackItem]] = {}

    for group_id, requirements in grouped_requirements.items():
        requirement_matches: dict[uuid.UUID, list[StackItem]] = {}

        for requirement in requirements:
            matches = _matching_stack_items_for_requirement(db, requirement, stack_item_cache)
            if not matches:
                requirement_matches = {}
                break
            requirement_matches[requirement.id] = matches

        if not requirement_matches:
            continue

        eligible_targets = _eligible_target_stack_items(requirements, requirement_matches)
        if not eligible_targets:
            logger.debug("No vulnerable targets in group %s for %s; skipping user match creation", group_id, cve_id)
            continue

        for stack_item in eligible_targets:
            matched_stack_item_ids.add(stack_item.id)
            pair_key = (stack_item.user_id, stack_item.id)
            if pair_key in rows_to_upsert:
                continue

            rows_to_upsert[pair_key] = {
                "user_id": stack_item.user_id,
                "cve_id": cve_id,
                "stack_item_id": stack_item.id,
                "priority_score": priority,
                "matched_at": now,
            }

    if rows_to_upsert:
        stmt = (
            pg_insert(UserCveMatch)
            .values(list(rows_to_upsert.values()))
            .on_conflict_do_update(
                constraint="uq_match",
                # Only the score is recomputed. matched_at must keep the time the
                # CVE FIRST matched this stack item — refreshing it here made every
                # routine rematch (EPSS runs nightly, KEV hourly) look like a brand
                # new discovery, which resets the "new since last visit" badge and,
                # worse, pulls the whole backlog into the next daily digest because
                # that query selects on `matched_at >= now - 24h`.
                set_={"priority_score": priority},
            )
        )
        db.execute(stmt)

    _reconcile_matches_for_cve(db, cve_id, matched_stack_item_ids)

    return len(rows_to_upsert)


@shared_task(
    name="app.tasks.matcher.run_matcher_for_cves",
    bind=True,
    max_retries=2,
)
def run_matcher_for_cves(self, cve_ids: list[str]) -> dict:
    """Run the matcher for a specific list of CVE IDs.

    Called automatically by nvd_sync and kev_sync after ingestion.
    Also called directly when a user adds a new stack item.
    """
    normalized_cve_ids = _normalize_cve_ids(cve_ids)
    log_structured_event(
        logger,
        logging.INFO,
        "matcher_run_started",
        scope="cves",
        cves_requested=len(cve_ids),
        cves_unique=len(normalized_cve_ids),
        task_id=getattr(self.request, "id", None),
    )
    total_matches = 0
    errors = 0

    with SyncSessionLocal() as db:
        for cve_id in normalized_cve_ids:
            try:
                count = match_cve_against_stacks(db, cve_id)
                total_matches += count
            except Exception as e:
                log_structured_event(
                    logger,
                    logging.ERROR,
                    "matcher_cve_failed",
                    scope="cves",
                    cve_id=cve_id,
                    task_id=getattr(self.request, "id", None),
                    error=str(e),
                    error_type=type(e).__name__,
                )
                errors += 1

        try:
            db.commit()
        except Exception as e:
            logger.error("Matcher commit failed: %s", e)
            db.rollback()

    result = {"cves_processed": len(normalized_cve_ids), "matches_created": total_matches, "errors": errors}
    log_structured_event(logger, logging.INFO, "matcher_run_finished", scope="cves", **result)
    logger.info("Matcher complete: %s", result)
    return result


def rebuild_all_user_matches() -> dict:
    """Rebuild matches for every existing user.

    Useful after a full feed bootstrap or as a recovery/backfill operation.
    """
    with SyncSessionLocal() as db:
        user_ids = [str(user_id) for user_id in db.execute(select(StackItem.user_id).distinct()).scalars().all()]

    if not user_ids:
        return {"users_processed": 0, "matches_created": 0, "errors": 0}

    total_matches = 0
    errors = 0

    for user_id in user_ids:
        try:
            result = run_matcher_for_user(user_id)
            total_matches += int(result.get("matches_created", 0))
        except Exception as exc:
            logger.error("Matcher rebuild failed for user %s: %s", user_id, exc)
            errors += 1

    return {
        "users_processed": len(user_ids),
        "matches_created": total_matches,
        "errors": errors,
    }


@shared_task(name="app.tasks.matcher.run_matcher_for_user")
def run_matcher_for_user(user_id: str) -> dict:
    """Run matching for a single user against all existing CVEs.

    Called when a user adds a new stack item. We need to find all
    CVEs that already exist in our DB and match against the new item.
    """
    log_structured_event(logger, logging.INFO, "matcher_run_started", scope="user", user_id=user_id)
    with SyncSessionLocal() as db:
        # Get all CVE IDs that affect any product this user has in their stack
        stack_items = (
            db.execute(
                select(StackItem).where(StackItem.user_id == user_id)
            ).scalars().all()
        )

        if not stack_items:
            result = {"matches_created": 0}
            log_structured_event(logger, logging.INFO, "matcher_run_finished", scope="user", user_id=user_id, **result)
            return result

        # Get unique (vendor, product) pairs from user's stack
        user_products = {(s.vendor, s.cpe_product) for s in stack_items}

        product_filters = [
            (CveAffectedProduct.vendor == vendor) & (CveAffectedProduct.product == product)
            for vendor, product in sorted(user_products)
        ]
        cve_ids = db.execute(
            select(CveAffectedProduct.cve_id)
            .where(or_(*product_filters))
            .distinct()
        ).scalars().all()

        total_matches = 0
        for cve_id in _normalize_cve_ids(cve_ids):
            try:
                count = match_cve_against_stacks(db, cve_id)
                total_matches += count
            except Exception as e:
                log_structured_event(
                    logger,
                    logging.ERROR,
                    "matcher_cve_failed",
                    scope="user",
                    user_id=user_id,
                    cve_id=cve_id,
                    error=str(e),
                    error_type=type(e).__name__,
                )

        db.commit()

    result = {"matches_created": total_matches, "candidate_cves": len(cve_ids)}
    log_structured_event(logger, logging.INFO, "matcher_run_finished", scope="user", user_id=user_id, **result)
    return result


@shared_task(name="app.tasks.matcher.run_matcher_for_all_users")
def run_matcher_for_all_users() -> dict:
    """Rebuild matches for all users and record the run for observability."""
    log_structured_event(logger, logging.INFO, "matcher_run_started", scope="all_users")
    run_id = start_sync_run(
        "match_rebuild_all",
        trigger_source="celery_task",
        details={"scope": "all_users"},
    )

    try:
        result = rebuild_all_user_matches()
    except Exception as exc:
        finish_sync_run(run_id, status="failed", error_message=str(exc))
        raise

    finish_sync_run(run_id, status="success", details=result)
    log_structured_event(logger, logging.INFO, "matcher_run_finished", scope="all_users", **result)
    logger.info("Full match rebuild complete: %s", result)
    return result
