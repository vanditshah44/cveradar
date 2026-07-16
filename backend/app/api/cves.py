"""
cves.py — CVE endpoints (user's matched CVEs).

GET  /api/cves              → list matched CVEs with filters
GET  /api/cves/{cve_id}     → full CVE detail
POST /api/cves/{cve_id}/seen     → mark as seen
POST /api/cves/{cve_id}/dismiss  → dismiss from dashboard
"""
import logging
from datetime import datetime, timezone
from math import ceil
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user_dep
from app.database import get_db
from app.models.cve import Cve, CveAffectedProduct
from app.models.match import UserCveMatch
from app.models.stack_item import StackItem
from app.models.user import User
from app.schemas.cve import (
    AffectedProductOut,
    CveDetailOut,
    CveListItemOut,
    CveListOut,
    CveReferenceOut,
    MatchedStackItemOut,
)
from app.services.priority import severity_label
from app.services.seen_state import resolve_seen_at
from app.services.notification_email import format_affected_version_range, pick_useful_reference

router = APIRouter(prefix="/api/cves", tags=["cves"])
logger = logging.getLogger(__name__)
SortBy = Literal["priority", "published", "cvss", "product"]

# Validated CVE-ID path param — rejects anything that doesn't look like CVE-YYYY-NNNNN
CveIdPath = Annotated[str, Path(pattern=r"^CVE-\d{4}-\d{4,}$")]

MIN_DT = datetime.min.replace(tzinfo=timezone.utc)


def _severity_ranges() -> dict[str, tuple[float, float]]:
    return {
        "critical": (9.0, 10.1),
        "high": (7.0, 9.0),
        "medium": (4.0, 7.0),
        "low": (0.1, 4.0),
    }


def _aggregate_cve_rows(rows) -> list[CveListItemOut]:
    grouped: dict[str, dict] = {}

    for match, cve, stack_item in rows:
        group = grouped.get(cve.cve_id)
        if group is None:
            group = {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_score": cve.cvss_score,
                "cvss_vector": cve.cvss_vector,
                "epss_score": cve.epss_score,
                "kev_flag": cve.kev_flag,
                "kev_date_added": str(cve.kev_date_added) if cve.kev_date_added else None,
                "published_at": cve.published_at,
                "severity": severity_label(cve.cvss_score),
                "priority_score": match.priority_score,
                "matched_at": match.matched_at,
                "dismissed": match.dismissed,
                "product_names": {stack_item.product_name},
                "seen_values": [match.seen_at],
            }
            grouped[cve.cve_id] = group
            continue

        group["priority_score"] = max(group["priority_score"], match.priority_score)
        group["matched_at"] = max(group["matched_at"], match.matched_at)
        group["product_names"].add(stack_item.product_name)
        group["seen_values"].append(match.seen_at)

    items: list[CveListItemOut] = []
    for group in grouped.values():
        product_names = sorted(group["product_names"], key=str.lower)
        seen_values = group["seen_values"]
        seen_at = None if any(value is None for value in seen_values) else min(seen_values)

        items.append(
            CveListItemOut(
                cve_id=group["cve_id"],
                description=group["description"],
                cvss_score=group["cvss_score"],
                cvss_vector=group["cvss_vector"],
                epss_score=group["epss_score"],
                kev_flag=group["kev_flag"],
                kev_date_added=group["kev_date_added"],
                published_at=group["published_at"],
                severity=group["severity"],
                priority_score=group["priority_score"],
                matched_at=group["matched_at"],
                seen_at=seen_at,
                dismissed=group["dismissed"],
                primary_product_name=product_names[0] if product_names else "Unknown product",
                product_names=product_names,
                product_count=len(product_names),
            )
        )

    return items


def _sort_cve_items(items: list[CveListItemOut], sort_by: SortBy) -> list[CveListItemOut]:
    if sort_by == "published":
        return sorted(
            items,
            key=lambda item: (
                item.published_at is not None,
                item.published_at or MIN_DT,
                item.priority_score,
                item.cve_id,
            ),
            reverse=True,
        )
    if sort_by == "cvss":
        return sorted(
            items,
            key=lambda item: (
                item.cvss_score is not None,
                item.cvss_score or -1.0,
                item.priority_score,
                item.published_at or MIN_DT,
                item.cve_id,
            ),
            reverse=True,
        )
    if sort_by == "product":
        return sorted(
            items,
            key=lambda item: (
                item.primary_product_name.lower(),
                -item.priority_score,
                item.cve_id,
            ),
        )

    return sorted(
        items,
        key=lambda item: (
            item.priority_score,
            item.published_at or MIN_DT,
            item.cvss_score or -1.0,
            item.cve_id,
        ),
        reverse=True,
    )


def _normalize_reference_tags(tags) -> list[str] | None:
    if isinstance(tags, list):
        normalized = [str(tag) for tag in tags if tag is not None and str(tag).strip()]
        return normalized or None
    if isinstance(tags, str) and tags.strip():
        return [tags.strip()]
    return None


def _reference_out(reference) -> CveReferenceOut | None:
    if not isinstance(reference, dict):
        return None

    url = reference.get("url")
    source = reference.get("source")
    return CveReferenceOut(
        url=str(url) if url else None,
        source=str(source) if source else None,
        tags=_normalize_reference_tags(reference.get("tags")),
    )


def _normalize_match_context(value) -> dict | None:
    if isinstance(value, dict):
        return value
    return None


@router.get("", response_model=CveListOut)
async def list_cves(
    product: str | None = Query(None),
    severity: str | None = Query(None),
    kev_only: bool = Query(False),
    unseen_only: bool = Query(False),
    sort_by: SortBy = Query("priority"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    """List deduplicated CVEs matching the user's stack."""
    query = (
        select(UserCveMatch, Cve, StackItem)
        .join(Cve, UserCveMatch.cve_id == Cve.cve_id)
        .join(StackItem, UserCveMatch.stack_item_id == StackItem.id)
        .where(
            UserCveMatch.user_id == current_user.id,
            UserCveMatch.dismissed == False,  # noqa: E712
        )
    )

    if kev_only:
        query = query.where(Cve.kev_flag == True)  # noqa: E712
    if unseen_only:
        query = query.where(UserCveMatch.seen_at == None)  # noqa: E711
    if product:
        product_filter = f"%{product}%"
        query = query.where(
            or_(
                StackItem.product_name.ilike(product_filter),
                StackItem.cpe_product.ilike(product_filter),
                StackItem.vendor.ilike(product_filter),
            )
        )
    if severity:
        r = _severity_ranges().get(severity.lower())
        if r:
            query = query.where(Cve.cvss_score >= r[0], Cve.cvss_score < r[1])

    result = await db.execute(query)
    rows = result.all()
    items = _sort_cve_items(_aggregate_cve_rows(rows), sort_by)
    total_items = len(items)
    total_pages = ceil(total_items / per_page) if total_items else 0
    start = (page - 1) * per_page
    page_items = items[start:start + per_page]

    return CveListOut(
        items=page_items,
        page=page,
        per_page=per_page,
        total_items=total_items,
        total_pages=total_pages,
        sort_by=sort_by,
    )


@router.get("/{cve_id}", response_model=CveDetailOut)
async def get_cve_detail(
    cve_id: CveIdPath,
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    """Full CVE detail — includes references and affected products."""
    result = await db.execute(
        select(UserCveMatch, Cve, StackItem)
        .join(Cve, UserCveMatch.cve_id == Cve.cve_id)
        .join(StackItem, UserCveMatch.stack_item_id == StackItem.id)
        .where(
            UserCveMatch.user_id == current_user.id,
            UserCveMatch.cve_id == cve_id,
        )
        .order_by(
            UserCveMatch.priority_score.desc(),
            UserCveMatch.matched_at.desc(),
            StackItem.product_name.asc(),
        )
    )
    rows = result.all()
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found in your matches")

    _, cve, primary_stack_item = rows[0]
    seen_values = [match.seen_at for match, _, _ in rows]
    seen_at = None if any(value is None for value in seen_values) else min(seen_values)
    matched_at = max(match.matched_at for match, _, _ in rows)
    priority_score = max(match.priority_score for match, _, _ in rows)

    matched_stack_items: list[MatchedStackItemOut] = []
    seen_stack_item_ids = set()
    for match, _, stack_item in rows:
        if stack_item.id in seen_stack_item_ids:
            continue
        seen_stack_item_ids.add(stack_item.id)
        matched_stack_items.append(
            MatchedStackItemOut(
                id=stack_item.id,
                product_name=stack_item.product_name,
                vendor=stack_item.vendor,
                cpe_product=stack_item.cpe_product,
                version=stack_item.version,
                category=stack_item.category,
                matched_at=match.matched_at,
                seen_at=match.seen_at,
            )
        )

    # Fetch affected products for context
    affected: list[AffectedProductOut] = []
    try:
        ap_result = await db.execute(
            select(CveAffectedProduct)
            .where(CveAffectedProduct.cve_id == cve_id)
            .order_by(
                CveAffectedProduct.is_vulnerable_match.desc(),
                CveAffectedProduct.vendor.asc(),
                CveAffectedProduct.product.asc(),
                CveAffectedProduct.single_version.asc().nulls_last(),
                CveAffectedProduct.version_start.asc().nulls_last(),
                CveAffectedProduct.version_end.asc().nulls_last(),
            )
        )
        affected = [
            AffectedProductOut(
                vendor=ap.vendor,
                product=ap.product,
                version_start=ap.version_start,
                version_start_including=ap.version_start_including,
                version_end=ap.version_end,
                version_end_including=ap.version_end_including,
                single_version=ap.single_version,
                condition_group=ap.condition_group,
                config_path=ap.config_path,
                is_vulnerable_match=ap.is_vulnerable_match,
                match_context=_normalize_match_context(ap.match_context),
                range_display=format_affected_version_range(ap),
            )
            for ap in ap_result.scalars().all()
        ]
    except Exception as exc:
        logger.warning(
            "Could not load affected product rules for CVE detail %s: %s",
            cve_id,
            exc,
            exc_info=True,
        )
        affected = []

    references = [
        reference_out
        for reference_out in (_reference_out(reference) for reference in (cve.references or []))
        if reference_out is not None
    ]
    useful_reference = _reference_out(pick_useful_reference(cve))

    return CveDetailOut(
        cve_id=cve.cve_id,
        description=cve.description,
        cvss_score=cve.cvss_score,
        cvss_vector=cve.cvss_vector,
        epss_score=cve.epss_score,
        kev_flag=cve.kev_flag,
        kev_date_added=str(cve.kev_date_added) if cve.kev_date_added else None,
        published_at=cve.published_at,
        severity=severity_label(cve.cvss_score),
        priority_score=priority_score,
        matched_at=matched_at,
        seen_at=seen_at,
        dismissed=all(match.dismissed for match, _, _ in rows),
        stack_item_id=primary_stack_item.id,
        product_name=primary_stack_item.product_name,
        references=references or None,
        useful_reference=useful_reference,
        matched_stack_items=matched_stack_items,
        affected_products=affected or None,
    )


@router.post("/{cve_id}/seen", status_code=status.HTTP_200_OK)
async def mark_seen(
    cve_id: CveIdPath,
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    seen_values = (
        await db.execute(
            select(UserCveMatch.seen_at)
            .where(
                UserCveMatch.user_id == current_user.id,
                UserCveMatch.cve_id == cve_id,
            )
        )
    ).scalars().all()
    if not seen_values:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found in your matches")

    existing_seen_at = min((seen_at for seen_at in seen_values if seen_at is not None), default=None)
    seen_at = resolve_seen_at(existing_seen_at, datetime.now(timezone.utc))
    await db.execute(
        update(UserCveMatch)
        .where(
            UserCveMatch.user_id == current_user.id,
            UserCveMatch.cve_id == cve_id,
            UserCveMatch.seen_at == None,  # noqa: E711
        )
        .values(seen_at=seen_at)
    )
    return {"ok": True, "seen_at": seen_at.isoformat()}


@router.post("/{cve_id}/dismiss", status_code=status.HTTP_200_OK)
async def dismiss_cve(
    cve_id: CveIdPath,
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    await db.execute(
        update(UserCveMatch)
        .where(UserCveMatch.user_id == current_user.id, UserCveMatch.cve_id == cve_id)
        .values(dismissed=True)
    )
    return {"ok": True}
