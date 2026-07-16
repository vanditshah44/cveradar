"""
stats.py — Dashboard stats endpoint.

GET /api/stats → {total_cves, critical_count, kev_count, new_since_last_visit,
                   severity_distribution, top_products}

Called on every dashboard load. Drives the header stats bar and sidebar analytics.
Fast because user_cve_matches has indexes on (user_id, dismissed) and (user_id, seen_at).
"""
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import Depends
from fastapi.routing import APIRouter
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user_dep
from app.database import get_db
from app.models.cve import Cve
from app.models.match import UserCveMatch
from app.models.stack_item import StackItem
from app.models.user import User
from app.schemas.cve import SeverityDistributionItem, StatsOut, TopProductItem
from app.services.priority import severity_label

router = APIRouter(prefix="/api/stats", tags=["stats"])

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]


@router.get("", response_model=StatsOut)
async def get_stats(
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    base_filters = (
        UserCveMatch.user_id == current_user.id,
        UserCveMatch.dismissed == False,  # noqa: E712
    )
    distinct_cve_count = func.count(func.distinct(UserCveMatch.cve_id))

    total = (await db.execute(
        select(distinct_cve_count).where(*base_filters)
    )).scalar_one()

    critical = (await db.execute(
        select(distinct_cve_count)
        .select_from(UserCveMatch)
        .join(Cve, UserCveMatch.cve_id == Cve.cve_id)
        .where(*base_filters, Cve.cvss_score >= 9.0)
    )).scalar_one()

    kev = (await db.execute(
        select(distinct_cve_count)
        .select_from(UserCveMatch)
        .join(Cve, UserCveMatch.cve_id == Cve.cve_id)
        .where(*base_filters, Cve.kev_flag == True)  # noqa: E712
    )).scalar_one()

    # "new since last visit" = unseen matches created after user's last_seen_at
    new_cutoff = current_user.last_seen_at
    new_query = select(distinct_cve_count).where(
        *base_filters,
        UserCveMatch.seen_at == None,  # noqa: E711
    )
    if new_cutoff:
        new_query = new_query.where(UserCveMatch.matched_at > new_cutoff)

    new = (await db.execute(new_query)).scalar_one()

    # ── Severity distribution (all user CVEs, server-side) ────────────────────
    # One row per (cve_id, cvss_score) — take MAX priority per CVE to deduplicate
    sev_rows = (await db.execute(
        select(Cve.cve_id, func.max(Cve.cvss_score).label("max_cvss"))
        .select_from(UserCveMatch)
        .join(Cve, UserCveMatch.cve_id == Cve.cve_id)
        .where(*base_filters)
        .group_by(Cve.cve_id)
    )).all()

    sev_counts: dict[str, int] = defaultdict(int)
    for _, cvss in sev_rows:
        sev_counts[severity_label(cvss)] += 1

    severity_distribution = [
        SeverityDistributionItem(severity=sev, count=sev_counts[sev])
        for sev in _SEV_ORDER
        if sev_counts.get(sev, 0) > 0
    ]

    # ── Top exposed products (all user CVEs, server-side) ────────────────────
    product_rows = (await db.execute(
        select(
            StackItem.product_name,
            func.count(func.distinct(UserCveMatch.cve_id)).label("cve_count"),
            func.count(func.distinct(
                UserCveMatch.cve_id
            )).filter(Cve.cvss_score >= 9.0).label("crit_count"),
            func.count(func.distinct(
                UserCveMatch.cve_id
            )).filter(Cve.kev_flag == True).label("kev_count"),  # noqa: E712
        )
        .select_from(UserCveMatch)
        .join(Cve, UserCveMatch.cve_id == Cve.cve_id)
        .join(StackItem, UserCveMatch.stack_item_id == StackItem.id)
        .where(*base_filters)
        .group_by(StackItem.product_name)
        .order_by(func.count(func.distinct(UserCveMatch.cve_id)).desc())
        .limit(6)
    )).all()

    top_products = [
        TopProductItem(
            name=row.product_name,
            count=row.cve_count,
            crit_count=row.crit_count,
            kev_count=row.kev_count,
        )
        for row in product_rows
    ]

    return StatsOut(
        total_cves=total,
        critical_count=critical,
        kev_count=kev,
        new_since_last_visit=new,
        severity_distribution=severity_distribution,
        top_products=top_products,
    )


@router.post("/visit", status_code=200)
async def mark_dashboard_visit(
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    current_user.last_seen_at = datetime.now(timezone.utc)
    await db.flush()
    return {"ok": True, "last_seen_at": current_user.last_seen_at.isoformat()}
