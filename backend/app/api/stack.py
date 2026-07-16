"""
stack.py — Stack management endpoints.

GET    /api/stack         → list user's stack items
POST   /api/stack         → add product to stack
PUT    /api/stack/{id}    → update version
DELETE /api/stack/{id}    → remove from stack

After add/update, we trigger async matching via Celery so the
user's dashboard starts populating with CVEs immediately.
"""
import uuid
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user_dep
from app.database import get_db
from app.models.stack_item import StackItem
from app.models.user import User
from app.schemas.stack import StackItemCreate, StackItemOut, StackItemUpdate, StackMutationOut
from app.services.matching import MatchDispatchResult, trigger_matching_for_user
from app.tasks.nvd_sync import sync_nvd_for_products
from app.services.structured_logging import log_structured_event

router = APIRouter(prefix="/api/stack", tags=["stack"])
logger = logging.getLogger(__name__)


def _build_stack_mutation_response(item: StackItem, dispatch: MatchDispatchResult) -> StackMutationOut:
    return StackMutationOut(
        id=item.id,
        product_name=item.product_name,
        vendor=item.vendor,
        cpe_product=item.cpe_product,
        version=item.version,
        cpe_string=item.cpe_string,
        category=item.category,
        added_at=item.added_at,
        matching_queued=dispatch.queued,
        matching_message=dispatch.message,
    )


@router.get("", response_model=list[StackItemOut])
async def list_stack(
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(StackItem)
        .where(StackItem.user_id == current_user.id)
        .order_by(StackItem.added_at.desc())
    )
    return result.scalars().all()


@router.post("", response_model=StackMutationOut, status_code=status.HTTP_201_CREATED)
async def add_to_stack(
    body: StackItemCreate,
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    item = StackItem(user_id=current_user.id, **body.model_dump())
    db.add(item)

    try:
        await db.flush()
    except IntegrityError:
        # The unique constraint (user_id, cpe_product, version) fired — duplicate entry.
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{body.product_name} {body.version} is already in your stack",
        )

    # Persist the stack item first so the request succeeds even if Redis/Celery
    # is temporarily unavailable.
    await db.commit()
    await db.refresh(item)

    # Backfill this product's historical CVEs from NVD. Scheduled syncs only store
    # CVEs for already-tracked products, so a brand-new product would otherwise
    # have no history until the next full sync. Best-effort — never blocks the add.
    try:
        sync_nvd_for_products.delay([[item.vendor, item.cpe_product]])
    except Exception as exc:  # noqa: BLE001 — Redis/Celery may be down; add still succeeds
        log_structured_event(
            logger,
            logging.WARNING,
            "stack_item_backfill_dispatch_failed",
            user_id=current_user.id,
            stack_item_id=item.id,
            vendor=item.vendor,
            cpe_product=item.cpe_product,
            error=str(exc),
            error_type=type(exc).__name__,
        )

    dispatch = trigger_matching_for_user(str(current_user.id))

    log_structured_event(
        logger,
        logging.INFO,
        "stack_item_added",
        user_id=current_user.id,
        stack_item_id=item.id,
        product_name=item.product_name,
        vendor=item.vendor,
        cpe_product=item.cpe_product,
        version=item.version,
        category=item.category,
        matching_queued=dispatch.queued,
    )
    if not dispatch.queued:
        log_structured_event(
            logger,
            logging.WARNING,
            "stack_item_matching_not_queued",
            operation="add",
            user_id=current_user.id,
            stack_item_id=item.id,
            product_name=item.product_name,
            version=item.version,
            error=dispatch.message,
        )

    return _build_stack_mutation_response(item, dispatch)


@router.put("/{item_id}", response_model=StackMutationOut)
async def update_stack_item(
    item_id: uuid.UUID,
    body: StackItemUpdate,
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(StackItem).where(StackItem.id == item_id, StackItem.user_id == current_user.id)
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stack item not found")

    item.version = body.version
    item.cpe_string = body.cpe_string

    await db.commit()
    await db.refresh(item)

    # Re-run matching for this user since their version changed
    dispatch = trigger_matching_for_user(str(current_user.id))

    log_structured_event(
        logger,
        logging.INFO,
        "stack_item_updated",
        user_id=current_user.id,
        stack_item_id=item.id,
        product_name=item.product_name,
        vendor=item.vendor,
        cpe_product=item.cpe_product,
        version=item.version,
        category=item.category,
        matching_queued=dispatch.queued,
    )
    if not dispatch.queued:
        log_structured_event(
            logger,
            logging.WARNING,
            "stack_item_matching_not_queued",
            operation="update",
            user_id=current_user.id,
            stack_item_id=item.id,
            product_name=item.product_name,
            version=item.version,
            error=dispatch.message,
        )

    return _build_stack_mutation_response(item, dispatch)


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_from_stack(
    item_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dep),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(StackItem).where(StackItem.id == item_id, StackItem.user_id == current_user.id)
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stack item not found")

    await db.delete(item)
    await db.commit()
    # Cascades will delete user_cve_matches for this stack item
    log_structured_event(
        logger,
        logging.INFO,
        "stack_item_removed",
        user_id=current_user.id,
        stack_item_id=item.id,
        product_name=item.product_name,
        vendor=item.vendor,
        cpe_product=item.cpe_product,
        version=item.version,
        category=item.category,
    )
