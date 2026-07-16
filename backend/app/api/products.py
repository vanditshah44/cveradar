"""
products.py — Product catalog endpoints (autocomplete for stack page).

GET /api/products/search?q=ngi  → search catalog by name (autocomplete)
GET /api/products/popular        → top popular products for onboarding

These endpoints don't require auth — the product catalog is public data.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.product_catalog import ProductCatalog

router = APIRouter(prefix="/api/products", tags=["products"])


@router.get("/search")
async def search_products(
    q: str = Query(..., min_length=1, max_length=100),
    db: AsyncSession = Depends(get_db),
):
    """Autocomplete search — returns up to 10 matching products.

    Searches display_name (case-insensitive). Used by the stack page
    product input field.
    """
    result = await db.execute(
        select(ProductCatalog)
        .where(ProductCatalog.display_name.ilike(f"%{q}%"))
        .order_by(ProductCatalog.popular.desc(), ProductCatalog.display_name)
        .limit(10)
    )
    products = result.scalars().all()

    return [
        {
            "id": str(p.id),
            "display_name": p.display_name,
            "vendor": p.vendor,
            "cpe_product": p.cpe_product,
            "category": p.category,
            "popular": p.popular,
        }
        for p in products
    ]


@router.get("/popular")
async def popular_products(db: AsyncSession = Depends(get_db)):
    """Return the top 20 popular products for the onboarding flow."""
    result = await db.execute(
        select(ProductCatalog)
        .where(ProductCatalog.popular == True)  # noqa: E712
        .order_by(ProductCatalog.display_name)
        .limit(20)
    )
    products = result.scalars().all()

    return [
        {
            "id": str(p.id),
            "display_name": p.display_name,
            "vendor": p.vendor,
            "cpe_product": p.cpe_product,
            "category": p.category,
            "popular": p.popular,
        }
        for p in products
    ]
