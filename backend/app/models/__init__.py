"""
Import all models here so Alembic can find them when it autogenerates migrations.
If a model isn't imported here, Alembic won't know it exists.
"""
from app.models.user import User
from app.models.stack_item import StackItem
from app.models.cve import Cve, CveAffectedProduct
from app.models.match import UserCveMatch
from app.models.notification import Notification
from app.models.product_catalog import ProductCatalog
from app.models.sync_run import SyncRun

__all__ = [
    "User",
    "StackItem",
    "Cve",
    "CveAffectedProduct",
    "UserCveMatch",
    "Notification",
    "ProductCatalog",
    "SyncRun",
]
