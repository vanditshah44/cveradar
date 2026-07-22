import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.api.settings import update_settings
from app.models.match import UserCveMatch
from app.models.notification import Notification
from app.models.stack_item import StackItem
from app.models.user import User
from app.schemas.settings import NotificationSettings


class FakeAsyncSession:
    def __init__(self):
        self.flushed = False

    async def flush(self):
        self.flushed = True


def test_update_settings_flushes_and_returns_saved_values():
    # id is required: update_settings emits a structured log carrying user_id.
    user = SimpleNamespace(id=uuid4(), daily_digest=True, instant_alerts=False)
    db = FakeAsyncSession()

    result = asyncio.run(
        update_settings(
            NotificationSettings(daily_digest=False, instant_alerts=True),
            current_user=user,
            db=db,
        )
    )

    assert db.flushed is True
    assert result.daily_digest is False
    assert result.instant_alerts is True
    assert user.daily_digest is False
    assert user.instant_alerts is True


def test_user_relationships_delete_children_with_delete_orphan():
    assert "delete" in User.stack_items.property.cascade
    assert "delete-orphan" in User.stack_items.property.cascade
    assert "delete" in User.cve_matches.property.cascade
    assert "delete-orphan" in User.cve_matches.property.cascade
    assert "delete" in User.notifications.property.cascade
    assert "delete-orphan" in User.notifications.property.cascade


def test_user_owned_foreign_keys_use_database_level_cascade():
    stack_user_fk = next(iter(StackItem.__table__.c.user_id.foreign_keys))
    match_user_fk = next(iter(UserCveMatch.__table__.c.user_id.foreign_keys))
    notification_user_fk = next(iter(Notification.__table__.c.user_id.foreign_keys))

    assert stack_user_fk.ondelete == "CASCADE"
    assert match_user_fk.ondelete == "CASCADE"
    assert notification_user_fk.ondelete == "CASCADE"
