from pydantic import BaseModel


class NotificationSettings(BaseModel):
    daily_digest: bool
    instant_alerts: bool
