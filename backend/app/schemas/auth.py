import uuid
from pydantic import BaseModel, EmailStr


class MagicLinkRequest(BaseModel):
    email: EmailStr


class MagicLinkVerify(BaseModel):
    token: str


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    daily_digest: bool
    instant_alerts: bool

    model_config = {"from_attributes": True}
