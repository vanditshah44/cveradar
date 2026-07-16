import uuid
from datetime import datetime
from pydantic import BaseModel, Field


class StackItemCreate(BaseModel):
    product_name: str = Field(..., min_length=1, max_length=200)
    vendor: str = Field(..., min_length=1, max_length=200)
    cpe_product: str = Field(..., min_length=1, max_length=200)
    version: str = Field(..., min_length=1, max_length=100)
    cpe_string: str = Field(..., min_length=1, max_length=500)
    category: str | None = Field(None, max_length=100)  # copied from ProductCatalog at add-time


class StackItemUpdate(BaseModel):
    version: str = Field(..., min_length=1, max_length=100)
    cpe_string: str = Field(..., min_length=1, max_length=500)


class StackItemOut(BaseModel):
    id: uuid.UUID
    product_name: str
    vendor: str
    cpe_product: str
    version: str
    cpe_string: str
    category: str | None
    added_at: datetime

    model_config = {"from_attributes": True}


class StackMutationOut(StackItemOut):
    matching_queued: bool
    matching_message: str | None = None
