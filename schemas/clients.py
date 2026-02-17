"""Relacionado a los Schemas en la APP"""

from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime


# Clases Client(Base)
class ClientBase(BaseModel):
    ip_address: str = Field(min_length=7, max_length=64)
    description: str = Field(min_length=7, max_length=255)


class ClientResponsePublic(ClientBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime


class ApprovedClient(BaseModel):
    id: int
    ip_address: str
    description: str | None
    created_at: datetime


class ApprovedClientCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip_address: str
    description: str | None = None


class ApprovedClientResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    description: str | None
    created_at: datetime
