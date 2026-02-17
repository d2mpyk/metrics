from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime


# --- Schemas de Métricas ---
class EncryptedMetrics(BaseModel):
    nonce: str
    ciphertext: str


# --- Schemas de Clientes Aprobados ---
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


# --- Schemas de Clientes Registrados ---
class ClientBase(BaseModel):
    ip_address: str = Field(min_length=7, max_length=64)
    description: str = Field(min_length=7, max_length=255)


class ClientResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_identifier: str
    ip_address: str
    description: str | None
    is_active: bool
    created_at: datetime


class ClientResponsePublic(ClientBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


class PaginatedClientResponse(BaseModel):
    total: int
    clients: list[ClientResponse]
    description: str | None
