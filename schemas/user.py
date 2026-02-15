"""Relacionado a los Schemas en la APP"""
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from datetime import datetime

# Clases USER (Base)
class UserBase(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    email: EmailStr = Field(max_length=120)

# Creación de User
class UserCreate(UserBase):
    password: str = Field(min_length=8)

# Respuesta de User
class UserResponsePublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    image_file: str | None
    image_path: str

class UserResponsePrivate(UserResponsePublic):
    email: EmailStr
    role: str
    is_active: bool
    create_at: datetime

# Actualización de usuario
class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=50)
    email: EmailStr | None = Field(default=None, max_length=120)
    role: str | None = Field(default=None)
    is_active: bool | None = Field(default=None)
    image_file: str | None = Field(default=None, min_length=1, max_length=50)

# Respuesta de inicio de sessión de usuario
class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class ApprovedUsers(BaseModel):
    id: int
    email: EmailStr = Field(max_length=120)
    
class ApprovedUsersResponse(BaseModel):
    email: EmailStr 