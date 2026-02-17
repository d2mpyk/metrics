"""Relacionado a los Schemas en la APP"""

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from datetime import datetime
from typing import Literal


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
    created_at: datetime


# Actualización de usuario propio
class UserMeUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str | None = None
    image_file: str | None = None


# Actualización de usuario
class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=50)
    email: EmailStr | None = Field(default=None, max_length=120)
    role: str | None = Field(default=None)
    is_active: bool | None = Field(default=None)
    image_file: str | None = Field(default=None, min_length=1, max_length=50)


# Actualización del Rol del usuario
class UserRoleUpdate(BaseModel):
    role: Literal["admin", "user"]


# Actualización del Password
class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str


# Petición de Email del usuario para recuperar Password
class PasswordResetRequest(BaseModel):
    email: str


# Confirmación del nuevo password
class PasswordResetConfirm(BaseModel):
    new_password: str


# Respuesta de inicio de sessión de usuario
class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class ApprovedUsers(BaseModel):
    id: int
    email: EmailStr = Field(max_length=120)
    created_at: datetime


class ApprovedUsersResponse(BaseModel):
    email: EmailStr
