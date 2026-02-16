from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Annotated

# Import's Locales
from schemas.user import TokenResponse
from utils.auth import (
    authenticate_user,
    create_access_token,
)
from utils.database import get_db
from utils.config import get_settings

# Instancia de las rutas
router = APIRouter()
settings = get_settings()

# ----------------------------------------------------------------------
# Respuesta de Token
@router.post(
    "/token",
    # response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def login_for_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
):
    # Autentica user por email
    user = authenticate_user(form_data.username, form_data.password, db)

    # Verifica si el user exists y el password es correcto
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o Password incorrecto",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verifica si el usuario está activo
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error: Usuario inactivo, por favor confirme su correo.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Crea access token con email, username, id
    access_token_expires = timedelta(
        minutes=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES.get_secret_value())
    )
    access_token = create_access_token(
        data={
            "id": str(user.id),
            "sub": str(user.username),
            "email": str(user.email),
            "type": "user",
            "role": str(user.role),
        },
        expires_delta=access_token_expires,
    )
    # For Debug
    # print(access_token)

    # 🔐 Set Cookie HttpOnly
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # True en producción con HTTPS
        samesite="lax",
    )

    return TokenResponse(access_token=access_token, token_type="bearer")


# ----------------------------------------------------------------------
# Logout
@router.post(
    "/logout",
    name="logout",
)
def logout(response: Response):
    redirect = RedirectResponse(url="/", status_code=303)
    redirect.delete_cookie("access_token")
    return redirect
