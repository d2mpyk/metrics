import secrets, uuid
from datetime import datetime, timedelta, UTC
from fastapi import APIRouter, Depends, HTTPException, Response, status, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from typing import Annotated

# Import's Locales
from models.clients import ApprovedClient, Client, DeviceCode
from models.users import User
from schemas.user import TokenResponse
from utils.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    get_current_admin,
    get_minutes_until_end_of_year,
)
from utils.database import get_db
from utils.config import get_settings

# Instancia de las rutas
router = APIRouter()
settings = get_settings()
templates = Jinja2Templates(directory="templates")


# ----------------------------------------------------------------------
# Vista de Login
@router.get("/login", response_class=HTMLResponse, name="login")
def login_view(request: Request):
    # Recuperar mensajes flash de las cookies
    flash_message = request.cookies.get("flash_message")
    flash_type = request.cookies.get("flash_type")

    response = templates.TemplateResponse(
        request=request,
        name="auth/login.html",
        context={
            "flash_message": flash_message,
            "flash_type": flash_type,
        },
    )

    # Limpiar cookies flash si existen
    if flash_message:
        response.delete_cookie("flash_message")
        response.delete_cookie("flash_type")

    return response


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
    include_in_schema=False,
)
def logout(request: Request, response: Response):
    redirect = RedirectResponse(url=request.url_for("login"), status_code=303)
    redirect.delete_cookie("access_token")
    return redirect


# ----------------------------------------------------------------------
# Device Flow: 1. Solicitar Código (Device Authorization Request)
@router.post("/device/code", status_code=status.HTTP_200_OK)
def device_authorization_request(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    # 1. Validar IP en lista blanca
    client_ip = request.client.host
    approved = (
        db.execute(select(ApprovedClient).where(ApprovedClient.ip_address == client_ip))
        .scalars()
        .first()
    )

    if not approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Este servidor no está autorizado. IP detectada: {client_ip}",
        )

    # 2. Generar Códigos
    device_code = secrets.token_urlsafe(32)
    user_code = secrets.token_hex(4).upper()  # 8 caracteres hex
    expires_in = 600  # 10 minutos

    new_device_code = DeviceCode(
        device_code=device_code,
        user_code=user_code,
        ip_address=client_ip,
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_in),
        is_verified=False,
    )

    db.add(new_device_code)
    db.commit()

    # Construir URI para que el usuario la visite
    verification_uri = str(request.url_for("device_activate_view"))

    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "expires_in": expires_in,
        "interval": 5,
    }


# ----------------------------------------------------------------------
# Device Flow: 2. Polling de Token (Device Access Token Request)
@router.post("/device/token", status_code=status.HTTP_200_OK)
def device_access_token(
    device_code: Annotated[str, Form()],
    grant_type: Annotated[str, Form()],
    db: Annotated[Session, Depends(get_db)],
):
    if grant_type != "urn:ietf:params:oauth:grant-type:device_code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unsupported_grant_type",
        )

    # Buscar código
    code_record = (
        db.execute(select(DeviceCode).where(DeviceCode.device_code == device_code))
        .scalars()
        .first()
    )

    if not code_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant",
        )

    if datetime.now(UTC) > code_record.expires_at.replace(tzinfo=UTC):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expired_token",
        )

    if not code_record.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="authorization_pending",
        )

    # Recuperar el cliente creado durante la activación
    client = (
        db.execute(select(Client).where(Client.id == code_record.client_id))
        .scalars()
        .first()
    )

    if not client:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Client not found",
        )

    # Generar Token JWT para el dispositivo
    minutes = get_minutes_until_end_of_year()
    access_token_expires = timedelta(minutes=minutes)
    access_token = create_access_token(
        data={
            "sub": client.client_identifier,
            "type": "client",
            "role": "device",
            "client_id": client.id,
        },
        expires_delta=access_token_expires,
    )

    # Eliminar el código usado por seguridad
    db.delete(code_record)
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": int(access_token_expires.total_seconds()),
        "client_secret_key": client.client_secret_key,
        "client_identifier": client.client_identifier,
    }


# ----------------------------------------------------------------------
# Device Flow: 3. Vista de Activación (HTML)
@router.get(
    "/device/activate", response_class=HTMLResponse, name="device_activate_view"
)
def device_activate_view(request: Request):
    # Recuperar mensajes flash de las cookies
    flash_message = request.cookies.get("flash_message")
    flash_type = request.cookies.get("flash_type")

    response = templates.TemplateResponse(
        request=request,
        name="device_activate.html",
        context={
            "title": "Activar Dispositivo",
            "flash_message": flash_message,
            "flash_type": flash_type,
        },
    )
    # Limpiar cookies flash si existen
    if flash_message:
        response.delete_cookie("flash_message")
        response.delete_cookie("flash_type")

    return response


# ----------------------------------------------------------------------
# Device Flow: 4. Procesar Activación (Admin Only)
@router.post(
    "/device/activate",
    status_code=status.HTTP_303_SEE_OTHER,
    name="device_activate_submit",
)
def device_activate_submit(
    request: Request,
    user_code: Annotated[str, Form()],
    db: Annotated[Session, Depends(get_db)],
    current_admin: User = Depends(get_current_admin),
):
    # Normalizar input (eliminar guiones si el usuario los envió)
    user_code = user_code.strip().upper().replace("-", "")

    # Helper para redirección con error
    def redirect_error(msg):
        resp = RedirectResponse(
            url=request.url_for("device_activate_view"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
        resp.set_cookie(key="flash_message", value=msg, httponly=True)
        resp.set_cookie(key="flash_type", value="red", httponly=True)
        return resp

    code_record = (
        db.execute(select(DeviceCode).where(DeviceCode.user_code == user_code))
        .scalars()
        .first()
    )

    if not code_record:
        return redirect_error("Código inválido")

    if datetime.now(UTC) > code_record.expires_at.replace(tzinfo=UTC):
        return redirect_error("Código expirado")

    if code_record.is_verified:
        return redirect_error("Este dispositivo ya fue verificado.")

    # Buscar el ApprovedClient correspondiente para obtener la descripción
    approved_client = (
        db.execute(
            select(ApprovedClient).where(
                ApprovedClient.ip_address == code_record.ip_address
            )
        )
        .scalars()
        .first()
    )
    client_description = approved_client.description if approved_client else None

    # Crear Cliente Nuevo (Rotación de secretos por cada registro)
    new_client = Client(
        client_identifier=str(uuid.uuid4()),
        client_secret_key=secrets.token_urlsafe(64),
        ip_address=code_record.ip_address,
        is_active=True,
        created_at=datetime.now(UTC),
        description=client_description,
    )
    db.add(new_client)
    db.flush()  # Para obtener el ID del nuevo cliente antes de hacer commit

    # Actualizar DeviceCode para que el polling del dispositivo reciba éxito
    code_record.is_verified = True
    code_record.client_id = new_client.id

    # Actualizar el registro de ApprovedClient ya que el cliente ha sido activado
    if approved_client:
        approved_client.is_active = True

    db.commit()

    # Redirección exitosa al Dashboard
    response = RedirectResponse(
        url=request.url_for("dashboard"), status_code=status.HTTP_303_SEE_OTHER
    )
    response.set_cookie(
        key="flash_message", value="Dispositivo autorizado exitosamente.", httponly=True
    )
    response.set_cookie(key="flash_type", value="green", httponly=True)

    return response
