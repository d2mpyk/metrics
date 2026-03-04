from datetime import UTC, datetime, timedelta
from fastapi import Depends, Request, status, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from typing import Annotated
from sqlalchemy import func, select
from sqlalchemy.orm import Session
import jwt, smtplib, logging

from pwdlib import PasswordHash
from argon2.exceptions import VerifyMismatchError
from fastapi.security import OAuth2PasswordBearer
from itsdangerous import URLSafeTimedSerializer

from .config import get_settings
from .database import get_db
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from models.users import User
from models.clients import Client


# Password Hasher
ph = PasswordHash.recommended()

# Esquema de FastAPI para extraer el token del header "Authorization: Bearer ..."
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)

# Obtener las variables de entorno
settings = get_settings()

# Configuración de templates
templates = Jinja2Templates(directory="templates")

# Configuración de Logging para Emails
email_logger = logging.getLogger("email_sender")
email_logger.setLevel(logging.INFO)

# Evitar duplicar handlers si se recarga el módulo
if not email_logger.handlers:
    fh = logging.FileHandler("email_logs.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    email_logger.addHandler(fh)


# ----------------------------------------------------------------------
# HASH el Password
def hash_password(password: str) -> str:
    """Genera el hash seguro para guardar en la base de datos."""
    return ph.hash(password)


# ----------------------------------------------------------------------
# Verifica el Password HASH
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si la contraseña coincide con el hash."""
    try:
        return ph.verify(plain_password, hashed_password)
    except VerifyMismatchError:
        return False


# ----------------------------------------------------------------------
# Calcula minutos hasta fin de año
def get_minutes_until_end_of_year() -> int:
    """Calcula los minutos restantes hasta el 31 de Dic a las 23:59:00 del año actual."""
    now = datetime.now(UTC)
    expiration = datetime(now.year, 12, 31, 23, 59, 0, tzinfo=UTC)

    expiration_unix = expiration.timestamp()
    now_unix = now.timestamp()

    minutes = int((expiration_unix - now_unix) / 60)
    return max(minutes, 0)


# ----------------------------------------------------------------------
# Crea el token de acceso
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Genera un JWT firmado"""
    payload = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES.get_secret_value()),
        )

    # Authlib requiere claims estándar: 'exp' (expiration) y 'iat' (issued at)
    payload.update({"exp": expire, "iat": datetime.now(UTC)})

    # Codificación y firma
    token = jwt.encode(
        payload,
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM.get_secret_value(),
    )
    return token


# ----------------------------------------------------------------------
# Verifica el Token de Acceso
def verify_access_token(token: str) -> str | None:
    """Verifica un JWT y retorna el 'sub' si es valido."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Error: No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM.get_secret_value()],
            options={"require": ["sub", "exp", "iat"]},
        )
    except (
        jwt.InvalidTokenError,
        jwt.ExpiredSignatureError,
        jwt.InvalidAlgorithmError,
    ):
        raise credentials_exception
    else:
        return payload.get("sub")


# ----------------------------------------------------------------------
# Obtiene el usuario actual
def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    token_: Annotated[str | None, Depends(oauth2_scheme)],
) -> User | RedirectResponse:
    """
    Obtiene el usuario actual autenticado desde la cookie.
    Si el token es inválido o ha expirado, retorna un RedirectResponse a la página de login.
    """

    token = token_
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        # No hay token, no se puede continuar.
        return RedirectResponse(url="/api/v1/auth/login", status_code=status.HTTP_303_SEE_OTHER)

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM.get_secret_value()],
            options={"require": ["sub", "exp", "iat"]},
        )
        username = payload.get("sub")
        if not username:
            raise jwt.InvalidTokenError

        user = db.execute(select(User).where(User.username == username)).scalars().first()
        if not user or not user.is_active:
            raise jwt.InvalidTokenError

        return user

    except jwt.ExpiredSignatureError:
        # Caso específico: el token ha expirado.
        response = RedirectResponse(url="/api/v1/auth/login", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="flash_message", value="Su sesión ha expirado. Por favor, inicie sesión de nuevo.", httponly=True)
        response.set_cookie(key="flash_type", value="orange", httponly=True)
        response.delete_cookie("access_token")
        return response

    except jwt.InvalidTokenError:
        # Caso genérico: token inválido, manipulado, o usuario no encontrado.
        response = RedirectResponse(url="/api/v1/auth/login", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="flash_message", value="Error de autenticación. Por favor, inicie sesión.", httponly=True)
        response.set_cookie(key="flash_type", value="red", httponly=True)
        response.delete_cookie("access_token")
        return response


# ----------------------------------------------------------------------
# Alias de Modelo
CurrentUser = Annotated[User, Depends(get_current_user)]


# ----------------------------------------------------------------------
# Verifica si el usuario es admin
def get_current_admin(current_user_or_redirect: CurrentUser) -> User | RedirectResponse:
    """Verifica que el usuario actual tenga rol de administrador."""
    if isinstance(current_user_or_redirect, RedirectResponse):
        return current_user_or_redirect

    if current_user_or_redirect.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado",
        )
    return current_user_or_redirect


# ----------------------------------------------------------------------
# Alias de Modelo
CurrentAdmin = Annotated[User, Depends(get_current_admin)]


# ----------------------------------------------------------------------
# Obtiene el cliente (dispositivo) actual
def get_current_client(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    token_: Annotated[str | None, Depends(oauth2_scheme)],
) -> Client:
    """Obtiene el dispositivo autenticado desde el Header Authorization."""

    response_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales de dispositivo inválidas.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token = token_

    if not token:
        raise response_exception

    # 2. Decodificar y validar rol
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM.get_secret_value()],
            options={"require": ["sub", "exp", "iat", "role", "client_id"]},
        )
    except jwt.InvalidTokenError:
        raise response_exception

    if payload.get("role") != "device":
        raise response_exception

    client_id = payload.get("client_id")
    client = db.execute(select(Client).where(Client.id == client_id)).scalars().first()

    if not client or not client.is_active:
        raise response_exception

    return client


# ----------------------------------------------------------------------
# Autenticar usuario
def authenticate_user(
    username: str,
    password: str,
    db: Annotated[Session, Depends(get_db)],
):
    # Busca user por email
    result = db.execute(
        select(User).where(
            func.lower(User.email) == username.lower(),
        ),
    )
    user = result.scalars().first()

    # Verifica si el user exists y el password es correcto
    if not user or not verify_password(password, user.password_hash):
        return None

    return user


# ----------------------------------------------------------------------
# Crea el token de confirmación de correo
def generate_verification_token(email: str):
    """Genera un token para la verificación del correo"""
    serializer = URLSafeTimedSerializer(
        settings.SECRET_KEY_CHECK_MAIL.get_secret_value()
    )
    return serializer.dumps(
        email, salt=settings.SECURITY_PASSWD_SALT.get_secret_value()
    )


# ----------------------------------------------------------------------
# Verifica el token de confirmación de correo
def confirm_verification_token(token: str, expiration=3600):
    """Verifica un token de confirmación de correo"""
    serializer = URLSafeTimedSerializer(
        settings.SECRET_KEY_CHECK_MAIL.get_secret_value()
    )
    try:
        email = serializer.loads(
            token,
            salt=settings.SECURITY_PASSWD_SALT.get_secret_value(),
            max_age=expiration,  # Token expira en 1 hora
        )
    except Exception:
        return False
    return email


# ----------------------------------------------------------------------
# (Privada) Función genérica para enviar correos
def _send_email(recipient_email: str, subject: str, html_content: str):
    """Función base para enviar correos HTML usando SMTP SSL."""
    EMAIL_SERVER = settings.EMAIL_SERVER.get_secret_value()
    EMAIL_PORT = int(settings.EMAIL_PORT.get_secret_value())
    EMAIL_USER = settings.EMAIL_USER.get_secret_value()
    EMAIL_PASSWD = settings.EMAIL_PASSWD.get_secret_value()

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = EMAIL_USER
    message["To"] = recipient_email

    part_html = MIMEText(html_content, "html")
    message.attach(part_html)

    try:
        with smtplib.SMTP_SSL(EMAIL_SERVER, EMAIL_PORT) as server:
            server.login(EMAIL_USER, EMAIL_PASSWD)
            server.sendmail(EMAIL_USER, recipient_email, message.as_string())
        email_logger.info(
            f"EXITO: Email enviado a {recipient_email} | Asunto: {subject}"
        )
    except Exception as e:
        email_logger.error(f"ERROR: Fallo al enviar a {recipient_email} | {e}")


# ----------------------------------------------------------------------
# Envia el email de confirmación
def send_email_confirmation(context: dict):
    """Envia un correo de confirmación de email"""
    email_destinatario = context.get("email")
    DOMINIO = settings.DOMINIO.get_secret_value()

    # 1. Obtener y Renderizar la Plantilla
    template = templates.get_template("email/email_confirmation.html")
    html_content = template.render(context)
    subject = f"{DOMINIO} - Confirme su correo"

    # 2. Enviar usando la función base
    _send_email(
        recipient_email=email_destinatario, subject=subject, html_content=html_content
    )


# ----------------------------------------------------------------------
# Genera token para resetear password
def generate_reset_password_token(email: str):
    """Genera un token seguro para restablecer la contraseña"""
    # Es buena práctica usar una clave secreta diferente para cada tipo de token
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY.get_secret_value())
    # Usamos el salt de la configuración para no tener valores 'secretos' hardcodeados
    return serializer.dumps(
        email, salt=settings.SECURITY_PASSWD_SALT.get_secret_value()
    )


# ----------------------------------------------------------------------
# Verifica token de resetear password
def verify_reset_password_token(token: str, expiration=3600):
    """Verifica el token de restablecimiento de contraseña"""
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY.get_secret_value())
    try:
        email = serializer.loads(
            token,
            salt=settings.SECURITY_PASSWD_SALT.get_secret_value(),
            max_age=expiration,
        )
    except Exception:
        return None
    return email


# ----------------------------------------------------------------------
# Envia el email de reseteo de password
def send_reset_password_email(context: dict):
    """Envia un correo con el link para resetear la contraseña."""
    email_destinatario = context.get("email")
    DOMINIO = settings.DOMINIO.get_secret_value()

    # 1. Obtener y Renderizar la Plantilla
    template = templates.get_template("email/password_reset_email.html")
    html_content = template.render(context)
    subject = f"{DOMINIO} - Restablecer Contraseña"

    # 2. Enviar usando la función base
    _send_email(
        recipient_email=email_destinatario, subject=subject, html_content=html_content
    )
