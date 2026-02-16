from datetime import UTC, datetime, timedelta
from fastapi import Depends, Request, status, HTTPException
from fastapi.templating import Jinja2Templates
from typing import Annotated
from sqlalchemy import func, select
from sqlalchemy.orm import Session
import jwt, smtplib

from pwdlib import PasswordHash
from argon2.exceptions import VerifyMismatchError
from fastapi.security import OAuth2PasswordBearer
from itsdangerous import URLSafeTimedSerializer

from .config import get_settings
from .database import get_db
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from models.users import User


# Password Hasher
ph = PasswordHash.recommended()

# Esquema de FastAPI para extraer el token del header "Authorization: Bearer ..."
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/token")

# Obtener las variables de entorno
settings = get_settings()

# Configuración de templates
templates = Jinja2Templates(directory="templates")


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
# Crea el token de acceso
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Genera un JWT firmado"""
    payload = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES.get_secret_value(),
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
        jwt.InvalidTokenError | jwt.ExpiredSignatureError | jwt.InvalidAlgorithmError
    ):
        return credentials_exception
    else:
        return payload.get("sub")


# ----------------------------------------------------------------------
# Obtiene el usuario actual
def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Obtiene el usuario actual autenticado desde la cookie."""

    response_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token Inválido o Expirado.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Obtiene el token desde la cookie
    token = request.cookies.get("access_token")

    # 1.1 Si no hay cookie, intenta obtenerlo del Header Authorization (Estándar OAuth2)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        else:
            raise response_exception

    # 2. Decodifica el Token
    username = verify_access_token(token)
    if username is None:
        raise response_exception

    result = db.execute(select(User).where(User.username == username))
    user = result.scalars().first()

    # 3. Validar username en token y existencia del usuario
    if user is None:
        raise response_exception

    # 4. Validar que esté activo (Buena práctica en OAuth2)
    if not user.is_active:
        raise response_exception

    return user


# ----------------------------------------------------------------------
# Alias de Modelo
CurrentUser = Annotated[User, Depends(get_current_user)]


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
# Envia el email de confirmación
def send_email_confirmation(context: dict):
    """Envia un correo de confirmación de email"""
    email_destinatario = context.get("email")
    DOMINIO = settings.DOMINIO.get_secret_value()
    EMAIL_SERVER = settings.EMAIL_SERVER.get_secret_value()
    EMAIL_PORT = int(settings.EMAIL_PORT.get_secret_value())
    EMAIL_USER = settings.EMAIL_USER.get_secret_value()
    EMAIL_PASSWD = settings.EMAIL_PASSWD.get_secret_value()

    # 1. Obtener y Renderizar la Plantilla
    # Buscamos el archivo y le pasamos el diccionario de contexto completo
    template = templates.get_template("email_confirmation.html")
    html_content = template.render(context)

    # 2. Crear el objeto Mensaje (MIMEMultipart es mejor para evitar errores de formato)
    message = MIMEMultipart("alternative")
    message["Subject"] = f"{DOMINIO} - Confirme su correo"
    message["From"] = EMAIL_USER
    message["To"] = email_destinatario

    # 3. Adjuntar el contenido HTML renderizado
    part_html = MIMEText(html_content, "html")
    message.attach(part_html)

    # 4. Enviar
    try:
        with smtplib.SMTP_SSL(EMAIL_SERVER, EMAIL_PORT) as server:
            server.login(EMAIL_USER, EMAIL_PASSWD)
            server.sendmail(EMAIL_USER, email_destinatario, message.as_string())
        print(f"¡Mensaje enviado a {email_destinatario}!")
    except Exception as e:
        print(f"Error enviando email: {e}")


# ----------------------------------------------------------------------
# Genera token para resetear password
def generate_reset_password_token(email: str):
    """Genera un token seguro para restablecer la contraseña"""
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY.get_secret_value())
    return serializer.dumps(email, salt="password-reset-salt")


# ----------------------------------------------------------------------
# Verifica token de resetear password
def verify_reset_password_token(token: str, expiration=3600):
    """Verifica el token de restablecimiento de contraseña"""
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY.get_secret_value())
    try:
        email = serializer.loads(
            token,
            salt="password-reset-salt",
            max_age=expiration,
        )
    except Exception:
        return None
    return email


# ----------------------------------------------------------------------
# Envia el email de reseteo de password
def send_reset_password_email(context: dict):
    """Envia un correo con el link para resetear la contraseña"""
    # Reutilizamos la lógica de envío, idealmente deberías tener un template
    # llamado 'password_reset_email.html'
    try:
        # Intentamos usar un template específico si existe
        template = templates.get_template("password_reset_email.html")
        html_content = template.render(context)
        
        # Preparamos el contexto para reutilizar la función de envío o lógica similar
        # Por simplicidad, aquí inyectamos el contenido en la función existente o duplicamos lógica.
        # Para mantener el código limpio, duplicaremos la parte de envío con el asunto correcto:
        
        email_destinatario = context.get("email")
        DOMINIO = settings.DOMINIO.get_secret_value()
        EMAIL_SERVER = settings.EMAIL_SERVER.get_secret_value()
        EMAIL_PORT = int(settings.EMAIL_PORT.get_secret_value())
        EMAIL_USER = settings.EMAIL_USER.get_secret_value()
        EMAIL_PASSWD = settings.EMAIL_PASSWD.get_secret_value()

        message = MIMEMultipart("alternative")
        message["Subject"] = f"{DOMINIO} - Restablecer Contraseña"
        message["From"] = EMAIL_USER
        message["To"] = email_destinatario

        part_html = MIMEText(html_content, "html")
        message.attach(part_html)

        with smtplib.SMTP_SSL(EMAIL_SERVER, EMAIL_PORT) as server:
            server.login(EMAIL_USER, EMAIL_PASSWD)
            server.sendmail(EMAIL_USER, email_destinatario, message.as_string())
        print(f"¡Email de reseteo enviado a {email_destinatario}!")
        
    except Exception as e:
        print(f"Error enviando email de reseteo: {e}")
