from typing import Annotated
import shutil
import os
import uuid

from fastapi import (
    APIRouter,
    Request,
    BackgroundTasks,
    Response,
    Depends,
    HTTPException,
    status,
    File,
    UploadFile,
    Form,
)
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# Import's Locales
from models.users import User, ApprovedUsers
from fastapi.responses import RedirectResponse
from utils.auth import (
    CurrentUser,
    generate_verification_token,
    hash_password,
    verify_password,
    send_email_confirmation,
    confirm_verification_token,
    generate_reset_password_token,
    verify_reset_password_token,
    send_reset_password_email,
    get_current_admin,
    security_logger,
    get_flash_messages,
)
from utils.limiter import limiter
from utils.config import get_settings
from utils.database import get_db
from schemas.user import (
    ApprovedUsersResponse,
    UserCreate,
    UserPasswordUpdate,
    PasswordResetRequest,
    PasswordResetConfirm,
    UserRoleUpdate,
    UserResponsePrivate,
    UserUpdate,
)
from utils.users import check_email_exists, check_username_exists
from utils.stats import get_dashboard_stats


# Instancia de las rutas
router = APIRouter()
# Obtener las variables de entorno
settings = get_settings()
# Configurar motor de plantillas
templates = Jinja2Templates(directory="templates")


# ----------------------------------------------------------------------
# Muestra mi usuario
@router.get("/me", response_model=UserResponsePrivate, status_code=status.HTTP_200_OK)
def get_current_user_endpoint(
    user_or_redirect: CurrentUser,
):
    """Obtiene el usuario actual autenticado."""
    if isinstance(user_or_redirect, RedirectResponse):
        return user_or_redirect
    return user_or_redirect


# ----------------------------------------------------------------------
# Edita el usuario actual
@router.patch("/me", response_model=UserResponsePrivate, status_code=status.HTTP_200_OK)
async def update_current_user_profile(
    user_or_redirect: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str | None, Form()] = None,
    image_file: Annotated[UploadFile | None, File()] = None,
):
    """Permite al usuario autenticado actualizar su username y su foto de perfil."""
    if isinstance(user_or_redirect, RedirectResponse):
        return user_or_redirect
    current_user = user_or_redirect

    if not username and not image_file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se proporcionaron datos para actualizar.",
        )

    if username:
        # Verificar que el nuevo username no esté en uso por otro usuario
        if username != current_user.username:
            check_username_exists(db, username, current_user.id)
            current_user.username = username

    if image_file:
        # --- Validación de Archivo ---
        # 1. Validar tipo de archivo (Content-Type)
        if image_file.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tipo de archivo no válido. Solo se permiten .jpg y .png",
            )

        # 2. Validar tamaño del archivo (máx 2MB)
        # Mover el cursor al final del archivo para obtener el tamaño
        image_file.file.seek(0, os.SEEK_END)
        file_size = image_file.file.tell()
        # Regresar el cursor al inicio para poder leer/copiar el archivo
        image_file.file.seek(0)

        MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
        if file_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El archivo es demasiado grande. El tamaño máximo es de 2MB.",
            )
        # --- Fin Validación ---
        # Definir directorio de subida (asegurar que existe)
        upload_dir = "media/profile_pics"
        os.makedirs(upload_dir, exist_ok=True)

        # Generar nombre único para evitar colisiones
        file_extension = os.path.splitext(image_file.filename)[1]
        new_filename = f"{uuid.uuid4()}{file_extension}"
        file_path = os.path.join(upload_dir, new_filename)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image_file.file, buffer)

        current_user.image_file = new_filename

    db.commit()
    db.refresh(current_user)

    return current_user


# ----------------------------------------------------------------------
# Cambia la contraseña del usuario actual
@router.patch("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def update_current_user_password(
    password_data: UserPasswordUpdate,
    user_or_redirect: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
):
    """Permite al usuario autenticado cambiar su propia contraseña."""
    if isinstance(user_or_redirect, RedirectResponse):
        return user_or_redirect
    current_user = user_or_redirect

    # 2. Verificar la contraseña actual
    if not verify_password(password_data.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La contraseña actual es incorrecta.",
        )

    # 2. Hashear y actualizar la nueva contraseña
    current_user.password_hash = hash_password(password_data.new_password)
    db.commit()

    # No es necesario retornar nada, el 204 lo indica.
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ----------------------------------------------------------------------
# Solicita reseteo de contraseña (Forgot Password)
@router.post(
    "/forgot-password", status_code=status.HTTP_200_OK, name="request_password_reset",
)
@limiter.limit("3/hour")
def request_password_reset(
    request: Request,
    request_data: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[Session, Depends(get_db)],
):
    """
    Genera un token de reseteo y envía un email si el usuario existe.
    Siempre retorna 200 OK para evitar enumeración de usuarios.
    """
    result = db.execute(
        select(User).where(func.lower(User.email) == request_data.email.lower())
    )
    user = result.scalars().first()

    if user and user.is_active:
        # 1. Generar Token
        token = generate_reset_password_token(user.email)

        # 2. Crear Link
        reset_url = str(request.url_for("reset_password_view", token=token))
        context = {"username": user.username, "email": user.email, "url": reset_url}

        # 3. Enviar Email en background
        background_tasks.add_task(send_reset_password_email, context)

    return {
        "message": "Si el correo existe, se ha enviado un enlace para restablecer la contraseña."
    }


# ----------------------------------------------------------------------
# Vista de Reseteo de contraseña (GET)
@router.get(
    "/reset-password/{token}", response_class=HTMLResponse, name="reset_password_view"
)
def reset_password_view(request: Request, token: str):
    """Muestra el formulario para restablecer la contraseña."""
    flash_message, flash_type = get_flash_messages(request)

    response = templates.TemplateResponse(
        request=request,
        name="auth/reset-password.html",
        context={
            "token": token,
            "flash_message": flash_message,
            "flash_type": flash_type,
        },
    )
    if flash_message:
        response.delete_cookie("flash_message")
        response.delete_cookie("flash_type")
    return response


# Ejecuta el reseteo de contraseña
@limiter.limit("5/minute")
@router.post(
    "/reset-password/{token}",
    response_class=RedirectResponse,
    name="reset_password",
)
def reset_password(
    request: Request,
    token: str,
    db: Annotated[Session, Depends(get_db)],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
):
    """Procesa el formulario de reseteo de contraseña."""

    def redirect_error(msg: str):
        response = RedirectResponse(
            url=request.url_for("reset_password_view", token=token),
            status_code=status.HTTP_303_SEE_OTHER,
        )
        response.set_cookie(key="flash_message", value=msg, httponly=True)
        response.set_cookie(key="flash_type", value="red", httponly=True)
        return response

    if new_password != confirm_password:
        return redirect_error("Las contraseñas no coinciden.")

    if len(new_password) < 8:
        return redirect_error("La contraseña debe tener al menos 8 caracteres.")

    email = verify_reset_password_token(token)
    if not email:
        # El logging del token inválido ya se hace dentro de verify_reset_password_token
        # Redirigir al login si el token es inválido para no dejar al usuario en una página rota
        response = RedirectResponse(
            url=request.url_for("login"), status_code=status.HTTP_303_SEE_OTHER
        )
        response.set_cookie(
            key="flash_message",
            value="El enlace para restablecer la contraseña es inválido o ha expirado.",
            httponly=True,
        )
        response.set_cookie(key="flash_type", value="red", httponly=True)
        return response

    result = db.execute(select(User).where(func.lower(User.email) == email.lower()))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    user.password_hash = hash_password(new_password)
    db.commit()

    response = RedirectResponse(url=request.url_for("login"), status_code=303)
    response.set_cookie(
        key="flash_message",
        value="Contraseña actualizada exitosamente. Ya puedes iniciar sesión.",
        httponly=True,
    )
    response.set_cookie(key="flash_type", value="green", httponly=True)
    return response


# ----------------------------------------------------------------------
# Muestra todos los usuarios
@router.get(
    "",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    name="get_users",
)
def get_users(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    user_admin = admin_or_redirect

    result = db.execute(select(User))
    users = result.scalars().all()

    flash_message, flash_type = get_flash_messages(request)

    response = templates.TemplateResponse(
        request=request,
        name="dashboard/users.html",
        context={
            "users": users,
            "user": user_admin,
            "data": get_dashboard_stats(db),
            "title": "Gestión de Usuarios",
            "flash_message": flash_message,
            "flash_type": flash_type,
        },
    )

    if flash_message:
        response.delete_cookie("flash_message")
        response.delete_cookie("flash_type")

    return response


# ----------------------------------------------------------------------
# Vista de Edición de Usuario (GET)
@router.get("/{user_id}/edit", response_class=HTMLResponse, name="get_user_edit_view")
def get_user_edit_view(
    request: Request,
    user_id: int,
    db: Annotated[Session, Depends(get_db)],
    user_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    """Muestra el formulario de edición para un usuario específico (Admin Only)."""
    if isinstance(user_or_redirect, RedirectResponse):
        return user_or_redirect

    target_user = db.get(User, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    flash_message, flash_type = get_flash_messages(request)

    response = templates.TemplateResponse(
        "dashboard/user_edit.html",
        {
            "request": request,
            "target_user": target_user,
            "user": user_or_redirect,
            "data": get_dashboard_stats(db),
            "title": f"Editar: {target_user.username}",
            "flash_message": flash_message,
            "flash_type": flash_type,
        },
    )

    if flash_message:
        response.delete_cookie("flash_message")
        response.delete_cookie("flash_type")

    return response


# ----------------------------------------------------------------------
# Procesar Edición de Usuario (POST)
@router.post("/{user_id}/edit", name="post_user_edit_view")
async def post_user_edit_view(
    request: Request,
    user_id: int,
    db: Annotated[Session, Depends(get_db)],
    requester_or_redirect: CurrentUser,  # Permite que el usuario se edite a sí mismo
    username: Annotated[str | None, Form()] = None,
    role: Annotated[str | None, Form()] = None,
    is_active: Annotated[str | None, Form()] = None,
    password: Annotated[str | None, Form()] = None,
):
    if isinstance(requester_or_redirect, RedirectResponse):
        return requester_or_redirect

    # Seguridad: Solo admin o el propio usuario
    is_admin = requester_or_redirect.role == "admin"
    if not is_admin and requester_or_redirect.id != user_id:
        security_logger.warning(
            f"Usuario '{requester_or_redirect.username}' (ID: {requester_or_redirect.id}) intentó editar sin permiso al usuario con ID: {user_id} desde IP {request.client.host}"
        )
        raise HTTPException(
            status_code=403, detail="No tienes permiso para editar este perfil."
        )

    user_to_update = db.get(User, user_id)
    if not user_to_update:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Aplicar cambios según permisos
    if is_admin:
        if username:
            user_to_update.username = username
        if role:
            user_to_update.role = role

        # Validar cambio de estado (is_active)
        new_active_status = True if is_active == "on" else False

        # Evitar auto-desactivación del admin
        if user_to_update.id == requester_or_redirect.id and not new_active_status:
            security_logger.warning(
                f"Admin '{requester_or_redirect.username}' intentó auto-desactivarse desde IP {request.client.host}"
            )
            response = RedirectResponse(
                url=request.url_for("get_user_edit_view", user_id=user_id),
                status_code=status.HTTP_303_SEE_OTHER,
            )
            response.set_cookie(
                key="flash_message",
                value="No puedes desactivar tu propia cuenta.",
                httponly=True,
            )
            response.set_cookie(key="flash_type", value="red", httponly=True)
            return response

        user_to_update.is_active = new_active_status

    if password and len(password.strip()) > 0:
        if len(password) < 8:
            response = RedirectResponse(
                url=request.url_for("get_user_edit_view", user_id=user_id),
                status_code=303,
            )
            response.set_cookie(
                key="flash_message",
                value="La contraseña debe tener al menos 8 caracteres.",
                httponly=True,
            )
            response.set_cookie(key="flash_type", value="red", httponly=True)
            return response
        user_to_update.password_hash = hash_password(password)

    db.commit()

    response = RedirectResponse(url=request.url_for("get_users"), status_code=303)
    response.set_cookie(
        key="flash_message",
        value=f"Usuario '{user_to_update.username}' actualizado con éxito.",
        httponly=True,
    )
    response.set_cookie(key="flash_type", value="green", httponly=True)

    return response


# ----------------------------------------------------------------------
# Muestra todos los usuarios aprobados
@router.get(
    "/approved",
    response_model=list[ApprovedUsersResponse],
    status_code=status.HTTP_200_OK,
)
def get_approved_users(
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect

    result = db.execute(select(ApprovedUsers))
    users = result.scalars().all()

    if users:
        return users
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="No hay usuarios que mostrar",
    )


# ----------------------------------------------------------------------
# Crea un usuario Aprobado
@router.post(
    "/approved/{approved_email}",
    response_model=ApprovedUsersResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_approved_user(
    approved_email: str,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect

    result = db.execute(
        select(ApprovedUsers).where(
            func.lower(ApprovedUsers.email) == approved_email.lower()
        )
    )
    exists_user = result.scalars().first()

    if exists_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este usuario ya ha sido aprobado.",
        )

    result = db.execute(
        select(User).where(func.lower(User.email) == approved_email.lower())
    )
    exists_email = result.scalars().first()

    # Aceptar solo si el email no está registrado
    if exists_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este email ya está registrado.",
        )

    new_approved = ApprovedUsers(email=approved_email.lower())

    db.add(new_approved)
    db.commit()
    db.refresh(new_approved)

    return new_approved


# ----------------------------------------------------------------------
# Crea un usuario
@limiter.limit("10/hour")
@router.post(
    "/create",
    response_class=RedirectResponse,
    status_code=status.HTTP_303_SEE_OTHER,
    name="create_user",
)
def create_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
    background_tasks: BackgroundTasks,
    username: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect

    def redirect_error(msg: str):
        response = RedirectResponse(
            url=request.url_for("get_users"), status_code=303
        )
        response.set_cookie(key="flash_message", value=msg, httponly=True)
        response.set_cookie(key="flash_type", value="red", httponly=True)
        return response

    # 1. Validaciones
    try:
        check_username_exists(db, username)
        check_email_exists(db, email)
    except HTTPException as e:
        return redirect_error(e.detail)

    # 2. Aprobar el email si no lo está ya
    is_already_approved = (
        db.execute(
            select(ApprovedUsers).where(func.lower(ApprovedUsers.email) == email.lower())
        )
        .scalars()
        .first()
    )
    if not is_already_approved:
        new_approved = ApprovedUsers(email=email.lower())
        db.add(new_approved)

    new_user = User(
        username=username,
        email=email.lower(),
        password_hash=hash_password(password),
        role="user",
        is_active=False,
    )

    db.add(new_user)
    db.commit()  # Guarda tanto la aprobación (si es nueva) como el usuario
    db.refresh(new_user)

    # --- Logica de confirmación de Email ---
    # 1. Generar token
    token = generate_verification_token(new_user.email)
    # 2. Crear link
    verify_url = str(request.url_for("verify_email", token=token))
    context = {"user": username, "email": email, "url": verify_url}
    # 3. Enviar email en segundo plano sin bloquear el return
    background_tasks.add_task(send_email_confirmation, context)

    response = RedirectResponse(url=request.url_for("get_users"), status_code=303)
    response.set_cookie(
        key="flash_message",
        value=f"Usuario '{username}' creado. Se ha enviado un email de confirmación.",
        httponly=True,
    )
    response.set_cookie(key="flash_type", value="green", httponly=True)
    return response


# ----------------------------------------------------------------------
# Verifica token de confirmación de email
@router.get("/verify/{token}", status_code=status.HTTP_200_OK, name="verify_email")
def verify_user_email(token: str, db: Annotated[Session, Depends(get_db)]):
    email = confirm_verification_token(token)

    if not email:
        # El logging ya se hace dentro de confirm_verification_token
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El link de verificación es inválido o ha expirado.",
        )

    # Buscar usuario
    result = db.execute(select(User).where(func.lower(User.email) == email.lower()))
    user = result.scalars().first()

    if not user:
        security_logger.error(
            f"Verificación de email fallida: usuario no encontrado para email '{email}' aunque el token era válido."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no encontrado",
        )

    if not user.is_active:
        # Activar usuario
        user.is_active = True
        db.commit()
        db.refresh(user)

    return {"message": "Cuenta verificada exitosamente."}


# ----------------------------------------------------------------------
# Muestra solo 1 user
@router.get(
    "/{user_id}",
    response_model=UserResponsePrivate,
    status_code=status.HTTP_200_OK,
)
def get_user(
    user_id: int,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect

    result = db.execute(select(User).where(User.id == user_id))
    exists_user = result.scalars().first()

    if exists_user:
        return exists_user

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Este usuario no existe"
    )


# ----------------------------------------------------------------------
# Cambia el rol de un usuario
@router.patch(
    "/{user_id}/role",
    response_model=UserResponsePrivate,
    status_code=status.HTTP_200_OK,
)
def update_user_role(
    user_id: int,
    request: Request,
    role_data: UserRoleUpdate,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    current_admin = admin_or_redirect

    if user_id == current_admin.id:
        security_logger.warning(
            f"Admin '{current_admin.username}' intentó cambiar su propio rol desde IP {request.client.host}."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un administrador no puede cambiar su propio rol.",
        )

    result = db.execute(select(User).where(User.id == user_id))
    user_to_update = result.scalars().first()

    if not user_to_update:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Este usuario no existe",
        )

    user_to_update.role = role_data.role
    db.commit()
    db.refresh(user_to_update)

    return user_to_update


# ----------------------------------------------------------------------
# Edita un usuario parcialmente
@router.patch(
    "/{user_id}",
    response_model=UserResponsePrivate,
    status_code=status.HTTP_200_OK,
)
def update_user_partial(
    user_id: int,
    user_data: UserUpdate,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    # current_admin = admin_or_redirect # No se usa

    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Este usuario no existe",
        )

    update_data = user_data.model_dump(exclude_unset=True)

    # Validar username y email si se están actualizando
    if "username" in update_data:
        check_username_exists(db, update_data["username"], user_id)

    if "email" in update_data:
        check_email_exists(db, update_data["email"], user_id)

    # Establecemos cada campo editado dinamicamente
    for field, value in update_data.items():
        setattr(user, field, value.lower() if isinstance(value, str) else value)

    db.commit()
    db.refresh(user)

    return user


# ----------------------------------------------------------------------
# Elimina un usuario
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Users"])
def delete_user(
    request: Request,
    user_id: int,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    current_admin = admin_or_redirect

    # Si se llega acá es porque es user Admin
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Este usuario no está registrado.",
        )

    # No se puede eliminar el usuario principal
    if user_id == current_admin.id:
        security_logger.warning(
            f"Admin '{current_admin.username}' (ID: {current_admin.id}) intentó auto-eliminarse desde IP {request.client.host}."
        )
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Este usuario no puede eliminarse a si mismo.",
        )

    db.delete(user)
    db.commit()
