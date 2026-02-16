from typing import Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Response,
    Depends,
    HTTPException,
    status,
)
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# Import's Locales
from models.users import User, ApprovedUsers
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
)
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


# Instancia de las rutas
router = APIRouter()
# Obtener las variables de entorno
settings = get_settings()
# Configurar motor de plantillas
templates = Jinja2Templates(directory="templates")


# ----------------------------------------------------------------------
# Muestra mi usuario
@router.get("/me", response_model=UserResponsePrivate, status_code=status.HTTP_200_OK)
def get_current_user(current_user: CurrentUser):
    """Obtiene el usuario actual autenticado."""
    return current_user


# ----------------------------------------------------------------------
# Cambia la contraseña del usuario actual
@router.patch("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def update_current_user_password(
    password_data: UserPasswordUpdate,
    current_user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
):
    """Permite al usuario autenticado cambiar su propia contraseña."""
    # 1. Verificar la contraseña actual
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
@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def request_password_reset(
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

        # 2. Crear Link (Ajustar según la ruta de tu Frontend o API)
        DOMINIO = settings.DOMINIO.get_secret_value()
        # Ejemplo: http://midominio.com/reset-password?token=...
        reset_url = f"http://{DOMINIO}/api/v1/users/reset-password?token={token}"
        context = {"username": user.username, "email": user.email, "url": reset_url}

        # 3. Enviar Email en background
        background_tasks.add_task(send_reset_password_email, context)

    return {
        "message": "Si el correo existe, se ha enviado un enlace para restablecer la contraseña."
    }


# ----------------------------------------------------------------------
# Ejecuta el reseteo de contraseña
@router.post("/reset-password/{token}", status_code=status.HTTP_200_OK)
def reset_password(
    token: str,
    password_data: PasswordResetConfirm,
    db: Annotated[Session, Depends(get_db)],
):
    email = verify_reset_password_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El enlace es inválido o ha expirado.",
        )

    result = db.execute(select(User).where(func.lower(User.email) == email.lower()))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    user.password_hash = hash_password(password_data.new_password)
    db.commit()

    return {"message": "Contraseña actualizada exitosamente."}


# ----------------------------------------------------------------------
# Verifica si el usuario es admin
def get_current_admin(
    current_user: User = Depends(get_current_user),
):
    # Verificamos el campo role
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            # 403 = Prohibido (Sabemos quién eres, pero no tienes permiso)
            detail="Acceso denegado",
        )
    return current_user


# ----------------------------------------------------------------------
# Muestra todos los usuarios
@router.get(
    "",
    response_model=list[UserResponsePrivate],
    status_code=status.HTTP_200_OK,
)
def get_users(
    db: Annotated[Session, Depends(get_db)],
    user_admin: Annotated[User, Depends(get_current_admin)],
):
    result = db.execute(select(User))
    users = result.scalars().all()

    if users:
        return users
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="No hay usuarios que mostrar",
    )


# ----------------------------------------------------------------------
# Muestra todos los usuarios aprobados
@router.get(
    "/approved",
    response_model=list[ApprovedUsersResponse],
    status_code=status.HTTP_200_OK,
)
def get_approved_users(
    db: Annotated[Session, Depends(get_db)],
    user_admin: Annotated[User, Depends(get_current_admin)],
):
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
    user_admin: Annotated[User, Depends(get_current_admin)],
):
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
@router.post(
    "/create",
    response_model=UserResponsePrivate,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    user: UserCreate,
    db: Annotated[Session, Depends(get_db)],
    user_admin: Annotated[User, Depends(get_current_admin)],
    background_tasks: BackgroundTasks,
):
    result = db.execute(
        select(User).where(func.lower(User.username) == user.username.lower())
    )
    exists_user = result.scalars().first()

    if exists_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este usuario ya está registrado",
        )

    result = db.execute(
        select(User).where(func.lower(User.email) == user.email.lower())
    )
    exists_email = result.scalars().first()

    # Aceptar solo si el email no está registrado
    if exists_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este email ya está registrado",
        )

    result = db.execute(
        select(ApprovedUsers).where(
            func.lower(ApprovedUsers.email) == user.email.lower()
        )
    )
    is_approved = result.scalars().first()

    # Aceptar solo usuarios que coincidan con la DB approved
    if is_approved is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este usuario no está aprobado.",
        )

    new_user = User(
        username=user.username,
        email=user.email.lower(),
        password_hash=hash_password(user.password),
        role="user",
        is_active=False,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # --- Logica de confirmación de Email ---
    # 1. Generar token
    token = generate_verification_token(new_user.email)
    # 2. Crear link (ajustar dominio en .env)
    DOMINIO = settings.DOMINIO.get_secret_value()
    verify_url = f"http://{DOMINIO}/api/v1/users/verify/{token}"
    context = {"user": user.username, "email": user.email, "url": verify_url}
    # 3. Enviar email en segundo plano sin bloquear el return
    background_tasks.add_task(send_email_confirmation, context)

    return new_user


# ----------------------------------------------------------------------
# Verifica token de confirmación de email
@router.get("/verify/{token}", status_code=status.HTTP_200_OK)
def verify_user_email(token: str, db: Annotated[Session, Depends(get_db)]):
    email = confirm_verification_token(token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El link de verificación es inválido o ha expirado.",
        )

    # Buscar usuario
    result = db.execute(select(User).where(func.lower(User.email) == email.lower()))
    user = result.scalars().first()

    if not user:
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
    user_admin: Annotated[User, Depends(get_current_admin)],
    db: Annotated[Session, Depends(get_db)],
):
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
    role_data: UserRoleUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_admin: User = Depends(get_current_admin),
):
    if user_id == current_admin.id:
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
    current_user: CurrentUser,
):
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Este usuario no existe",
        )

    # Si quiere editar el nombre del usuario, primero verificamos el usuario
    if (
        user_data.username is not None
        and user_data.username.lower() != user.username.lower()
    ):
        result = db.execute(
            select(User).where(func.lower(User.username) == user_data.username.lower()),
        )

        user_exist = result.scalars().first()
        if user_exist:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Este Usuario ya está registrado.",
            )

    if user_data.email is not None and user_data.email.lower() != user.email.lower():
        result = db.execute(
            select(User).where(func.lower(User.email) == user_data.email.lower()),
        )
        email_exist = result.scalars().first()
        if email_exist:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Este Email ya está registrado.",
            )

    # Establecemos cada campo editado dinamicamente, dejamos los otros iguales
    update_data = user_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    db.commit()
    db.refresh(user)

    return user


# ----------------------------------------------------------------------
# Elimina un usuario
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Users"])
def delete_user(
    user_id: int,
    db: Annotated[Session, Depends(get_db)],
    current_admin: User = Depends(get_current_admin),
):
    # Si se llega acá es por que es user Admin
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Este usuario no está registrado.",
        )

    # No se puede eliminar el usuario principal
    if user_id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Este usuario no puede eliminarse a si mismo.",
        )

    db.delete(user)
    db.commit()
