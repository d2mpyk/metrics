from datetime import timedelta
from typing import Annotated

from fastapi import (
    APIRouter, 
    BackgroundTasks, 
    Depends, 
    HTTPException, 
    Request,
    status,
)
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from models.users import User, ApprovedUsers
from utils.database import get_db
from utils.auth import (
    generate_verification_token,
    send_email_confirmation,
    confirm_verification_token,
)
from schemas.user import (
    ApprovedUsersResponse,
    UserCreate,
    UserResponsePrivate,
    UserUpdate,
)

# Import's Locales
from utils.config import settings
from utils.auth import CurrentUser, hash_password

# Instancia de las rutas
router = APIRouter()
# Configurar motor de plantillas
templates = Jinja2Templates(directory="templates")

# ----------------------------------------------------------------------
# Muestra mi usuario
@router.get("/me", response_model=UserResponsePrivate, status_code=status.HTTP_200_OK)
def get_current_user(current_user: CurrentUser):
    """Obtiene el usuario actual autenticado."""
    return current_user


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
        select(ApprovedUsers).where(func.lower(ApprovedUsers.email) == approved_email.lower())
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
    verify_url = (
        f"http://{DOMINIO}/api/v1/users/verify/{token}"
    )
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
    if user_id == user.id:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Este usuario no puede eliminarse a si mismo.",
        )
    
    db.delete(user)
    db.commit()


