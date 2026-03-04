from sqlalchemy.orm import Session
from models.users import User
from models.clients import Client
from sqlalchemy import func, select
from fastapi import HTTPException, status


def get_total_users(db: Session) -> int:
    if db.query(func.count(User.id)).scalar() is None:
        return 0
    return db.query(func.count(User.id)).scalar()


def get_total_clients(db: Session) -> int:
    if db.query(func.count(Client.id)).scalar() is None:
        return 0
    return db.query(func.count(Client.id)).scalar()


def check_username_exists(
    db: Session, username: str, current_user_id: int | None = None
):
    """Comprueba si un nombre de usuario ya existe, excluyendo opcionalmente al usuario actual."""
    query = select(User).where(func.lower(User.username) == username.lower())
    if current_user_id:
        query = query.where(User.id != current_user_id)

    if db.execute(query).scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este nombre de usuario ya está registrado.",
        )


def check_email_exists(db: Session, email: str, current_user_id: int | None = None):
    """Comprueba si un email ya existe, excluyendo opcionalmente al usuario actual."""
    query = select(User).where(func.lower(User.email) == email.lower())
    if current_user_id:
        query = query.where(User.id != current_user_id)

    if db.execute(query).scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este Email ya está registrado.",
        )
