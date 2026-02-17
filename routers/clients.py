from typing import Annotated
from fastapi import APIRouter, Depends, Query, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# Import's Locales
from models.clients import Client, ApprovedClient, ServerMetric
from models.users import User
from utils.auth import get_current_admin
from utils.config import get_settings
from utils.crypto import decrypt_payload
from utils.database import get_db
from schemas.client import (
    PaginatedClientResponse,
    ApprovedClientCreate,
    ApprovedClientResponse,
    EncryptedMetrics,
)

router = APIRouter()


settings = get_settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


async def get_current_client(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM.get_secret_value()],
        )
        client_id: int = payload.get("client_id")
        role: str = payload.get("role")
        if client_id is None or role != "device":
            raise credentials_exception
    except (jwt.InvalidTokenError, AttributeError):
        raise credentials_exception

    client = db.execute(select(Client).where(Client.id == client_id)).scalars().first()
    if client is None:
        raise credentials_exception
    return client


@router.get(
    "",
    response_model=PaginatedClientResponse,
    status_code=status.HTTP_200_OK,
)
def get_all_clients(
    db: Annotated[Session, Depends(get_db)],
    current_admin: Annotated[User, Depends(get_current_admin)],
    skip: Annotated[int, Query(ge=0, description="Número de registros a saltar")] = 0,
    limit: Annotated[
        int, Query(ge=1, le=200, description="Número máximo de registros a devolver")
    ] = 100,
):
    """
    Obtiene una lista paginada de todos los clientes registrados.
    Este endpoint es accesible solo para administradores.
    """
    total = db.execute(select(func.count(Client.id))).scalar() or 0
    clients = db.execute(select(Client).offset(skip).limit(limit)).scalars().all()

    # The response model `PaginatedClientResponse` seems to require a `description`
    # field for each client, but the `Client` SQLAlchemy model does not have one.
    # We add a default value to each object before returning to satisfy validation.
    for client in clients:
        client.description = "N/A"

    return {"total": total, "clients": clients, "description": "N/A"}


@router.post(
    "/approved",
    response_model=ApprovedClientResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_approved_client(
    client_data: ApprovedClientCreate,
    db: Annotated[Session, Depends(get_db)],
    current_admin: Annotated[User, Depends(get_current_admin)],
):
    """
    Registra una dirección IP en la lista de clientes aprobados.
    Solo accesible por administradores.
    """
    existing_ip = (
        db.execute(
            select(ApprovedClient).where(
                ApprovedClient.ip_address == client_data.ip_address
            )
        )
        .scalars()
        .first()
    )

    if existing_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta dirección IP ya se encuentra aprobada.",
        )

    new_client = ApprovedClient(
        ip_address=client_data.ip_address,
        description=client_data.description,
    )

    db.add(new_client)
    db.commit()
    db.refresh(new_client)

    return new_client


@router.get(
    "/approved",
    response_model=list[ApprovedClientResponse],
    status_code=status.HTTP_200_OK,
)
def get_approved_clients(
    db: Annotated[Session, Depends(get_db)],
    current_admin: Annotated[User, Depends(get_current_admin)],
):
    """Lista todas las IPs aprobadas."""
    return db.execute(select(ApprovedClient)).scalars().all()


@router.post("/metrics", status_code=status.HTTP_201_CREATED)
def receive_metrics(
    metrics_data: EncryptedMetrics,
    db: Annotated[Session, Depends(get_db)],
    current_client: Annotated[Client, Depends(get_current_client)],
):
    """Recibe métricas encriptadas de un cliente."""
    try:
        decrypted_data = decrypt_payload(
            metrics_data.nonce,
            metrics_data.ciphertext,
            current_client.client_secret_key,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Error de desencriptación")

    new_metric = ServerMetric(
        client_id=current_client.id,
        cpu_usage=decrypted_data.get("cpu"),
        ram_usage=decrypted_data.get("ram"),
        disk_usage=decrypted_data.get("disk"),
    )

    db.add(new_metric)
    db.commit()

    return {"status": "ok"}
