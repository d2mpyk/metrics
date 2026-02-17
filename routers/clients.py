from datetime import datetime, UTC
from zoneinfo import ZoneInfo
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.clients import ApprovedClient, Client, ServerMetric
from models.users import User
from schemas.clients import ApprovedClientResponse, ApprovedClientCreate
from schemas.metrics import EncryptedMetrics
from utils.auth import get_current_client, get_current_user, get_current_admin
from utils.database import get_db
from utils.config import get_settings
from utils.crypto import decrypt_payload

router = APIRouter()
settings = get_settings()


# ----------------------------------------------------------------------
def convert_to_server_time(utc_dt: datetime) -> datetime:
    """Convierte un datetime UTC a la zona horaria del servidor."""
    server_tz = ZoneInfo(settings.UTC_SERVER)
    return utc_dt.astimezone(server_tz)


# ----------------------------------------------------------------------
# Admin: Aprobar una IP para Device Flow
@router.get(
    "/approved",
    response_model=list[ApprovedClientResponse],
    status_code=status.HTTP_200_OK,
)
def get_approved_client(
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[User, Depends(get_current_admin)],
):
    result = db.execute(select(ApprovedClient))
    clients = result.scalars().all()

    if clients:
        return clients
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="No hay clientes registrados.",
    )


# ----------------------------------------------------------------------
# Admin: Aprobar una IP para Device Flow
@router.post(
    "/approved",
    status_code=status.HTTP_201_CREATED,
    response_model=ApprovedClientCreate,
)
def create_approved_client(
    client_data: ApprovedClientCreate,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[User, Depends(get_current_admin)],
):
    """Registra una IP en la lista blanca para permitir la vinculación de dispositivos."""
    # Verificar si ya existe
    existing = (
        db.execute(
            select(ApprovedClient).where(
                ApprovedClient.ip_address == client_data.ip_address
            )
        )
        .scalars()
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Esta IP ya está aprobada.",
        )

    new_approved = ApprovedClient(
        ip_address=client_data.ip_address, description=client_data.description
    )
    db.add(new_approved)
    db.commit()
    db.refresh(new_approved)
    return new_approved


# ----------------------------------------------------------------------
# Cliente: Enviar Métricas
@router.post("/metrics", status_code=status.HTTP_201_CREATED)
def receive_metrics(
    payload: EncryptedMetrics,
    client: Annotated[Client, Depends(get_current_client)],
    db: Annotated[Session, Depends(get_db)],
):
    """
    Recibe métricas encriptadas, las desencripta y las guarda
    con el timestamp ajustado a la zona horaria del servidor.
    """
    # 1. Desencriptar
    try:
        data = decrypt_payload(
            payload.nonce, payload.ciphertext, client.client_secret_key
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Fallo en la desencriptación",
        )

    # 2. Convertir Timestamp (UTC -> Server Time)
    current_utc = datetime.now(UTC)
    server_time = convert_to_server_time(current_utc)

    # 3. Guardar Métricas
    metric = ServerMetric(
        client_id=client.id,
        cpu_usage=data.get("cpu", 0.0),
        ram_usage=data.get("ram", 0.0),
        disk_usage=data.get("disk", 0.0),
        timestamp=server_time,
    )

    client.last_seen = server_time
    db.add(metric)
    db.commit()

    return {"status": "ok"}
