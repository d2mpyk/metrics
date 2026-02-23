import math
from typing import Annotated
from datetime import datetime, timezone, UTC, timedelta
from fastapi import APIRouter, Depends, Query, Request, status, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
import jwt
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

# Import's Locales
from models.clients import Client, ApprovedClient, ServerMetric
from models.users import User
from utils.auth import (
    create_access_token,
    get_current_admin,
    get_minutes_until_end_of_year,
)
from utils.config import get_settings
from utils.crypto import decrypt_payload
from utils.database import get_db
from utils.stats import get_dashboard_stats
from schemas.client import (
    PaginatedClientResponse,
    ApprovedClientCreate,
    ApprovedClientResponse,
    EncryptedMetrics,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

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

        # Validar expiración manualmente comparando con fecha actual
        exp = payload.get("exp")
        if exp is None or datetime.now(UTC).timestamp() > exp:
            raise credentials_exception

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
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def get_all_clients(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_admin: Annotated[User, Depends(get_current_admin)],
    page: Annotated[int, Query(ge=1, description="Número de página")] = 1,
):
    """
    Obtiene una lista paginada de todos los clientes registrados.
    Este endpoint es accesible solo para administradores.
    """
    limit = 20
    skip = (page - 1) * limit

    total_clients = db.execute(select(func.count(Client.id))).scalar() or 0
    total_pages = math.ceil(total_clients / limit) if total_clients > 0 else 1

    clients = (
        db.execute(select(Client).order_by(desc(Client.id)).offset(skip).limit(limit))
        .scalars()
        .all()
    )

    data = get_dashboard_stats(db)

    return templates.TemplateResponse(
        request=request,
        name="dashboard/clients.html",
        context={
            "clients": clients,
            "user": current_admin,
            "data": data,
            "title": "Gestión de Dispositivos",
            "current_page": page,
            "total_pages": total_pages,
        },
    )


@router.get(
    "/{client_id}",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def get_client_details(
    request: Request,
    client_id: int,
    db: Annotated[Session, Depends(get_db)],
    current_admin: Annotated[User, Depends(get_current_admin)],
):
    """Muestra la vista de detalles de un cliente específico."""
    client = db.execute(select(Client).where(Client.id == client_id)).scalars().first()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Cliente no encontrado"
        )

    data = get_dashboard_stats(db)

    return templates.TemplateResponse(
        request=request,
        name="dashboard/client_details.html",
        context={
            "client": client,
            "user": current_admin,
            "data": data,
            "title": f"Detalles: {client.client_identifier}",
        },
    )


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


@router.post(
    "/approved",
    response_model=ApprovedClientResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
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
    "/{client_id}/metrics/json",
    status_code=status.HTTP_200_OK,
)
def get_client_metrics_json(
    client_id: int,
    db: Annotated[Session, Depends(get_db)],
    current_admin: Annotated[User, Depends(get_current_admin)],
    last_timestamp: Annotated[datetime | None, Query()] = None,
):
    """Devuelve las últimas 20 métricas de un cliente en formato JSON para polling."""
    client_exists = db.execute(select(Client.id).where(Client.id == client_id)).scalar()
    if not client_exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Cliente no encontrado"
        )

    query = select(ServerMetric).where(ServerMetric.client_id == client_id)

    if last_timestamp:
        # Si hay timestamp, traemos solo las nuevas (orden ascendente para el gráfico)
        query = query.where(ServerMetric.timestamp > last_timestamp).order_by(
            ServerMetric.timestamp.asc()
        )
        metrics = db.execute(query).scalars().all()
    else:
        # Carga inicial: últimas 20
        metrics = (
            db.execute(query.order_by(desc(ServerMetric.timestamp)).limit(20))
            .scalars()
            .all()
        )
        metrics = list(reversed(metrics))  # Invertir para orden cronológico

    data = []
    for m in metrics:
        data.append(
            {
                "timestamp": m.timestamp.strftime("%H:%M:%S"),
                "full_timestamp": m.timestamp.isoformat(),
                "cpu": m.cpu_usage,
                "ram": m.ram_usage,
                "disk": m.disk_usage,
            }
        )

    return data


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


@router.post("/renew-token", status_code=status.HTTP_200_OK)
def renew_token(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
):
    """
    Renueva el token del dispositivo.
    Permite renovación con token expirado SOLO durante los primeros 5 días del año.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar el token para renovación.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # 1. Decodificar SIN verificar expiración para leer claims
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM.get_secret_value()],
            options={"verify_exp": False},
        )

        client_id: int = payload.get("client_id")
        role: str = payload.get("role")
        exp: int = payload.get("exp")

        if client_id is None or role != "device":
            raise credentials_exception

        # 2. Validar Ventana de Renovación (Grace Period)
        now = datetime.now(UTC)
        if exp and now.timestamp() > exp:
            # Si expiró, solo permitimos renovar del 1 al 3 de Enero
            if not (now.month == 1 and now.day <= 3):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="El periodo de gracia para renovación ha finalizado (1-5 Ene).",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Y solo si el token es del año inmediatamente anterior
            exp_date = datetime.fromtimestamp(exp, tz=UTC)
            if exp_date.year != (now.year - 1):
                raise credentials_exception

    except (jwt.InvalidTokenError, AttributeError):
        raise credentials_exception

    # 3. Verificar Cliente
    client = db.execute(select(Client).where(Client.id == client_id)).scalars().first()
    if not client or not client.is_active:
        raise credentials_exception

    # 4. Generar Nuevo Token
    minutes = get_minutes_until_end_of_year()
    access_token_expires = timedelta(minutes=minutes)

    new_token = create_access_token(
        data={
            "sub": client.client_identifier,
            "type": "client",
            "role": "device",
            "client_id": client.id,
        },
        expires_delta=access_token_expires,
    )

    return {
        "access_token": new_token,
        "token_type": "bearer",
        "expires_in": int(access_token_expires.total_seconds()),
    }
