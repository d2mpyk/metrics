import math
from typing import Annotated
from datetime import datetime, timezone, timedelta, UTC
from fastapi import APIRouter, Depends, Query, Request, status, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
import jwt
from sqlalchemy import and_, desc, func, select
from sqlalchemy.orm import Session, joinedload, aliased

# Import's Locales
from models.clients import Client, ApprovedClient, ServerMetric, DeviceCode
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

    # Si el cliente no tiene descripción, intentamos recuperarla de ApprovedClient
    if not client.description:
        approved_client = (
            db.execute(
                select(ApprovedClient).where(
                    ApprovedClient.ip_address == client.ip_address
                )
            )
            .scalars()
            .first()
        )
        if approved_client and approved_client.description:
            client.description = approved_client.description
            db.commit()
            db.refresh(client)

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
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
    page: Annotated[int, Query(ge=1, description="Número de página")] = 1,
):
    """
    Obtiene una lista paginada de todos los clientes registrados.
    Este endpoint es accesible solo para administradores.
    """
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    current_admin = admin_or_redirect

    limit = 20
    skip = (page - 1) * limit

    # Subconsulta para obtener la métrica más reciente por cliente
    latest_metrics_subquery = select(
        ServerMetric,
        func.row_number()
        .over(
            partition_by=ServerMetric.client_id, order_by=desc(ServerMetric.timestamp)
        )
        .label("rn"),
    ).subquery()
    # Usamos aliased para mapear la subconsulta a un objeto ServerMetric
    MetricAlias = aliased(ServerMetric, latest_metrics_subquery)

    # Consulta principal que une Clientes con su última métrica
    query = (
        select(Client, MetricAlias)
        .outerjoin(
            MetricAlias,
            and_(
                Client.id == MetricAlias.client_id,
                latest_metrics_subquery.c.rn == 1,
            ),
        )
        .order_by(desc(Client.id))
        .offset(skip)
        .limit(limit)
    )

    results = db.execute(query).all()
    clients_with_metrics = []
    for client, metric in results:
        # Asegurar que el timestamp tenga zona horaria para evitar errores en el template
        if metric and metric.timestamp and metric.timestamp.tzinfo is None:
            metric.timestamp = metric.timestamp.replace(tzinfo=UTC)
        client.latest_metric = metric  # Ahora metric es un objeto ServerMetric o None
        clients_with_metrics.append(client)

    total_clients = db.execute(select(func.count(Client.id))).scalar() or 0
    total_pages = math.ceil(total_clients / limit) if total_clients > 0 else 1

    return templates.TemplateResponse(
        request=request,
        name="dashboard/clients.html",
        context={
            "clients": clients_with_metrics,
            "user": current_admin,
            "data": get_dashboard_stats(db),
            "title": "Gestión de Dispositivos",
            "current_page": page,
            "total_pages": total_pages,
            "now": datetime.now(UTC),
        },
    )


@router.get(
    "/approved",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    name="get_approved_clients",
)
def get_approved_clients(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    """Lista todas las IPs aprobadas."""
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    current_admin = admin_or_redirect

    approved_clients = (
        db.execute(select(ApprovedClient).order_by(desc(ApprovedClient.id)))
        .scalars()
        .all()
    )

    # Para cada IP aprobada, buscamos si hay códigos de dispositivo pendientes de activar
    if approved_clients:
        for ac in approved_clients:
            ac.pending_codes = (
                db.execute(
                    select(DeviceCode).where(
                        DeviceCode.ip_address == ac.ip_address,
                        DeviceCode.is_verified == False,
                        DeviceCode.expires_at > datetime.now(UTC),
                    )
                )
                .scalars()
                .all()
            )

    data = get_dashboard_stats(db)

    # Recuperar mensajes flash de las cookies
    flash_message = request.cookies.get("flash_message")
    flash_type = request.cookies.get("flash_type")

    response = templates.TemplateResponse(
        request=request,
        name="dashboard/approved_clients.html",
        context={
            "approved_clients": approved_clients,
            "user": current_admin,
            "data": data,
            "title": "IPs Aprobadas",
            "flash_message": flash_message,
            "flash_type": flash_type,
        },
    )

    # Limpiar cookies flash si existen para que el mensaje no persista
    if flash_message:
        response.delete_cookie("flash_message")
        response.delete_cookie("flash_type")

    return response


@router.post(
    "/approved",
    status_code=status.HTTP_303_SEE_OTHER,
    include_in_schema=False,
    name="create_approved_client",
)
def create_approved_client(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
    ip_address: Annotated[str, Form()],
    description: Annotated[str, Form()],
):
    """
    Registra una dirección IP en la lista de clientes aprobados.
    Solo accesible por administradores.
    """
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    current_admin = admin_or_redirect

    existing_ip = (
        db.execute(
            select(ApprovedClient).where(ApprovedClient.ip_address == ip_address)
        )
        .scalars()
        .first()
    )

    if existing_ip:
        response = RedirectResponse(
            url=request.url_for("get_approved_clients"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
        response.set_cookie(
            key="flash_message",
            value="Error: Esta dirección IP ya se encuentra aprobada.",
            httponly=True,
        )
        response.set_cookie(key="flash_type", value="red", httponly=True)
        return response

    new_client = ApprovedClient(
        ip_address=ip_address,
        description=description,
    )

    db.add(new_client)
    db.commit()

    response = RedirectResponse(
        url=request.url_for("get_approved_clients"),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.set_cookie(
        key="flash_message", value="IP aprobada correctamente.", httponly=True
    )
    response.set_cookie(key="flash_type", value="green", httponly=True)

    return response


@router.get(
    "/{client_id}",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    name="get_client_details",
)
def get_client_details(
    request: Request,
    client_id: int,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    """Muestra la vista de detalles de un cliente específico."""
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    current_admin = admin_or_redirect

    client = db.get(Client, client_id)
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


@router.post(
    "/{client_id}/update",
    status_code=status.HTTP_303_SEE_OTHER,
    include_in_schema=False,
    name="update_client_description",
)
def update_client_description(
    request: Request,
    client_id: int,
    description: Annotated[str, Form()],
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    """Actualiza manualmente la descripción de un cliente."""
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect

    client = db.get(Client, client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Cliente no encontrado"
        )

    client.description = description
    db.commit()

    return RedirectResponse(
        url=request.url_for("get_client_details", client_id=client_id),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/{client_id}/metrics",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    name="get_client_metrics_view",
)
def get_client_metrics_view(
    request: Request,
    client_id: int,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
):
    """Muestra la vista de métricas en tiempo real para un cliente."""
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    current_admin = admin_or_redirect

    client = db.get(Client, client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Cliente no encontrado"
        )

    data = get_dashboard_stats(db)

    return templates.TemplateResponse(
        request=request,
        name="dashboard/client_metrics.html",
        context={
            "client": client,
            "user": current_admin,
            "data": data,
            "title": f"Métricas: {client.description or client.client_identifier}",
        },
    )


@router.get(
    "/{client_id}/metrics/json",
    status_code=status.HTTP_200_OK,
)
def get_client_metrics_json(
    client_id: int,
    db: Annotated[Session, Depends(get_db)],
    admin_or_redirect: Annotated[User | RedirectResponse, Depends(get_current_admin)],
    last_timestamp: Annotated[datetime | None, Query()] = None,
    time_range: Annotated[str | None, Query()] = None,
):
    """Devuelve las últimas 20 métricas de un cliente en formato JSON para polling."""
    if isinstance(admin_or_redirect, RedirectResponse):
        return admin_or_redirect
    # current_admin = admin_or_redirect # No se usa, pero lo dejamos por consistencia

    client_exists = db.get(Client, client_id)
    if not client_exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Cliente no encontrado"
        )

    query = select(ServerMetric).where(ServerMetric.client_id == client_id)

    if time_range:
        # Lógica para rangos históricos
        now = datetime.now(UTC)
        if time_range == "day":
            start_date = now - timedelta(days=1)
        elif time_range == "week":
            start_date = now - timedelta(weeks=1)
        elif time_range == "month":
            start_date = now - timedelta(days=30)
        else:
            start_date = now - timedelta(days=1)

        # Traer todas las métricas del rango en orden ascendente
        query = query.where(ServerMetric.timestamp >= start_date).order_by(ServerMetric.timestamp.asc())
        metrics = db.execute(query).scalars().all()
    elif last_timestamp:
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
                "net_speed_sent_kbytes_s": (
                    round(m.net_speed_sent / 1024, 2)
                    if m.net_speed_sent is not None
                    else 0
                ),
                "net_speed_recv_kbytes_s": (
                    round(m.net_speed_recv / 1024, 2)
                    if m.net_speed_recv is not None
                    else 0
                ),
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Error de desencriptación"
        )

    # --- Lógica para calcular la velocidad de red (Delta) ---
    # 1. Obtener la última métrica para este cliente
    last_metric = (
        db.execute(
            select(ServerMetric)
            .where(ServerMetric.client_id == current_client.id)
            .order_by(desc(ServerMetric.timestamp))
        )
        .scalars()
        .first()
    )

    # 2. Obtener valores acumulativos del payload
    new_net_sent = decrypted_data.get("net_sent")
    new_net_recv = decrypted_data.get("net_recv")
    speed_sent_bps = 0.0
    speed_recv_bps = 0.0
    current_timestamp = datetime.now(UTC)

    # 3. Calcular velocidad si existe una métrica anterior
    if last_metric and new_net_sent is not None and new_net_recv is not None:
        last_ts = last_metric.timestamp
        # Asegurar que last_ts tenga timezone para evitar error de sustracción
        if last_ts.tzinfo is None:
            last_ts = last_ts.replace(tzinfo=UTC)
        time_delta = (current_timestamp - last_ts).total_seconds()

        if time_delta > 0:
            # Manejar reinicio de contadores (si el nuevo valor es menor)
            if new_net_sent >= last_metric.net_sent:
                speed_sent_bps = (new_net_sent - last_metric.net_sent) / time_delta

            if new_net_recv >= last_metric.net_recv:
                speed_recv_bps = (new_net_recv - last_metric.net_recv) / time_delta

    new_metric = ServerMetric(
        client_id=current_client.id,
        cpu_usage=decrypted_data.get("cpu"),
        ram_usage=decrypted_data.get("ram"),
        disk_usage=decrypted_data.get("disk"),
        net_sent=new_net_sent,
        net_recv=new_net_recv,
        net_speed_sent=speed_sent_bps,
        net_speed_recv=speed_recv_bps,
        timestamp=current_timestamp,
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
