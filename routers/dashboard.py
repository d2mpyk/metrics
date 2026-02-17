from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Request,
    status,
)

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

# Import's Locales
from models.clients import ServerMetric
from utils.auth import CurrentUser
from utils.database import get_db
from utils.users import get_total_users


# Instancia de las rutas
router = APIRouter()
# Configurar motor de plantillas
templates = Jinja2Templates(directory="templates")


# ----------------------------------------------------------------------
# Muestra el Dashboard
@router.get(
    "/",
    name="dashboard",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    tags=["Dashboard"],
    include_in_schema=False,
)
def dashboard(
    request: Request,
    current_user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
):
    data = {}
    data["total_users"] = get_total_users(db)
    return templates.TemplateResponse(
        "dashboard/dashboard.html",
        {
            "request": request,
            "user": current_user,
            "data": data,
        },
    )


# ----------------------------------------------------------------------
# Muestra las métricas
@router.get(
    "/metrics",
    name="metrics",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    tags=["Dashboard"],
    include_in_schema=False,
)
def metrics_view(
    request: Request,
    current_user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
):
    # Obtener las últimas 50 métricas
    result = db.execute(
        select(ServerMetric).order_by(desc(ServerMetric.timestamp)).limit(50)
    )
    metrics = result.scalars().all()

    return templates.TemplateResponse(
        request=request,
        name="dashboard/metrics.html",
        context={
            "user": current_user,
            "metrics": metrics,
            "title": "Métricas de Servidores",
        },
    )
