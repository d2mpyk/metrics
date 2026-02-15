from datetime import timedelta
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends, 
    Request,
    status,
)

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# Import's Locales
from models.users import User, ApprovedUsers
from utils.auth import CurrentUser
from utils.config import settings
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
        }
    )