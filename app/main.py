"""Esta es una plantilla de FastAPI con model User, Auth y DB"""

from fastapi import FastAPI, Request, status

# Para enviar respuestas HTML
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import sys

# Imports Locales
from utils.database import Base, engine
from routers import auth, clients, dashboard, dev, media, users
from utils.init_db import get_init_config, init_approved_users
from utils.middleware import HTMLAuthMiddleware


# Verificación de configuraciones iniciales
get_init_config()
# Instancia la ceación de la base y sus tablas sino existen
Base.metadata.create_all(bind=engine)
# Verificación inicial de base de datos
init_approved_users()
# Instancia la aplicación de FastAPI
app = FastAPI(
    title="FastAPI Template",
    description="Este es una plantilla de app en FastAPI",
    version="1.0.0",
)
# Middleware
app.add_middleware(HTMLAuthMiddleware)

# Montar archivos estáticos (CSS/JS/Imagenes)
app.mount("/static", StaticFiles(directory="static"), name="static")
# Monta los archivos de imagenes de usuario
app.mount("/media", StaticFiles(directory="media"), name="media")

# Configurar motor de plantillas
templates = Jinja2Templates(directory="templates")

# Enrutadores
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(clients.router, prefix="/api/v1/clients", tags=["Clients"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(dev.router, prefix="/dev", tags=["Development"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(media.router, prefix="/api/v1/media", tags=["Media"])


# Muestra la pagina principal del sitio
@app.get(
    "/",
    name="login",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def inicio(request: Request):
    """Renderiza la página inicial"""
    return templates.TemplateResponse(
        request=request,
        name="login/login.html",
        context={"title": "Iniciar Sesión"},
    )


# -----------------------------------------------
# Muestra la pagina de recuperar contraseña
@app.get(
    "/forgot-password",
    name="forgot-password",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def forgot_password_view(request: Request):
    """Renderiza la página recuperar contraseña"""
    return templates.TemplateResponse(
        request=request,
        name="login/forgot-password.html",
        context={"title": "Recupera tu contraseña"},
    )


# -----------------------------------------------
# Muestra la pagina de resetear contraseña
@app.get(
    "/reset-password",
    name="reset-password",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def reset_password_view(request: Request):
    """Renderiza la página de resetear contraseña"""
    return templates.TemplateResponse(
        request=request,
        name="login/reset-password.html",
        context={"title": "Restablecer contraseña"},
    )
