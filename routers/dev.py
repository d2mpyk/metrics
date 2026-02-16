from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get(
    "/preview/email-confirmation",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def preview_email_confirmation(request: Request):
    """Renderiza una vista previa de la plantilla de confirmación de correo."""
    context = {
        "request": request,
        "user": "UsuarioDePrueba",
        "url": "http://localhost:8000/api/v1/users/verify/un-token-de-ejemplo-muy-largo",
    }
    return templates.TemplateResponse("email_confirmation.html", context)


@router.get(
    "/preview/password-reset", response_class=HTMLResponse, include_in_schema=False
)
def preview_password_reset(request: Request):
    """Renderiza una vista previa de la plantilla de reseteo de contraseña."""
    context = {
        "request": request,
        "username": "UsuarioDePrueba",
        "email": "test@example.com",
        "url": "http://localhost:8000/reset-password?token=un-token-de-ejemplo-muy-largo",
    }
    return templates.TemplateResponse("password_reset_email.html", context)
