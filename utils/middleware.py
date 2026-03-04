from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import RedirectResponse
from fastapi import Request
from .auth import verify_access_token  # tu función JWT

class HTMLAuthMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        path = request.url.path

        # 🔓 Rutas públicas permitidas
        public_paths = [
            "/",
            "/api/v1/auth/token",
            "/api/v1/users/verify"
        ]

        # Permitir rutas públicas
        if path in public_paths:
            return await call_next(request)

        # Permitir archivos estáticos
        if path.startswith("/static") or path.startswith("/media"):
            return await call_next(request)

        # 🔐 SOLO proteger vistas HTML
        if path.startswith("/api/v1/dashboard"):

            token = request.cookies.get("access_token")

            if not token:
                return RedirectResponse(url="/")

            try:
                verify_access_token(token)
            except Exception:
                return RedirectResponse(url="/")

        return await call_next(request)
