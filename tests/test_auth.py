# s:\WISE\Management\SERVER\tests\test_auth.py
from datetime import datetime, timedelta, timezone
import secrets
from fastapi import status
from sqlalchemy import select
from models.clients import ApprovedClient, DeviceCode


def test_login_success_returns_token_and_cookie(client, test_user):
    """
    Verifica que el login exitoso devuelva el JSON estándar de OAuth2
    Y ADEMÁS establezca la cookie HttpOnly (flujo híbrido).
    """
    response = client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # 1. Verificar respuesta JSON (Estándar OAuth2)
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # 2. Verificar Cookie (Seguridad Web)
    assert "access_token" in response.cookies


def test_login_invalid_credentials(client, test_user):
    """Verifica que credenciales incorrectas devuelvan 401."""
    response = client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": "wrongpassword"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_access_protected_route_via_cookie(client, test_user):
    """
    Verifica el acceso a una ruta protegida confiando en la Cookie.
    Este es el comportamiento que usará el Frontend (Navegador).
    """
    # 1. Login (TestClient guarda las cookies automáticamente en su jar)
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    # 2. Acceder a ruta protegida sin enviar headers manuales
    response = client.get("/api/v1/users/me")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["email"] == test_user["email"]


def test_access_protected_route_via_header(client, test_user):
    """
    Verifica el acceso a una ruta protegida usando el Header Authorization.
    Este es el comportamiento para Apps Móviles o Swagger UI.
    """
    # 1. Login para obtener el token string
    login_res = client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )
    token = login_res.json()["access_token"]

    # 2. Limpiamos las cookies del cliente para asegurar que no se usen
    client.cookies.clear()

    # 3. Acceder enviando explícitamente el Header
    response = client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["email"] == test_user["email"]


def test_access_denied_without_token(client):
    """Verifica que se deniegue el acceso si no hay cookie ni header."""
    # Al ser una app web, redirige al login en lugar de dar 401 JSON
    response = client.get("/api/v1/users/me", follow_redirects=False)
    assert response.status_code in [
        status.HTTP_302_FOUND,
        status.HTTP_303_SEE_OTHER,
        status.HTTP_307_TEMPORARY_REDIRECT,
    ]


def test_logout_clears_cookie(client, test_user):
    """Verifica que el endpoint de logout invalide la cookie."""
    # Login previo
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    # Logout
    response = client.post("/api/v1/auth/logout", follow_redirects=False)

    # Verificar redirección
    assert response.status_code == status.HTTP_303_SEE_OTHER

    # Verificar que la cookie se ha mandado a borrar
    # Buscamos en los headers de respuesta la instrucción de borrado
    set_cookie = response.headers.get("set-cookie")
    assert set_cookie is not None
    # Generalmente se borra seteando valor vacío o Max-Age=0
    assert 'access_token=""' in set_cookie or "Max-Age=0" in set_cookie


def test_device_activation_flow_redirects(client, admin_user, db_session):
    """
    Verifica que el flujo de activación:
    1. Redirija con error si el código es inválido.
    2. Redirija con éxito y cookies flash si el código es válido.
    """
    # 1. Login Admin
    login_payload = {
        "username": admin_user["email"],
        "password": admin_user["password"],
    }
    client.post("/api/v1/auth/token", data=login_payload)

    # 2. Caso Error: Código Inválido
    resp_invalid = client.post(
        "/api/v1/auth/device/activate",
        data={"user_code": "INVALID-CODE"},
        follow_redirects=False,
    )
    assert resp_invalid.status_code == status.HTTP_303_SEE_OTHER
    # Verifica que redirige a la misma vista de activación
    assert resp_invalid.headers["location"].endswith("/device/activate")
    assert "flash_message" in resp_invalid.cookies
    assert resp_invalid.cookies["flash_type"] == "red"

    # 3. Caso Éxito: Preparar datos (IP aprobada y código generado)
    # Nota: 'testclient' es el host por defecto de TestClient
    approved_client_rec = ApprovedClient(
        ip_address="testclient", description="Test Auth"
    )
    db_session.add(approved_client_rec)
    db_session.commit()
    user_code = "AAAA-BBBB"
    device_code = secrets.token_urlsafe(32)
    db_session.add(
        DeviceCode(
            device_code=device_code,
            user_code="AAAABBBB",  # Normalizado en DB
            ip_address="testclient",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            is_verified=False,
        )
    )
    db_session.commit()

    # 4. Activar
    resp_success = client.post(
        "/api/v1/auth/device/activate",
        data={"user_code": user_code},  # Enviamos con guión
        follow_redirects=False,
    )
    assert resp_success.status_code == status.HTTP_303_SEE_OTHER
    assert (
        resp_success.headers["location"]
        == "http://testserver/metrics/api/v1/dashboard/"
    )
    assert "flash_message" in resp_success.cookies
    assert resp_success.cookies["flash_type"] == "green"

    # 5. Verificar que el ApprovedClient fue eliminado
    deleted_approved_client = db_session.get(ApprovedClient, approved_client_rec.id)
    assert deleted_approved_client is None
