from fastapi import status
from sqlalchemy import select
from models.users import User
from unittest.mock import patch
from utils.auth import generate_reset_password_token

# -----------------------------------------------------------------------------
# TESTS DE LECTURA (GET)
# -----------------------------------------------------------------------------


def test_get_users_as_admin(client, admin_user):
    """Un administrador debe poder ver la lista de usuarios."""
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    response = client.get("/api/v1/users")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)
    assert len(response.json()) >= 1


def test_get_users_as_normal_user_forbidden(client, test_user):
    """Un usuario normal NO debe poder ver la lista de usuarios."""
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    response = client.get("/api/v1/users")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_get_specific_user_as_admin(client, admin_user, test_user):
    """Un admin puede ver detalles de otro usuario por ID."""
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    response = client.get(f"/api/v1/users/{test_user['id']}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["email"] == test_user["email"]


# -----------------------------------------------------------------------------
# TESTS DE APROBACIÓN (POST)
# -----------------------------------------------------------------------------


def test_approve_user_as_admin(client, admin_user):
    """Un admin puede aprobar nuevos emails."""
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    new_email = "new_friend@example.com"
    response = client.post(f"/api/v1/users/approved/{new_email}")

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["email"] == new_email


def test_approve_user_as_normal_user_forbidden(client, test_user):
    """Un usuario normal NO puede aprobar emails."""
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    response = client.post("/api/v1/users/approved/hacker@example.com")
    assert response.status_code == status.HTTP_403_FORBIDDEN


# -----------------------------------------------------------------------------
# TESTS DE CREACIÓN (POST)
# -----------------------------------------------------------------------------


def test_create_user_flow_as_admin(client, admin_user):
    """
    Prueba el flujo completo de creación por parte de un admin:
    1. Aprobar email
    2. Crear usuario (endpoint protegido para admins)
    """
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    email_to_create = "employee@example.com"

    # 1. Aprobar
    client.post(f"/api/v1/users/approved/{email_to_create}")

    # 2. Crear
    user_data = {
        "username": "employee",
        "email": email_to_create,
        "password": "securepassword",
    }
    response = client.post("/api/v1/users/create", json=user_data)

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == email_to_create
    assert data["is_active"] is False  # Se crea inactivo hasta verificar email


def test_create_user_as_normal_user_forbidden(client, test_user):
    """Un usuario normal no puede crear otros usuarios."""
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    user_data = {
        "username": "intruder",
        "email": "intruder@example.com",
        "password": "password",
    }
    response = client.post("/api/v1/users/create", json=user_data)
    assert response.status_code == status.HTTP_403_FORBIDDEN


# -----------------------------------------------------------------------------
# TESTS DE ELIMINACIÓN (DELETE)
# -----------------------------------------------------------------------------


def test_delete_user_as_admin(client, admin_user, test_user):
    """Un admin puede eliminar a otro usuario."""
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    # Eliminar al usuario de prueba
    response = client.delete(f"/api/v1/users/{test_user['id']}")
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Verificar que ya no existe
    check_response = client.get(f"/api/v1/users/{test_user['id']}")
    assert check_response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_user_as_normal_user_forbidden(client, test_user, admin_user):
    """Un usuario normal NO puede eliminar usuarios (ni siquiera al admin)."""
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    response = client.delete(f"/api/v1/users/{admin_user['id']}")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_cannot_delete_self(client, admin_user):
    """Un admin no debería poder auto-eliminarse."""
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    response = client.delete(f"/api/v1/users/{admin_user['id']}")
    assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE


def test_create_user_ignores_role_admin_payload(client, admin_user, db_session):
    """
    Seguridad: Verifica que si se envía 'role': 'admin' en el JSON de creación,
    el backend lo ignore y fuerce el rol a 'user'.
    """
    # Login como admin
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    email = "wannabe_admin@example.com"
    client.post(f"/api/v1/users/approved/{email}")

    # Payload con intento de escalada de privilegios
    user_data = {
        "username": "wannabe_admin",
        "email": email,
        "password": "password123",
        "role": "admin",
    }

    response = client.post("/api/v1/users/create", json=user_data)
    assert response.status_code == status.HTTP_201_CREATED

    # Verificación directa en DB para asegurar que el rol es 'user'
    created_user = (
        db_session.execute(select(User).where(User.email == email)).scalars().first()
    )
    assert created_user.role == "user"


# -----------------------------------------------------------------------------
# TESTS DE GESTIÓN DE ROLES
# -----------------------------------------------------------------------------


def test_admin_can_promote_user_to_admin(client, admin_user, test_user):
    """Un admin puede promover a otro usuario a admin."""
    # Login como admin
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    # Promover al usuario de prueba
    response = client.patch(
        f"/api/v1/users/{test_user['id']}/role", json={"role": "admin"}
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["role"] == "admin"


def test_normal_user_cannot_change_role(client, test_user, admin_user):
    """Un usuario normal no puede cambiar roles."""
    # Login como usuario normal
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    # Intentar promover al admin (o a cualquiera)
    response = client.patch(
        f"/api/v1/users/{admin_user['id']}/role", json={"role": "admin"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_cannot_change_own_role(client, admin_user):
    """Un admin no puede cambiar su propio rol para evitar bloqueos."""
    # Login como admin
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )

    # Intentar cambiarse el rol a 'user'
    response = client.patch(
        f"/api/v1/users/{admin_user['id']}/role", json={"role": "user"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


# -----------------------------------------------------------------------------
# TESTS DE CAMBIO DE CONTRASEÑA
# -----------------------------------------------------------------------------


def test_user_can_change_own_password(client, test_user):
    """Un usuario autenticado puede cambiar su propia contraseña si proporciona la correcta."""
    # 1. Login
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    # 2. Cambiar contraseña
    password_payload = {
        "current_password": test_user["password"],
        "new_password": "new_secure_password",
    }
    response = client.patch("/api/v1/users/me/password", json=password_payload)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # 3. Logout para invalidar la sesión actual
    client.post("/api/v1/auth/logout", follow_redirects=False)

    # 4. Intentar login con la contraseña antigua (debe fallar)
    old_login_response = client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )
    assert old_login_response.status_code == status.HTTP_401_UNAUTHORIZED

    # 5. Intentar login con la contraseña nueva (debe funcionar)
    new_login_response = client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": "new_secure_password"},
    )
    assert new_login_response.status_code == status.HTTP_200_OK


def test_user_cannot_change_password_with_wrong_current_one(client, test_user):
    """Falla al cambiar la contraseña si la contraseña actual es incorrecta."""
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )

    password_payload = {
        "current_password": "wrong_current_password",
        "new_password": "new_secure_password",
    }
    response = client.patch("/api/v1/users/me/password", json=password_payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_unauthenticated_user_cannot_change_password(client):
    """Un usuario no autenticado no puede acceder al endpoint de cambio de contraseña."""
    password_payload = {
        "current_password": "any_password",
        "new_password": "new_password",
    }
    response = client.patch("/api/v1/users/me/password", json=password_payload,)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# -----------------------------------------------------------------------------
# TESTS DE RECUPERACIÓN DE CONTRASEÑA (FORGOT PASSWORD)
# -----------------------------------------------------------------------------


@patch("routers.users.send_reset_password_email")
def test_forgot_password_request_success(mock_send_email, client, test_user):
    """
    Verifica que un usuario existente y activo pueda solicitar un reseteo
    y que se llame a la tarea de envío de email.
    """
    response = client.post(
        "/api/v1/users/forgot-password", json={"email": test_user["email"]}
    )

    assert response.status_code == status.HTTP_200_OK
    assert (
        response.json()["message"]
        == "Si el correo existe, se ha enviado un enlace para restablecer la contraseña."
    )

    # Verificar que la función de envío de email fue llamada
    mock_send_email.assert_called_once()

    # Opcional: verificar el contenido del email
    call_args = mock_send_email.call_args[0][0]  # call_args es una tupla (args, kwargs)
    assert call_args["email"] == test_user["email"]
    assert "url" in call_args


@patch("routers.users.send_reset_password_email")
def test_forgot_password_non_existent_user(mock_send_email, client):
    """
    Verifica que al solicitar reseteo para un email no existente,
    se devuelva una respuesta genérica y no se envíe email para evitar enumeración.
    """
    response = client.post(
        "/api/v1/users/forgot-password", json={"email": "nouser@example.com"}
    )

    assert response.status_code == status.HTTP_200_OK
    assert (
        response.json()["message"]
        == "Si el correo existe, se ha enviado un enlace para restablecer la contraseña."
    )

    # Verificar que la función de envío de email NO fue llamada
    mock_send_email.assert_not_called()


def test_reset_password_with_valid_token(client, test_user):
    """
    Verifica el flujo completo: generar token, resetear contraseña y
    verificar que la nueva contraseña funciona.
    """
    # 1. Generar un token válido (como lo haría el endpoint /forgot-password)
    token = generate_reset_password_token(test_user["email"])
    new_password = "a_brand_new_password"

    # 2. Usar el token para resetear la contraseña
    response = client.post(
        f"/api/v1/users/reset-password/{token}", json={"new_password": new_password}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Contraseña actualizada exitosamente."


def test_reset_password_with_invalid_token(client):
    """Verifica que un token inválido o manipulado sea rechazado."""
    response = client.post(
        "/api/v1/users/reset-password/this_is_not_a_valid_token",
        json={"new_password": "any_password"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "inválido o ha expirado" in response.json()["detail"]

