from fastapi import status
from sqlalchemy import select
from models.users import User
from unittest.mock import patch
from utils.auth import generate_reset_password_token

# -----------------------------------------------------------------------------
# TESTS DE LECTURA (GET)
# -----------------------------------------------------------------------------


def test_get_users_as_admin(admin_client):
    """Un administrador debe poder ver la lista de usuarios (HTML)."""
    response = admin_client.get("/api/v1/users")
    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]
    assert "Lista de Usuarios" in response.text


def test_get_users_as_normal_user_forbidden(auth_client):
    """Un usuario normal NO debe poder ver la lista de usuarios."""
    response = auth_client.get("/api/v1/users")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_get_specific_user_as_admin(admin_client, test_user):
    """Un admin puede ver detalles de otro usuario por ID."""
    response = admin_client.get(f"/api/v1/users/{test_user['id']}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["email"] == test_user["email"]


# -----------------------------------------------------------------------------
# TESTS DE APROBACIÓN (POST)
# -----------------------------------------------------------------------------


def test_approve_user_as_admin(admin_client):
    """Un admin puede aprobar nuevos emails."""
    new_email = "new_friend@example.com"
    response = admin_client.post(f"/api/v1/users/approved/{new_email}")

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["email"] == new_email


def test_approve_user_as_normal_user_forbidden(auth_client):
    """Un usuario normal NO puede aprobar emails."""
    response = auth_client.post("/api/v1/users/approved/hacker@example.com")
    assert response.status_code == status.HTTP_403_FORBIDDEN


# -----------------------------------------------------------------------------
# TESTS DE CREACIÓN (POST)
# -----------------------------------------------------------------------------


def test_create_user_flow_as_admin(admin_client):
    """
    Prueba el flujo completo de creación por parte de un admin:
    1. Aprobar email
    2. Crear usuario (endpoint protegido para admins)
    """
    email_to_create = "employee@example.com"

    # 1. Aprobar
    admin_client.post(f"/api/v1/users/approved/{email_to_create}")

    # 2. Crear
    user_data = {
        "username": "employee",
        "email": email_to_create,
        "password": "securepassword",
    }
    response = admin_client.post("/api/v1/users/create", json=user_data)

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == email_to_create
    assert data["is_active"] is False  # Se crea inactivo hasta verificar email


def test_create_user_as_normal_user_forbidden(auth_client):
    """Un usuario normal no puede crear otros usuarios."""
    user_data = {
        "username": "intruder",
        "email": "intruder@example.com",
        "password": "password",
    }
    response = auth_client.post("/api/v1/users/create", json=user_data)
    assert response.status_code == status.HTTP_403_FORBIDDEN


# -----------------------------------------------------------------------------
# TESTS DE ELIMINACIÓN (DELETE)
# -----------------------------------------------------------------------------


def test_delete_user_as_admin(admin_client, test_user):
    """Un admin puede eliminar a otro usuario."""
    # Eliminar al usuario de prueba
    response = admin_client.delete(f"/api/v1/users/{test_user['id']}")
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Verificar que ya no existe
    check_response = admin_client.get(f"/api/v1/users/{test_user['id']}")
    assert check_response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_user_as_normal_user_forbidden(auth_client, admin_user):
    """Un usuario normal NO puede eliminar usuarios (ni siquiera al admin)."""
    response = auth_client.delete(f"/api/v1/users/{admin_user['id']}")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_cannot_delete_self(admin_client, admin_user):
    """Un admin no debería poder auto-eliminarse."""
    response = admin_client.delete(f"/api/v1/users/{admin_user['id']}")
    assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE


def test_create_user_ignores_role_admin_payload(admin_client, db_session):
    """
    Seguridad: Verifica que si se envía 'role': 'admin' en el JSON de creación,
    el backend lo ignore y fuerce el rol a 'user'.
    """
    email = "wannabe_admin@example.com"
    admin_client.post(f"/api/v1/users/approved/{email}")

    # Payload con intento de escalada de privilegios
    user_data = {
        "username": "wannabe_admin",
        "email": email,
        "password": "password123",
        "role": "admin",
    }

    response = admin_client.post("/api/v1/users/create", json=user_data)
    assert response.status_code == status.HTTP_201_CREATED

    # Verificación directa en DB para asegurar que el rol es 'user'
    created_user = (
        db_session.execute(select(User).where(User.email == email)).scalars().first()
    )
    assert created_user.role == "user"


# -----------------------------------------------------------------------------
# TESTS DE GESTIÓN DE ROLES
# -----------------------------------------------------------------------------


def test_admin_can_promote_user_to_admin(admin_client, test_user):
    """Un admin puede promover a otro usuario a admin."""
    # Promover al usuario de prueba
    response = admin_client.patch(
        f"/api/v1/users/{test_user['id']}/role", json={"role": "admin"}
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["role"] == "admin"


def test_normal_user_cannot_change_role(auth_client, admin_user):
    """Un usuario normal no puede cambiar roles."""
    # Intentar promover al admin (o a cualquiera)
    response = auth_client.patch(
        f"/api/v1/users/{admin_user['id']}/role", json={"role": "admin"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_admin_cannot_change_own_role(admin_client, admin_user):
    """Un admin no puede cambiar su propio rol para evitar bloqueos."""
    # Intentar cambiarse el rol a 'user'
    response = admin_client.patch(
        f"/api/v1/users/{admin_user['id']}/role", json={"role": "user"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


# -----------------------------------------------------------------------------
# TESTS DE ACTUALIZACIÓN (PATCH)
# -----------------------------------------------------------------------------


def test_admin_can_update_user_details(admin_client, test_user, db_session):
    """Un admin puede editar los detalles de otro usuario."""
    update_payload = {"username": "updated_username"}
    response = admin_client.patch(
        f"/api/v1/users/{test_user['id']}", json=update_payload
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["username"] == "updated_username"

    # Verificar en la DB
    db_session.expire_all()  # Para obtener datos frescos de la DB
    updated_user = db_session.get(User, test_user["id"])
    assert updated_user.username == "updated_username"


def test_normal_user_cannot_update_other_user_details(auth_client, admin_user):
    """Un usuario normal NO puede editar los detalles de otro usuario."""
    update_payload = {"username": "hacked_username"}
    response = auth_client.patch(
        f"/api/v1/users/{admin_user['id']}", json=update_payload
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_normal_user_cannot_update_self_via_admin_endpoint(auth_client, test_user):
    """Un usuario normal NO puede usar el endpoint de admin para editarse a sí mismo."""
    update_payload = {"username": "new_self_username"}
    response = auth_client.patch(
        f"/api/v1/users/{test_user['id']}", json=update_payload
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


# -----------------------------------------------------------------------------
# TESTS DE ACTUALIZACIÓN DE PERFIL (/me)
# -----------------------------------------------------------------------------


def test_user_can_update_own_profile(auth_client, test_user, db_session):
    """Un usuario puede actualizar su propio username y image_file."""
    # 1. Update profile
    # Usamos 'data' para campos de formulario y 'files' para subida de archivos
    data_payload = {"username": "new_test_username"}
    # Simulamos un archivo de imagen
    files_payload = {"image_file": ("avatar.png", b"fake image content", "image/png")}

    response = auth_client.patch(
        "/api/v1/users/me", data=data_payload, files=files_payload
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "new_test_username"
    assert data["image_file"] is not None
    assert data["image_file"] != "avatar.png"  # Debe ser diferente por el UUID

    # 3. Verify in DB
    db_session.expire_all()
    updated_user = db_session.get(User, test_user["id"])
    assert updated_user.username == "new_test_username"
    assert updated_user.image_file == data["image_file"]


def test_user_cannot_update_profile_with_existing_username(auth_client, admin_user):
    """Un usuario no puede tomar un username que ya está en uso por otro."""
    # Attempt to update with admin's username
    update_payload = {"username": admin_user["username"]}
    response = auth_client.patch("/api/v1/users/me", data=update_payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "nombre de usuario ya está registrado" in response.json()["detail"]


def test_update_profile_with_invalid_image_type(auth_client):
    """Verifica que se rechace un archivo que no es una imagen."""
    files_payload = {"image_file": ("test.txt", b"some text", "text/plain")}
    response = auth_client.patch("/api/v1/users/me", files=files_payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Tipo de archivo no válido" in response.json()["detail"]


def test_update_profile_with_image_too_large(auth_client):
    """Verifica que se rechace una imagen que excede el tamaño máximo."""
    # Crear un archivo falso de > 2 MB
    large_content = b"a" * (2 * 1024 * 1024 + 1)
    files_payload = {"image_file": ("large_image.png", large_content, "image/png")}
    response = auth_client.patch("/api/v1/users/me", files=files_payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "archivo es demasiado grande" in response.json()["detail"]


def test_user_cannot_update_unsupported_fields_via_me_endpoint(auth_client):
    """
    Verifica que campos no permitidos (como 'role') sean ignorados silenciosamente
    cuando se envían junto con datos válidos.
    """
    # Enviamos un campo válido (username) y uno protegido (role)
    response = auth_client.patch(
        "/api/v1/users/me", data={"username": "safe_user", "role": "admin"}
    )

    # FastAPI ignora los campos extra del Form, devolviendo 200 OK
    assert response.status_code == status.HTTP_200_OK

    # Verificamos que el rol NO haya cambiado (la inyección falló)
    assert response.json()["role"] != "admin"


# -----------------------------------------------------------------------------
# TESTS DE CAMBIO DE CONTRASEÑA
# -----------------------------------------------------------------------------


def test_user_can_change_own_password(auth_client, test_user):
    """Un usuario autenticado puede cambiar su propia contraseña si proporciona la correcta."""
    # 1. Cambiar contraseña
    password_payload = {
        "current_password": test_user["password"],
        "new_password": "new_secure_password",
    }
    response = auth_client.patch("/api/v1/users/me/password", json=password_payload)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # 2. Logout para invalidar la sesión actual
    auth_client.post("/api/v1/auth/logout", follow_redirects=False)

    # 3. Intentar login con la contraseña antigua (debe fallar)
    old_login_response = auth_client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )
    assert old_login_response.status_code == status.HTTP_401_UNAUTHORIZED

    # 4. Intentar login con la contraseña nueva (debe funcionar)
    new_login_response = auth_client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": "new_secure_password"},
    )
    assert new_login_response.status_code == status.HTTP_200_OK


def test_user_cannot_change_password_with_wrong_current_one(auth_client):
    """Falla al cambiar la contraseña si la contraseña actual es incorrecta."""
    password_payload = {
        "current_password": "wrong_current_password",
        "new_password": "new_secure_password",
    }
    response = auth_client.patch("/api/v1/users/me/password", json=password_payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_unauthenticated_user_cannot_change_password(client):
    """Un usuario no autenticado no puede acceder al endpoint de cambio de contraseña."""
    password_payload = {
        "current_password": "any_password",
        "new_password": "new_password",
    }
    response = client.patch(
        "/api/v1/users/me/password",
        json=password_payload,
    )
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
