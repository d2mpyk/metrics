import base64, hashlib, json, jwt, os, pytest, time, secrets
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from fastapi import status
from sqlalchemy import select
from models.clients import Client, ServerMetric, ApprovedClient, DeviceCode
from utils.auth import create_access_token
from utils.crypto import decrypt_payload
from utils.config import get_settings
from datetime import datetime, timedelta, timezone


# -----------------------------------------------------------------------------
# UTILIDADES DE PRUEBA
# -----------------------------------------------------------------------------


def encrypt_helper(data: dict, secret_key: str) -> dict:
    """Helper para encriptar datos en los tests (misma lógica que el cliente)."""
    key = hashlib.sha256(secret_key.encode()).digest()
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    json_data = json.dumps(data).encode("utf-8")
    padded_data = padder.update(json_data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        "nonce": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


# -----------------------------------------------------------------------------
# TESTS DE CRIPTOGRAFÍA
# -----------------------------------------------------------------------------


def test_decrypt_payload_success():
    """Verifica que se pueda desencriptar un payload válido."""
    secret = "my_super_secret_key_123"
    data = {"cpu": 10.5, "ram": 50.0}

    encrypted = encrypt_helper(data, secret)

    decrypted = decrypt_payload(encrypted["nonce"], encrypted["ciphertext"], secret)
    assert decrypted == data


def test_decrypt_payload_wrong_key():
    """Verifica que falle si la clave es incorrecta."""
    secret = "key_A"
    wrong_secret = "key_B"
    data = {"msg": "hello"}

    encrypted = encrypt_helper(data, secret)

    with pytest.raises(ValueError, match="Error de desencriptación"):
        decrypt_payload(encrypted["nonce"], encrypted["ciphertext"], wrong_secret)


# -----------------------------------------------------------------------------
# TESTS DE ENDPOINT DE MÉTRICAS
# -----------------------------------------------------------------------------


def test_receive_metrics_and_delta_calculation(client, db_session):
    """Prueba el envío de métricas y la correcta calculación de la velocidad de red (delta)."""
    # 1. Crear un cliente en la DB
    secret_key = "device_secret_key"
    test_client = Client(
        client_identifier="device-001",
        client_secret_key=secret_key,
        ip_address="127.0.0.1",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(test_client)
    db_session.commit()
    db_session.refresh(test_client)

    # 2. Generar Token JWT para el dispositivo
    token = create_access_token(
        data={
            "sub": test_client.client_identifier,
            "role": "device",
            "client_id": test_client.id,
        }
    )

    # 3. Enviar la primera métrica
    metrics_data_1 = {
        "cpu": 10.0,
        "ram": 20.0,
        "disk": 5.0,
        "net_sent": 10240,  # 10 KB
        "net_recv": 20480,  # 20 KB
    }
    payload_1 = encrypt_helper(metrics_data_1, secret_key)
    response_1 = client.post(
        "/api/v1/clients/metrics",
        json=payload_1,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response_1.status_code == status.HTTP_201_CREATED

    # Verificar la primera métrica en la DB (la velocidad debe ser 0)
    metric_1 = db_session.execute(
        select(ServerMetric).where(ServerMetric.client_id == test_client.id)
    ).scalar_one()
    assert metric_1.net_sent == 10240
    assert metric_1.net_speed_sent == 0.0
    assert metric_1.net_speed_recv == 0.0

    # Esperar para simular un intervalo de tiempo
    time.sleep(1.1)

    # 4. Enviar la segunda métrica
    metrics_data_2 = {
        "cpu": 15.0,
        "ram": 25.0,
        "disk": 6.0,
        "net_sent": 20480,  # +10 KB
        "net_recv": 40960,  # +20 KB
    }
    payload_2 = encrypt_helper(metrics_data_2, secret_key)
    response_2 = client.post(
        "/api/v1/clients/metrics",
        json=payload_2,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response_2.status_code == status.HTTP_201_CREATED

    # 5. Verificar la segunda métrica en la DB
    metric_2 = db_session.get(ServerMetric, metric_1.id + 1)
    assert metric_2.net_sent == 20480

    time_delta = (metric_2.timestamp - metric_1.timestamp).total_seconds()
    expected_speed_sent = (20480 - 10240) / time_delta  # Bytes/sec
    expected_speed_recv = (40960 - 20480) / time_delta  # Bytes/sec

    assert metric_2.net_speed_sent == pytest.approx(expected_speed_sent, rel=1e-2)
    assert metric_2.net_speed_recv == pytest.approx(expected_speed_recv, rel=1e-2)


def test_receive_metrics_with_expired_token_manual_check(client, db_session):
    """
    Verifica que la validación manual de expiración rechace tokens vencidos
    (ej. del año pasado), confirmando que la lógica de comparación de fechas funciona.
    """
    # 1. Crear cliente
    secret_key = "expired_key"
    new_client = Client(
        client_identifier="device-expired",
        client_secret_key=secret_key,
        ip_address="127.0.0.1",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(new_client)
    db_session.commit()

    # 2. Generar Token con expiración en el pasado (hace 1 año)
    token = create_access_token(
        data={
            "sub": new_client.client_identifier,
            "role": "device",
            "client_id": new_client.id,
        },
        expires_delta=timedelta(days=-365),
    )

    # 3. Enviar Request con payload válido pero token expirado
    payload = encrypt_helper({"cpu": 1}, secret_key)
    response = client.post(
        "/api/v1/clients/metrics",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_full_device_flow_integration(client, admin_user):
    """
    Simula el flujo completo:
    1. Admin aprueba IP.
    2. Dispositivo solicita código.
    3. Admin autoriza dispositivo.
    4. Dispositivo obtiene token.
    5. Dispositivo envía métricas.
    """
    # 1. Login Admin
    login_payload = {
        "username": admin_user["email"],
        "password": admin_user["password"],
    }
    resp_login = client.post("/api/v1/auth/token", data=login_payload)
    assert resp_login.status_code == status.HTTP_200_OK

    # 2. Aprobar IP (TestClient usa 'testclient' como host por defecto)
    approved_payload = {
        "ip_address": "testclient",
        "description": "Integration Test Device",
    }
    # Con el patrón PRG, enviamos datos de formulario y esperamos una redirección.
    resp_approve = client.post(
        "/api/v1/clients/approved", data=approved_payload, follow_redirects=False
    )
    assert resp_approve.status_code == status.HTTP_303_SEE_OTHER
    assert resp_approve.headers["location"].endswith("/metrics/api/v1/clients/approved")
    # Verificar que se estableció el mensaje flash
    assert "flash_message" in resp_approve.cookies

    # 3. Dispositivo solicita código (Simulamos ser dispositivo limpiando cookies)
    client.cookies.clear()

    resp_code = client.post("/api/v1/auth/device/code")
    assert resp_code.status_code == status.HTTP_200_OK
    device_data = resp_code.json()
    device_code = device_data["device_code"]
    user_code = device_data["user_code"]

    # 4. Admin autoriza dispositivo
    # Nos logueamos de nuevo como admin
    client.post("/api/v1/auth/token", data=login_payload)

    resp_activate = client.post(
        "/api/v1/auth/device/activate",
        data={"user_code": user_code},
        follow_redirects=False,
    )
    assert resp_activate.status_code == status.HTTP_303_SEE_OTHER
    assert (
        resp_activate.headers["location"]
        == "http://testserver/metrics/api/v1/dashboard/"
    )
    # Verificar cookies flash
    assert "flash_message" in resp_activate.cookies

    # 5. Dispositivo obtiene token (Polling)
    client.cookies.clear()

    resp_token = client.post(
        "/api/v1/auth/device/token",
        data={
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    assert resp_token.status_code == status.HTTP_200_OK
    token_data = resp_token.json()
    access_token = token_data["access_token"]
    client_secret_key = token_data["client_secret_key"]

    # 6. Enviar Métricas
    metrics_data = {
        "cpu": 12.3,
        "ram": 45.6,
        "disk": 78.9,
        "net_sent": 0,
        "net_recv": 0,
    }
    encrypted_payload = encrypt_helper(metrics_data, client_secret_key)

    resp_metrics = client.post(
        "/api/v1/clients/metrics",
        json=encrypted_payload,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp_metrics.status_code == status.HTTP_201_CREATED


def test_get_approved_clients_as_normal_user_forbidden(auth_client):
    """Un usuario no-administrador no puede ver la lista de clientes aprobados."""
    response = auth_client.get("/api/v1/clients/approved")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_get_clients_dashboard_as_admin(admin_client, db_session):
    """Un admin puede ver el dashboard de clientes (HTML)."""
    # 1. Crear un cliente de prueba
    db_session.add(
        Client(
            client_identifier="device-test-html",
            client_secret_key="secret",
            ip_address="192.168.1.100",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
    )
    db_session.commit()

    # 2. Solicitar página
    response = admin_client.get("/api/v1/clients")
    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]
    assert "device-test-html" in response.text


def test_create_duplicate_approved_client_fails(admin_client, db_session):
    """
    Verifica que al intentar agregar una IP ya aprobada, se reciba un
    mensaje flash de error y se redirija correctamente.
    """
    ip = "192.168.1.111"
    # 1. Agregar la IP una vez
    db_session.add(ApprovedClient(ip_address=ip, description="First time"))
    db_session.commit()

    # 2. Intentar agregarla de nuevo
    response = admin_client.post(
        "/api/v1/clients/approved",
        data={"ip_address": ip, "description": "Second time"},
        follow_redirects=False,
    )

    # 3. Verificar redirección y cookie flash de error
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].endswith("/metrics/api/v1/clients/approved")
    assert "flash_message" in response.cookies
    assert response.cookies["flash_type"] == "red"
    assert "ya se encuentra aprobada" in response.cookies["flash_message"]


def test_get_approved_clients_shows_pending_codes(admin_client, db_session):
    """
    Verifica que la vista de IPs aprobadas muestre los códigos de usuario
    pendientes de activación si un dispositivo ha iniciado el proceso.
    """
    # 1. Aprobar una IP y simular que un dispositivo ha solicitado un código
    ip = "192.168.1.123"
    user_code = "C0D3T3ST"
    db_session.add(ApprovedClient(ip_address=ip, description="Device with code"))
    db_session.add(
        DeviceCode(
            device_code=secrets.token_urlsafe(16),
            user_code=user_code,
            ip_address=ip,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            is_verified=False,
        )
    )
    db_session.commit()

    # 2. Obtener la vista de clientes aprobados y verificar que el código aparece
    response = admin_client.get("/api/v1/clients/approved")
    assert response.status_code == status.HTTP_200_OK
    assert user_code in response.text
    assert "Activar" in response.text


def test_get_clients_as_normal_user_is_forbidden(auth_client):
    """Un usuario normal no puede acceder a la lista de clientes."""
    response = auth_client.get("/api/v1/clients")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_renew_token_grace_period_integration(client, db_session):
    """
    Simula que estamos a 2 de Enero y un dispositivo intenta renovar
    un token que venció el 31 de Diciembre del año anterior.
    """
    # 1. Setup: Crear cliente
    secret_key = "device_secret_key"
    new_client = Client(
        client_identifier="device-renewal",
        client_secret_key=secret_key,
        ip_address="127.0.0.1",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(new_client)
    db_session.commit()

    # 2. Preparar fechas simuladas (2 Ene Año Y, Expira 31 Dic Año Y-1)
    mock_now = datetime(2025, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    exp_date = datetime(2024, 12, 31, 23, 59, 0, tzinfo=timezone.utc)

    # 3. Generar token expirado manualmente
    settings = get_settings()
    token_data = {
        "sub": new_client.client_identifier,
        "type": "client",
        "role": "device",
        "client_id": new_client.id,
        "exp": exp_date,
        "iat": exp_date - timedelta(days=1),
    }
    expired_token = jwt.encode(
        token_data,
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM.get_secret_value(),
    )

    # 4. Mockear datetime en routers.clients
    with patch("routers.clients.datetime") as mock_dt:
        mock_dt.now.return_value = mock_now
        # Importante: fromtimestamp debe funcionar realmente para validar el año del token
        mock_dt.fromtimestamp.side_effect = datetime.fromtimestamp

        # 5. Llamar al endpoint
        response = client.post(
            "/api/v1/clients/renew-token",
            headers={"Authorization": f"Bearer {expired_token}"},
        )

    # 6. Verificar
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_renew_token_outside_grace_period_fails(client, db_session):
    """
    Verifica que la renovación falle si se intenta fuera del periodo de gracia
    (ej. 6 de Enero).
    """
    # 1. Setup: Crear cliente
    secret_key = "device_secret_key_fail"
    new_client = Client(
        client_identifier="device-renewal-fail",
        client_secret_key=secret_key,
        ip_address="127.0.0.1",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(new_client)
    db_session.commit()

    # 2. Preparar fechas simuladas (6 Ene Año Y, Expira 31 Dic Año Y-1)
    mock_now = datetime(2025, 1, 6, 12, 0, 0, tzinfo=timezone.utc)
    exp_date = datetime(2024, 12, 31, 23, 59, 0, tzinfo=timezone.utc)

    # 3. Generar token expirado manualmente
    settings = get_settings()
    token_data = {
        "sub": new_client.client_identifier,
        "type": "client",
        "role": "device",
        "client_id": new_client.id,
        "exp": exp_date,
        "iat": exp_date - timedelta(days=1),
    }
    expired_token = jwt.encode(
        token_data,
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM.get_secret_value(),
    )

    # 4. Mockear datetime en routers.clients
    with patch("routers.clients.datetime") as mock_dt:
        mock_dt.now.return_value = mock_now
        # Importante: fromtimestamp debe funcionar realmente para validar el año del token
        mock_dt.fromtimestamp.side_effect = datetime.fromtimestamp

        # 5. Llamar al endpoint
        response = client.post(
            "/api/v1/clients/renew-token",
            headers={"Authorization": f"Bearer {expired_token}"},
        )

    # 6. Verificar rechazo
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "periodo de gracia" in response.json()["detail"]


def test_client_description_auto_update(client, db_session):
    """
    Verifica que si un cliente tiene descripción vacía, se actualice
    automáticamente desde ApprovedClient al autenticarse (get_current_client).
    """
    # 1. Crear ApprovedClient con descripción
    ip = "192.168.1.50"
    desc = "Auto Description"
    approved = ApprovedClient(ip_address=ip, description=desc)
    db_session.add(approved)

    # 2. Crear Client con descripción vacía
    secret_key = "secret"
    test_client = Client(
        client_identifier="device-no-desc",
        client_secret_key=secret_key,
        ip_address=ip,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        description=None,  # Vacía
    )
    db_session.add(test_client)
    db_session.commit()

    # 3. Generar Token
    token = create_access_token(
        data={
            "sub": test_client.client_identifier,
            "role": "device",
            "client_id": test_client.id,
        }
    )

    # 4. Hacer request a endpoint protegido (ej: metrics) para disparar get_current_client
    # Usamos un payload válido para que pase la validación de métricas
    metrics_data = {"cpu": 10.0, "ram": 20.0, "disk": 5.0, "net_sent": 0, "net_recv": 0}
    payload = encrypt_helper(metrics_data, secret_key)

    response = client.post(
        "/api/v1/clients/metrics",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == status.HTTP_201_CREATED

    # 5. Verificar que la descripción se actualizó en DB
    db_session.refresh(test_client)
    assert test_client.description == desc


def test_update_client_description_manually_redirects(admin_client, db_session):
    """
    Verifica que el endpoint de actualización manual de descripción
    funciona, actualiza la DB y redirige correctamente.
    """
    # 1. Crear un cliente de prueba en la DB
    client_to_update = Client(
        client_identifier="device-to-update",
        client_secret_key="secret",
        ip_address="192.168.1.200",
        is_active=True,
        created_at=datetime.now(timezone.utc),
        description="Old Description",
    )
    db_session.add(client_to_update)
    db_session.commit()

    # 2. Realizar la petición POST para actualizar
    new_description = "New Manual Description"
    response = admin_client.post(
        f"/api/v1/clients/{client_to_update.id}/update",
        data={"description": new_description},
        follow_redirects=False,  # No seguir la redirección para poder inspeccionarla
    )

    # 3. Verificar la redirección
    assert response.status_code == status.HTTP_303_SEE_OTHER
    # La URL de redirección debe apuntar a la vista de detalles del cliente
    assert response.headers["location"].endswith(
        f"/metrics/api/v1/clients/{client_to_update.id}"
    )

    # 4. Verificar que el dato se actualizó en la base de datos
    db_session.refresh(client_to_update)
    assert client_to_update.description == new_description


def test_get_all_clients_attaches_latest_metric(admin_client, db_session):
    """
    Verifica que el dashboard de clientes muestre la métrica más reciente
    para cada dispositivo en las tarjetas.
    """
    # 1. Crear Cliente
    client_obj = Client(
        client_identifier="metric-test-device",
        client_secret_key="secret",
        ip_address="10.0.0.2",
        is_active=True,
        created_at=datetime.now(timezone.utc),
        description="Metric Test",
    )
    db_session.add(client_obj)
    db_session.commit()

    # 2. Insertar métrica antigua (hace 10 min)
    old_metric = ServerMetric(
        client_id=client_obj.id,
        cpu_usage=11.1,
        ram_usage=11.1,
        disk_usage=11.1,
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        net_sent=0,
        net_recv=0,
    )
    db_session.add(old_metric)

    # 3. Insertar métrica nueva (ahora)
    new_metric = ServerMetric(
        client_id=client_obj.id,
        cpu_usage=99.9,
        ram_usage=88.8,
        disk_usage=77.7,
        timestamp=datetime.now(timezone.utc),
        net_sent=0,
        net_recv=0,
    )
    db_session.add(new_metric)
    db_session.commit()

    # 4. Consultar Dashboard
    response = admin_client.get("/api/v1/clients")
    assert response.status_code == status.HTTP_200_OK

    # 5. Verificar que los valores nuevos aparecen en el HTML
    # El template usa "%.1f"|format(metric.cpu_usage) -> "99.9%"
    assert "99.9%" in response.text
    assert "88.8%" in response.text

    # Verificar que NO aparece la vieja (11.1%)
    assert "11.1%" not in response.text
