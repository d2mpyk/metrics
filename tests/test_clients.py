import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from fastapi import status
from sqlalchemy import select
from models.clients import Client, ServerMetric
from utils.auth import create_access_token
from utils.crypto import decrypt_payload
import pytest
from datetime import timedelta


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


def test_receive_metrics_success(client, db_session):
    """Prueba el flujo completo de envío de métricas."""
    # 1. Crear un cliente en la DB
    secret_key = "device_secret_key"
    new_client = Client(
        client_identifier="device-001",
        client_secret_key=secret_key,
        ip_address="127.0.0.1",
        is_active=True,
    )
    db_session.add(new_client)
    db_session.commit()
    db_session.refresh(new_client)

    # 2. Generar Token JWT para el dispositivo
    token = create_access_token(
        data={
            "sub": new_client.client_identifier,
            "role": "device",
            "client_id": new_client.id,
        }
    )

    # 3. Preparar Payload Encriptado
    metrics_data = {"cpu": 55.5, "ram": 40.0, "disk": 10.0}
    payload = encrypt_helper(metrics_data, secret_key)

    # 4. Enviar Request
    response = client.post(
        "/api/v1/clients/metrics",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() == {"status": "ok"}

    # 5. Verificar en DB
    metric = (
        db_session.execute(
            select(ServerMetric).where(ServerMetric.client_id == new_client.id)
        )
        .scalars()
        .first()
    )

    assert metric is not None
    assert metric.cpu_usage == 55.5


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
    resp_approve = client.post("/api/v1/clients/approved", json=approved_payload)
    assert resp_approve.status_code == status.HTTP_201_CREATED

    # Verificar que la respuesta no incluye id ni created_at
    data_approve = resp_approve.json()
    assert "id" not in data_approve
    assert "created_at" not in data_approve
    assert data_approve["ip_address"] == "testclient"

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
        "/api/v1/auth/device/activate", data={"user_code": user_code}
    )
    assert resp_activate.status_code == status.HTTP_200_OK

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
    metrics_data = {"cpu": 12.3, "ram": 45.6, "disk": 78.9}
    encrypted_payload = encrypt_helper(metrics_data, client_secret_key)

    resp_metrics = client.post(
        "/api/v1/clients/metrics",
        json=encrypted_payload,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp_metrics.status_code == status.HTTP_201_CREATED
