import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    json_data = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, json_data, None)
    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
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
