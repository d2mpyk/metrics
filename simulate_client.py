import time
import requests
import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuración
BASE_URL = "http://localhost:8000"
AUTH_URL = f"{BASE_URL}/api/v1/auth"
METRICS_URL = f"{BASE_URL}/api/v1/clients/metrics"


def encrypt_payload(data: dict, secret_key: str) -> dict:
    """Encripta un diccionario usando AES-GCM y la secret_key."""
    # 1. Derivar clave (SHA256)
    key = hashlib.sha256(secret_key.encode()).digest()
    aesgcm = AESGCM(key)

    # 2. Generar Nonce (12 bytes)
    nonce = os.urandom(12)

    # 3. Encriptar
    json_data = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, json_data, None)

    # 4. Retornar en Base64
    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def main():
    print("--- Iniciando Simulación de Cliente (Device Flow) ---")

    # 1. Solicitar Código
    print(f"[1] Solicitando código de dispositivo a {AUTH_URL}/device/code...")
    try:
        resp = requests.post(f"{AUTH_URL}/device/code")
        resp.raise_for_status()
        device_data = resp.json()
    except Exception as e:
        print(f"Error conectando al servidor: {e}")
        return

    device_code = device_data["device_code"]
    user_code = device_data["user_code"]
    verification_uri = device_data["verification_uri"]
    interval = device_data.get("interval", 5)

    print("\n" + "=" * 60)
    print(f"POR FAVOR AUTORIZA ESTE DISPOSITIVO:")
    print(f"1. Ve a: {verification_uri}")
    print(f"2. Ingresa el código: {user_code}")
    print("=" * 60 + "\n")

    # 2. Polling por el Token
    print(f"[2] Esperando autorización (Polling cada {interval}s)...")
    access_token = None
    client_secret_key = None

    while not access_token:
        time.sleep(interval)
        resp = requests.post(
            f"{AUTH_URL}/device/token",
            data={
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )

        if resp.status_code == 200:
            token_data = resp.json()
            access_token = token_data["access_token"]
            client_secret_key = token_data["client_secret_key"]
            print("\n[SUCCESS] ¡Dispositivo Autorizado!")
            print(f"Token recibido: {access_token[:10]}...")
            print(f"Secret Key recibida: {client_secret_key[:10]}...")
        elif resp.status_code == 400:
            error = resp.json().get("detail")
            if error == "authorization_pending":
                print(".", end="", flush=True)
            elif error == "slow_down":
                interval += 2
                print(f"(Slow down, new interval: {interval})", end="", flush=True)
            elif error == "expired_token":
                print("\n[ERROR] El código expiró. Reinicia el script.")
                return
            else:
                print(f"\n[ERROR] {error}")
                return
        else:
            print(f"\n[ERROR] Status {resp.status_code}: {resp.text}")
            return

    # 3. Enviar Métricas
    print("\n[3] Generando y enviando métricas encriptadas...")
    metrics_data = {"cpu": 45.5, "ram": 60.2, "disk": 30.1}
    print(f"Datos originales: {metrics_data}")

    encrypted_payload = encrypt_payload(metrics_data, client_secret_key)
    print(f"Payload encriptado: {encrypted_payload}")

    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.post(METRICS_URL, json=encrypted_payload, headers=headers)

    if resp.status_code == 201:
        print("[SUCCESS] Métricas enviadas y guardadas correctamente.")
    else:
        print(f"[ERROR] Fallo al enviar métricas: {resp.status_code} - {resp.text}")


if __name__ == "__main__":
    main()
