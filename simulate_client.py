import time
import requests
import base64
import hashlib
import json
import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Configuración
BASE_URL = "http://localhost:8000"
AUTH_URL = f"{BASE_URL}/api/v1/auth"
METRICS_URL = f"{BASE_URL}/api/v1/clients/metrics"


def encrypt_payload(data: dict, secret_key: str) -> dict:
    """Encripta un diccionario usando AES-CBC y la secret_key."""
    # 1. Derivar clave (SHA256)
    key = hashlib.sha256(secret_key.encode()).digest()

    # 2. Generar IV (16 bytes para AES)
    iv = os.urandom(16)

    # 3. Configurar Cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 4. Padding (PKCS7)
    padder = padding.PKCS7(128).padder()
    json_data = json.dumps(data).encode("utf-8")
    padded_data = padder.update(json_data) + padder.finalize()

    # 5. Encriptar
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 4. Retornar en Base64
    return {
        "nonce": base64.b64encode(iv).decode("utf-8"),
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
    print(
        "\n[3] Iniciando envío continuo de métricas (Presiona Ctrl+C para detener)..."
    )
    headers = {"Authorization": f"Bearer {access_token}"}

    # Contadores acumulativos para la red, para que el servidor pueda calcular el delta
    total_sent = random.randint(1000, 5000)
    total_recv = random.randint(10000, 50000)

    try:
        while True:
            # Generar datos aleatorios
            total_sent += random.randint(1024, 51200)  # Añadir entre 1KB y 50KB
            total_recv += random.randint(10240, 204800)  # Añadir entre 10KB y 200KB

            metrics_data = {
                "cpu": round(random.uniform(5.0, 95.0), 2),
                "ram": round(random.uniform(20.0, 80.0), 2),
                "disk": round(random.uniform(10.0, 70.0), 2),
                "net_sent": total_sent,
                "net_recv": total_recv,
            }

            encrypted_payload = encrypt_payload(metrics_data, client_secret_key)

            try:
                resp = requests.post(
                    METRICS_URL, json=encrypted_payload, headers=headers
                )

                if resp.status_code == 201:
                    print(
                        f"[{time.strftime('%H:%M:%S')}] Métricas enviadas: CPU {metrics_data['cpu']}% | RAM {metrics_data['ram']}% | NET_SENT {total_sent // 1024}KB"
                    )
                else:
                    print(
                        f"\n[ERROR] Fallo al enviar métricas: {resp.status_code} - {resp.text}"
                    )
                    break
            except requests.exceptions.RequestException as e:
                print(f"\n[ERROR] Problema de conexión: {e}")
                break

            time.sleep(5)  # Intervalo de envío
    except KeyboardInterrupt:
        print("\n--- Simulación detenida por el usuario. ---")


if __name__ == "__main__":
    main()
