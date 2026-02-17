import base64
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt_payload(nonce_b64: str, ciphertext_b64: str, secret_key: str) -> dict:
    """
    Desencripta un payload AES-GCM.
    Deriva una clave de 32 bytes usando SHA256 sobre la secret_key del cliente.
    """
    try:
        # 1. Derivar clave de 32 bytes (AES-256)
        key = hashlib.sha256(secret_key.encode()).digest()
        aesgcm = AESGCM(key)

        # 2. Decodificar Base64
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # 3. Desencriptar (Cryptography espera el tag al final del ciphertext, que es estándar)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Error de desencriptación: {str(e)}")
