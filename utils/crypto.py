import base64
import hashlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def decrypt_payload(nonce_b64: str, ciphertext_b64: str, secret_key: str) -> dict:
    """
    Desencripta un payload AES-CBC.
    Deriva una clave de 32 bytes usando SHA256 sobre la secret_key del cliente.
    """
    try:
        # 1. Derivar clave de 32 bytes (AES-256)
        key = hashlib.sha256(secret_key.encode()).digest()

        # 2. Decodificar Base64
        iv = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # 3. Configurar Cipher (AES en modo CBC)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # 4. Desencriptar
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # 5. Remover Padding (PKCS7)
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Error de desencriptación: {str(e)}")
