from slowapi import Limiter
from slowapi.util import get_remote_address

# Crea una instancia del limiter que usa la IP del cliente como clave.
limiter = Limiter(key_func=get_remote_address)