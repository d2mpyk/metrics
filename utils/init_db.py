from models.users import ApprovedUsers, User
from .database import SessionLocal
from utils.auth import hash_password
from utils.config import settings
import sys

def get_init_config():
    """Verifica si el archivo config esta ok"""
    # Verificación de seguridad
    SECRET_KEY = settings.SECRET_KEY.get_secret_value()
    SECRET_KEY_CHECK_MAIL = settings.SECRET_KEY_CHECK_MAIL.get_secret_value()
    SECURITY_PASSWD_SALT = settings.SECURITY_PASSWD_SALT.get_secret_value()
    if (SECRET_KEY is None 
        or not SECRET_KEY.strip() 
        or SECRET_KEY_CHECK_MAIL is None 
        or not SECRET_KEY_CHECK_MAIL.strip() 
        or SECURITY_PASSWD_SALT is None 
        or not SECURITY_PASSWD_SALT.strip()):
        print('='*60)
        print("❌ FATAL ERROR: Configuración de seguridad inválida.", file=sys.stderr)
        print("   La variables de AAA y de verificación de correo no están definidas.", file=sys.stderr)
        print('='*60)
        # Detiene la ejecución del script retornando un código de error (1)
        sys.exit(1)

    # Verificación de los datos del usuario Principal
    ADMIN = settings.ADMIN.get_secret_value()
    NAME = settings.NAME.get_secret_value()
    if (ADMIN is None 
        or not ADMIN.strip() 
        or NAME is None 
        or not NAME.strip()):
        print('='*60)
        print("❌ FATAL ERROR: Configuración de aplicación inválida.", file=sys.stderr)
        print("   La variable de entorno 'ADMIN' o 'NAME' no está definida.", file=sys.stderr)
        print('='*60)
        # Detiene la ejecución del script retornando un código de error (1)
        sys.exit(1)

    # Verificación de los datos del correo
    EMAIL_SERVER = settings.EMAIL_SERVER.get_secret_value()
    EMAIL_PORT = settings.EMAIL_PORT.get_secret_value()
    EMAIL_USER = settings.EMAIL_SERVER.get_secret_value()
    EMAIL_PASSWD = settings.EMAIL_PORT.get_secret_value()
    if (EMAIL_SERVER is None 
        or not EMAIL_SERVER.strip() 
        or EMAIL_PORT is None 
        or not EMAIL_PORT.strip() 
        or EMAIL_USER is None 
        or not EMAIL_USER.strip() 
        or EMAIL_PASSWD is None 
        or not EMAIL_PASSWD.strip()):
        print('='*60)
        print("❌ FATAL ERROR: Configuración de aplicación inválida.", file=sys.stderr)
        print("   Las variables de entorno de correo no están definida.", file=sys.stderr)
        print('='*60)
        # Detiene la ejecución del script retornando un código de error (1)
        sys.exit(1)


def init_approved_users():
    db = SessionLocal()
    try:
        user = db.query(ApprovedUsers).first()

        # Si no hay usuarios 
        if not user:
            # Primero lo agregamos a ApprovedUsers
            ADMIN = settings.ADMIN.get_secret_value()
            user = ApprovedUsers(email=ADMIN)
            db.add(user)
            db.commit()
            db.refresh(user)
            # Luego lo agregamos a Users
            NAME = settings.NAME.get_secret_value()
            user_admin = User(
                username=NAME,
                email=ADMIN,
                password_hash=hash_password("admin"),
                role="admin",
                is_active=True,
                image_file="dxtrthink.png",
            )
            db.add(user_admin)
            db.commit()
            db.refresh(user_admin)

    except Exception as e:
        print(f"Error: Inicializando DB: {e}, ", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()

    