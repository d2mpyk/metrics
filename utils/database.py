from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import get_settings

settings = get_settings()

# Configuración de la DB SQLite
# SQLALCHEMY_DATABASE_URL = "sqlite:///utils/template.db"

# Engine Connection para SQLite
#engine = create_engine(
#    SQLALCHEMY_DATABASE_URL,
#    connect_args={"check_same_thread": False},
#)

# Configuración de la DB MariaDB, MySQL
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{settings.DB_USER.get_secret_value()}:{settings.DB_PASSWORD.get_secret_value()}@{settings.DB_HOST.get_secret_value()}:{settings.DB_PORT}/{settings.DB_NAME.get_secret_value()}"

# Engine Connection para MariaDB
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True, # Recomendado para MySQL para manejar desconexiones
    pool_recycle=3600   # Reciclar conexiones cada hora
)

# Sesiones de acceso a la DB
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    with SessionLocal() as db:
        try:
            yield db
        finally:
            db.close()