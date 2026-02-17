# s:\WISE\Management\SERVER\tests\conftest.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Importamos la app y utilidades necesarias
# Asegúrate de ejecutar pytest desde la carpeta raíz (s:\WISE\Management\SERVER)
from app.main import app
from utils.database import Base, get_db
from utils.auth import hash_password
from models.users import User, ApprovedUsers

# Usamos SQLite en memoria para pruebas rápidas y aisladas
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """
    Crea una base de datos nueva en memoria para cada test.
    Crea las tablas al inicio y las elimina al final.
    """
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """
    Cliente de prueba de FastAPI con la dependencia de DB sobrescrita
    para usar la sesión en memoria.
    """

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db_session):
    """
    Crea un usuario válido y aprobado en la DB para usar en los tests.
    """
    email = "test@example.com"
    password = "password123"
    username = "testuser"

    # 1. Requisito: El email debe estar en la tabla ApprovedUsers
    approved = ApprovedUsers(email=email)
    db_session.add(approved)

    # 2. Crear el usuario
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="user",
        is_active=True,  # Importante: debe estar activo para loguearse
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return {"email": email, "password": password, "username": username, "id": user.id}


@pytest.fixture
def admin_user(db_session):
    """Crea un usuario administrador para pruebas."""
    email = "admin@example.com"
    password = "adminpassword"
    username = "admin"

    # 1. Aprobar
    approved = ApprovedUsers(email=email)
    db_session.add(approved)

    # 2. Crear Admin
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return {"email": email, "password": password, "username": username, "id": user.id}


@pytest.fixture
def auth_client(client, test_user):
    """Cliente autenticado como usuario normal."""
    client.post(
        "/api/v1/auth/token",
        data={"username": test_user["email"], "password": test_user["password"]},
    )
    return client


@pytest.fixture
def admin_client(client, admin_user):
    """Cliente autenticado como administrador."""
    client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["email"], "password": admin_user["password"]},
    )
    return client
