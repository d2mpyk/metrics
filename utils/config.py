from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    ADMIN: SecretStr
    NAME: SecretStr
    SECRET_KEY: SecretStr
    ALGORITHM: SecretStr
    ACCESS_TOKEN_EXPIRE_MINUTES: SecretStr
    SECRET_KEY_CHECK_MAIL: SecretStr
    SECURITY_PASSWD_SALT: SecretStr
    DOMINIO: SecretStr
    EMAIL_SERVER: SecretStr
    EMAIL_PORT: SecretStr
    EMAIL_USER: SecretStr
    EMAIL_PASSWD: SecretStr


# Carga de variables de entorno
settings = Settings()
