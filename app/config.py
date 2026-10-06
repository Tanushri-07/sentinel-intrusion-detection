from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    BAN_THRESHOLD: int = 10
    WINDOW_SECONDS: int = 60
    BAN_DURATION_SECONDS: int = 300
    LOG_FILE_PATH: str = "portal_auth.log"
    DATABASE_URL: str = "sqlite:///./sentinel.db"
    ADMIN_API_KEY: str = "sentinel-admin-secret-key"
    AI_API_KEY: str = ""
    TRUST_PROXY: bool = False

settings = Settings()
