"""
Base configuration for the project.

Loads settings from environment variables with fallback defaults.
SECURITY: Override all sensitive defaults in production via .env file.
"""
from pydantic_settings import BaseSettings
from typing import List
import json


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    All sensitive values (DATABASE_URL, SECRET_KEY) MUST be overridden
    in production using a .env file or environment variables.
    """

    # Project Info
    PROJECT_NAME: str = "NGcorion"
    VERSION: str = "1.0.8"
    DESCRIPTION: str = "Network Monitoring and Asset Management System"

    # Database
    # WARNING: Default credentials for development only!
    # Set DATABASE_URL in .env file for production
    DATABASE_URL: str = "postgresql://netease:1234@localhost/netease_db"

    # Security
    # WARNING: This default SECRET_KEY is INSECURE!
    # Generate a secure key with: openssl rand -hex 32
    # Set SECRET_KEY in .env file for production
    SECRET_KEY: str = "your-secret-key-here-change-in-production-min-32-chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120

    # CORS Origins
    # WARNING: ["*"] allows all origins - NOT SECURE for production!
    # In production, set to specific frontend URLs like:
    # BACKEND_CORS_ORIGINS=["https://yourdomain.com","https://app.yourdomain.com"]
    BACKEND_CORS_ORIGINS: List[str] = ["*"]  # حتما عوضش کنیم

    @property
    def cors_origins(self) -> List[str]:
        """Parse CORS origins from string or list."""
        if isinstance(self.BACKEND_CORS_ORIGINS, str):
            try:
                return json.loads(self.BACKEND_CORS_ORIGINS)
            except:
                return [self.BACKEND_CORS_ORIGINS]
        return self.BACKEND_CORS_ORIGINS

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Email (SMTP)
    # Leave SMTP_HOST empty to log password-reset emails to the console instead of
    # actually sending them (useful for development before a mail server exists).
    # Fill these in via .env to switch to live sending — no code change required.
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True  # STARTTLS on SMTP_PORT; set False to use implicit SSL
    SMTP_FROM_EMAIL: str = "no-reply@ngcorion.local"
    SMTP_FROM_NAME: str = "NGcorion"

    # Frontend base URL used to build the password-reset link sent by email.
    FRONTEND_BASE_URL: str = "http://localhost:5173"

    # How long a password-reset link stays valid.
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30

    # License Server
    LICENSE_SERVER_URL: str = "http://localhost:8001"
    LICENSE_STORAGE_DIR: str = "~/.license"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
