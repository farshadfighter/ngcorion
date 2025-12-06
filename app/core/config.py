"""
Base configuration for the project.

Loads settings from environment variables with fallback defaults.
SECURITY: Override all sensitive defaults in production via .env file.
"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    All sensitive values (DATABASE_URL, SECRET_KEY) MUST be overridden
    in production using a .env file or environment variables.
    """

    # Project Info
    PROJECT_NAME: str = "Ngicorn"
    VERSION: str = "1.0.6"
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
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # CORS Origins
    # WARNING: ["*"] allows all origins - NOT SECURE for production!
    # In production, set to specific frontend URLs like:
    # BACKEND_CORS_ORIGINS=["https://yourdomain.com","https://app.yourdomain.com"]
    BACKEND_CORS_ORIGINS: List[str] = ["*"]  # Must be restricted in production

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()