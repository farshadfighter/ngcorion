"""
Base config of project
"""
# Pydantic help for create clean config
from pydantic_settings import BaseSettings
#from typing import Optional

class Settings(BaseSettings):
    """Base setting"""

    # Project Info
    PROJECT_NAME: str = "Ngicorn"
    VERSION: str = "1.0.6"
    DESCRIPTION: str = "Network Monitoring and Asset Management System"
    
    # Database
    DATABASE_URL: str = "postgresql://netease:1234@localhost/netease_db"
    
    # Security
    SECRET_KEY: str = "your-secret-key-here-change-in-production-min-32-chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS
    BACKEND_CORS_ORIGINS: list = ["*"]  # باید در مراحل بعدی توسعه مححود شود
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()