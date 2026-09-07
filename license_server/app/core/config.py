from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str
    
    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_EXPIRE_HOURS: int = 24
    
    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # API
    API_V1_PREFIX: str = "/api"
    
    # Admin
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "changeme"
    
    # CORS — cross-origin browser access.
    # Empty by default, which is correct for the shipped deployment: the admin
    # UI is served by nginx on the same origin and reaches this API through a
    # /api/ proxy (license-admin-ui/nginx.conf), and the NGCorion backend is a
    # server-to-server client where CORS does not apply at all.
    # Never set this to "*": these endpoints authenticate with HTTP Basic, which
    # browsers send as credentials, so a wildcard would let any site an admin
    # visits drive this API with those cached credentials.
    CORS_ORIGINS: List[str] = []

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()


def resolve_cors_origins() -> List[str]:
    """Validated CORS allowlist: explicit origins only, wildcards refused."""
    origins: List[str] = []
    for raw in settings.CORS_ORIGINS:
        origin = str(raw).strip().rstrip("/")
        if not origin:
            continue
        if "*" in origin or origin.lower() == "null":
            raise RuntimeError(
                f"CORS_ORIGINS contains {raw!r}. A wildcard/null origin cannot be "
                "combined with credentialed requests — the caller's own Origin "
                "would be reflected back, exposing these HTTP Basic protected "
                "endpoints to any site. List exact origins, or leave it empty "
                "(the default) since the admin UI is served same-origin."
            )
        if not origin.startswith(("http://", "https://")):
            raise RuntimeError(
                f"CORS_ORIGINS entry {raw!r} must be a full origin, e.g. "
                "https://license-admin.example.com"
            )
        if origin not in origins:
            origins.append(origin)
    return origins
