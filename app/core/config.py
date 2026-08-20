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

    # Frontend base URL (reserved; the OTP reset flow no longer emails a link).
    FRONTEND_BASE_URL: str = "http://localhost:5173"

    # How long a password-reset OTP code stays valid (minutes).
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 10
    # Max wrong-code attempts before the OTP is invalidated and a new one is needed.
    PASSWORD_RESET_MAX_ATTEMPTS: int = 5

    # License Server
    # NO default host on purpose: the license server may live on a completely
    # different machine, and a "http://localhost:8001" fallback silently points
    # a misconfigured production deployment at nothing (or worse, at whatever
    # else listens on 8001 locally). LICENSE_SERVER_URL must be supplied via the
    # environment / .env; startup fails loudly when it is missing
    # (see require_license_server_url()).
    LICENSE_SERVER_URL: str = ""
    LICENSE_STORAGE_DIR: str = "~/.license"

    # HTTP behaviour for calls to the license server. Explicit connect/read
    # timeouts matter much more once the license server is a remote host: with
    # no timeout a single unreachable server hangs a worker thread forever.
    LICENSE_CONNECT_TIMEOUT: float = 5.0
    LICENSE_READ_TIMEOUT: float = 10.0
    # Attempts per call (1 = no retry). Only connection-level failures are
    # retried; a read timeout on POST is never retried, because /consume is not
    # idempotent and a retry could double-charge the quota.
    LICENSE_HTTP_RETRIES: int = 3

    # How long the last successfully validated license state stays usable while
    # the license server is unreachable. Mirrors the server-side rule that
    # downgrades a license after 48h without a heartbeat, so a network outage
    # degrades exactly as slowly as the server policy allows instead of locking
    # the whole app out on the first failed call.
    LICENSE_OFFLINE_GRACE_HOURS: int = 48

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()


def require_license_server_url() -> str:
    """
    Return LICENSE_SERVER_URL, or raise if it was never configured.

    Called at application startup so a deployment that forgot to set the
    variable fails immediately with an actionable message, instead of running
    and 403-ing every request because "localhost:8001" answers nothing.
    """
    url = (settings.LICENSE_SERVER_URL or "").strip()
    if not url:
        raise RuntimeError(
            "LICENSE_SERVER_URL is not set. Point it at the license server, "
            "e.g. LICENSE_SERVER_URL=http://10.0.0.20:8001 in the environment "
            "or .env file. There is deliberately no localhost default."
        )
    return url.rstrip("/")
