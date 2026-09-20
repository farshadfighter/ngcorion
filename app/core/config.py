"""
Base configuration for the project.

Loads settings from environment variables with fallback defaults.
SECURITY: Override all sensitive defaults in production via .env file.
"""
from pydantic_settings import BaseSettings
from typing import List
from urllib.parse import urlparse
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

    # CORS Origins — browsers only; see resolve_cors_origins() below.
    #
    # Empty by default, and that is the correct value for the normal
    # deployment: the frontend is served by this same application (front/dist via
    # the catch-all route) and calls the API with a relative base URL, so those
    # requests are same-origin and never involve CORS at all. The Vite dev server
    # likewise proxies /api and /auth to the backend, so dev is same-origin too.
    #
    # Only set this when a browser app served from a DIFFERENT origin must call
    # this API, e.g.:
    #   BACKEND_CORS_ORIGINS=["https://app.example.com","http://localhost:5173"]
    #   BACKEND_CORS_ORIGINS=https://app.example.com,http://localhost:5173
    # "*" is rejected at startup: it cannot be combined with credentialed
    # requests without letting any site on the internet drive this API as a
    # logged-in user.
    #
    # Typed as a plain string on purpose: pydantic-settings JSON-decodes a
    # List[str] field *before* any of our code runs, so the comma-separated
    # form above would raise a SettingsError at import and take the whole app
    # down. Parsing happens in `cors_origins` instead, which accepts both.
    BACKEND_CORS_ORIGINS: str = ""

    @property
    def cors_origins(self) -> List[str]:
        """
        Raw configured origins, accepting the shapes an operator may supply.

        pydantic-settings already parses a JSON list from the environment; this
        additionally tolerates a bare string and a comma-separated list. It does
        NOT validate — use resolve_cors_origins() for anything security-relevant.
        """
        raw = self.BACKEND_CORS_ORIGINS
        if isinstance(raw, str):
            text = raw.strip()
            if not text:
                return []
            try:
                parsed = json.loads(text)
            except ValueError:
                return [part.strip() for part in text.split(",") if part.strip()]
            if isinstance(parsed, str):
                return [parsed]
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
            return []
        return [str(item).strip() for item in (raw or []) if str(item).strip()]

    # SSH host-key verification (all managed-device connections)
    # "tofu"   — trust on first use: the first connection to a host pins its key
    #            (logged with the fingerprint) and every later connection must
    #            present the same key. Existing devices keep working; a changed
    #            or spoofed key is refused.
    # "strict" — only hosts already present in the known-hosts store may be
    #            reached. Nothing is pinned automatically.
    # There is deliberately no "off": a legitimately reinstalled device is
    # handled by removing that one host's entry from the store, not by
    # disabling verification. See docs/SSH_HOST_KEY_VERIFICATION.md.
    SSH_HOST_KEY_POLICY: str = "tofu"
    # Known-hosts store (OpenSSH format). Empty = auto-detect: /etc/ngcorion/
    # known_hosts when that directory is writable (it is bind-mounted into the
    # container, so pinned keys survive recreation), else ~/.ngcorion/known_hosts.
    SSH_KNOWN_HOSTS_FILE: str = ""

    # WinRM (Windows audit + hardening)
    # Validate the target's WinRM HTTPS certificate. Defaults to False because
    # Windows ships a self-signed WinRM listener; set WINRM_VERIFY_SSL=true once
    # the fleet presents certificates a CA in the trust store can validate.
    # A per-request verify_ssl in the API body overrides this.
    WINRM_VERIFY_SSL: bool = False

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

    # Path to a PEM certificate to verify the license server's HTTPS listener
    # against. The license server is internal and reached by IP, so it cannot
    # have a publicly-issued certificate; it serves a self-signed one instead.
    # Pointing this at that certificate makes verification *succeed properly*
    # rather than be switched off — there is deliberately no "skip verify"
    # option here, because disabling verification on the one channel that
    # authorises the whole product is exactly the wrong trade.
    # Empty (the default) = plain HTTP, or HTTPS against a publicly trusted CA;
    # either way requests uses its normal certifi bundle.
    LICENSE_SERVER_CA_BUNDLE: str = ""

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

    # Heartbeat cadence. On a *failed* heartbeat the loop does not wait a whole
    # interval before trying again: it backs off from RETRY_SECONDS, doubling up
    # to MAX_RETRY_SECONDS, until a heartbeat succeeds. Waiting the full hour
    # after a single dropped packet burns most of the 48h offline grace window
    # on doing nothing.
    LICENSE_HEARTBEAT_INTERVAL_SECONDS: int = 3600
    LICENSE_HEARTBEAT_RETRY_SECONDS: int = 60
    LICENSE_HEARTBEAT_MAX_RETRY_SECONDS: int = 900

    # Persist the last successfully validated license state (encrypted, next to
    # the license data) so a restart while the license server is unreachable
    # resumes inside the offline grace window instead of locking the product out
    # with an empty in-memory state.
    LICENSE_STATE_CACHE_ENABLED: bool = True

    # NOC: how often the background poller sweeps every asset that has an
    # SNMP credential configured (app/modules/noc/poller.py).
    NOC_POLL_INTERVAL_SECONDS: int = 60

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


_INSECURE_DEFAULT_SECRET_KEY = "your-secret-key-here-change-in-production-min-32-chars"


def require_secure_secret_key() -> str:
    """
    Return SECRET_KEY, or raise if it is still the published placeholder.

    SECRET_KEY signs every JWT this app issues; the default value above is
    checked into the repository and public, so leaving it in place lets
    anyone forge a valid token for any user, admin included, with no need to
    ever guess a password. Same fail-fast philosophy as
    require_license_server_url() / resolve_cors_origins(): stop at startup
    with an actionable message rather than run in a silently compromised
    state.
    """
    key = settings.SECRET_KEY
    if key == _INSECURE_DEFAULT_SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY is still the default placeholder from config.py. Generate "
            "a real one (e.g. `openssl rand -hex 32`) and set SECRET_KEY in the "
            "environment or .env file before starting the app."
        )
    return key


class CORSConfigurationError(RuntimeError):
    """BACKEND_CORS_ORIGINS contains an unsafe or malformed value."""


def _normalize_cors_origin(raw: str) -> str:
    """
    Validate one configured origin and return it in the exact form a browser
    sends in the ``Origin`` header: ``scheme://host[:port]``, lowercased, with
    no trailing slash and no path.

    Starlette compares the request's Origin header against this list with plain
    string equality, so a value that merely *looks* right ("https://app.example.com/",
    "APP.EXAMPLE.COM", "https://*.example.com") would silently never match and
    the operator would think CORS was configured when it was not. Rejecting
    these loudly is the difference between a security control and a placebo.

    Raises:
        CORSConfigurationError: value is unsafe or cannot be a browser Origin.
    """
    value = (raw or "").strip()
    if not value:
        raise CORSConfigurationError("BACKEND_CORS_ORIGINS contains an empty entry.")

    if value == "*":
        raise CORSConfigurationError(
            'BACKEND_CORS_ORIGINS contains "*". A wildcard cannot be combined '
            "with credentialed cross-origin requests: Starlette reflects the "
            "caller's own Origin back, so ANY website could drive this API as a "
            "logged-in user. List the exact frontend origins instead, e.g. "
            'BACKEND_CORS_ORIGINS=["https://app.example.com"] — or leave it '
            "empty (the default) when the frontend is served by this same "
            "application, which is the normal deployment and needs no CORS."
        )

    if value.lower() == "null":
        raise CORSConfigurationError(
            'BACKEND_CORS_ORIGINS contains "null". The null origin is sent by '
            "sandboxed iframes and local files and is not a trustworthy identity."
        )

    if "*" in value:
        raise CORSConfigurationError(
            f"BACKEND_CORS_ORIGINS entry {raw!r} contains a wildcard. Origins are "
            "matched by exact string comparison, so a pattern like "
            '"https://*.example.com" would never match anything. List each '
            "origin explicitly."
        )

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise CORSConfigurationError(
            f"BACKEND_CORS_ORIGINS entry {raw!r} must start with http:// or "
            "https:// (a browser Origin always carries a scheme)."
        )
    if not parsed.hostname:
        raise CORSConfigurationError(
            f"BACKEND_CORS_ORIGINS entry {raw!r} has no host."
        )
    if parsed.username or parsed.password:
        raise CORSConfigurationError(
            f"BACKEND_CORS_ORIGINS entry {raw!r} must not contain credentials."
        )
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise CORSConfigurationError(
            f"BACKEND_CORS_ORIGINS entry {raw!r} must be a bare origin "
            "(scheme://host[:port]) with no path, query or fragment — that is "
            "all a browser ever sends in the Origin header."
        )

    # Rebuild rather than string-munge, so the result is canonical.
    host = parsed.hostname.lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    origin = f"{parsed.scheme.lower()}://{host}"
    if parsed.port is not None:
        origin = f"{origin}:{parsed.port}"
    return origin


def resolve_cors_origins() -> List[str]:
    """
    Return the validated, normalized CORS allowlist.

    Fails closed in both directions:
      * unset/empty -> ``[]``: no cross-origin browser access is granted. This is
        the default and the correct value for the standard deployment, where the
        frontend is served by this same app and its requests are same-origin.
      * unsafe/malformed (``*``, ``null``, wildcards, paths, bad scheme) ->
        raises :class:`CORSConfigurationError` at startup rather than quietly
        degrading to something permissive.

    Duplicates are collapsed while preserving order.
    """
    resolved: List[str] = []
    for raw in settings.cors_origins:
        origin = _normalize_cors_origin(raw)
        if origin not in resolved:
            resolved.append(origin)
    return resolved
