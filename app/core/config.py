"""
Base configuration for the project.

Loads settings from environment variables with fallback defaults.
SECURITY: Override all sensitive defaults in production via .env file.
"""
from pydantic_settings import BaseSettings
from typing import List, Optional
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
    VERSION: str = "2.1.0-rc.1"
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
    # A web session unused for this long is ended (app/core/sessions.py); the
    # UI also signs out after this long without keyboard or mouse input.
    SESSION_IDLE_TIMEOUT_MINUTES: int = 30
    # Notice shown on the login page before anyone signs in (empty: the
    # built-in bilingual notice).
    LOGIN_BANNER: Optional[str] = None

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

    # License server: the address is fixed in app/core/license_keys.py
    # (https://lic.ngcorion.com) and is not configurable. These two settings
    # only remain so an existing .env that still sets them is accepted; they
    # are ignored, with a warning at startup.
    LICENSE_SERVER_URL: str = ""
    LICENSE_SERVER_CA_BUNDLE: str = ""
    LICENSE_STORAGE_DIR: str = "~/.license"

    # HTTP behaviour for calls to the license server. Explicit connect/read
    # timeouts matter much more once the license server is a remote host: with
    # no timeout a single unreachable server hangs a worker thread forever.
    LICENSE_CONNECT_TIMEOUT: float = 5.0
    LICENSE_READ_TIMEOUT: float = 10.0
    # Attempts per call (1 = no retry). Only connection-level failures are
    # retried on activation; validate and heartbeat also retry read timeouts.
    LICENSE_HTTP_RETRIES: int = 3

    # Ignored (licensing v3). Without contact with the license server NGCorion
    # keeps the license's plan for 48 hours, then runs as a pilot (5 assets)
    # for 30 days, then locks: fixed in app/core/license_state.py, because a
    # setting here could be raised by whoever runs the product. Kept as a field
    # only so an old .env that still sets it starts with a warning instead of
    # failing validation.
    LICENSE_OFFLINE_GRACE_HOURS: Optional[int] = None

    # How often the background job scheduler checks for due ScheduledJobs.
    SCHEDULER_SWEEP_INTERVAL_SECONDS: int = 60

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

    # NOC historical metrics (app/modules/noc/metrics_retention.py): every poll
    # appends a raw sample row per device/interface metric, in addition to the
    # upserted "latest status" tables above. Raw rows are rolled up into 5m/1h/1d
    # aggregates and then dropped once older than these windows, so storage stays
    # bounded regardless of how long the product has been deployed.
    NOC_METRICS_RAW_RETENTION_HOURS: int = 168  # 7 days
    NOC_METRICS_5M_RETENTION_DAYS: int = 30
    NOC_METRICS_1H_RETENTION_DAYS: int = 180
    # 0 = keep daily rollups forever (their volume is negligible).
    NOC_METRICS_1D_RETENTION_DAYS: int = 0
    # Second line of defense: if the metrics tables' actual on-disk size passes
    # this fraction of the configured budget (e.g. more assets/interfaces than
    # planned), the retention job evicts the oldest rows tier-by-tier (raw
    # first, then 5m, then 1h) until back under it - a wrong retention-window
    # guess can never fill the disk.
    NOC_METRICS_STORAGE_BUDGET_GB: float = 10.0
    NOC_METRICS_STORAGE_EVICT_THRESHOLD: float = 0.8

    # Syslog intake (app/modules/syslog): the port the listener binds inside the container. The
    # container does not run as root, so it listens on 5514 and docker-compose publishes the
    # standard port 514 (UDP and TCP) of the host to it. Turned on and off in System Configuration.
    SYSLOG_BIND_ADDRESS: str = "0.0.0.0"
    SYSLOG_PORT: int = 5514

    # Audit storage (FAU_STG.4, app/core/storage_guard.py): below this much free disk, changes are
    # refused to everyone but system administrators and scheduled work waits, so the space left
    # goes to recording what administrators do to free it. The "Disk space low" alert (2 GB by
    # default) warns well before. 0 turns the guard off.
    STORAGE_CRITICAL_MB: int = 500

    # NGCorion self-backup (app/modules/sysbackup): encrypted .ngbak archives
    # of the database and the files the product keeps on disk. Mounted as a
    # volume in docker-compose so archives survive container recreation; copy
    # them off the server too (SFTP / Windows share destinations in the UI).
    BACKUP_DIR: str = "/var/lib/ngcorion/backups"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()


def ignored_license_settings() -> List[str]:
    """Names of the old license settings that are set although they have no effect."""
    names = [name for name in ("LICENSE_SERVER_URL", "LICENSE_SERVER_CA_BUNDLE")
             if (getattr(settings, name) or "").strip()]
    if settings.LICENSE_OFFLINE_GRACE_HOURS is not None:
        names.append("LICENSE_OFFLINE_GRACE_HOURS")
    return names


_INSECURE_DEFAULT_SECRET_KEY = "your-secret-key-here-change-in-production-min-32-chars"
# Placeholders published in this repository (config.py, .env.example): never a real key.
_PUBLISHED_SECRET_KEYS = {_INSECURE_DEFAULT_SECRET_KEY, "change-this-to-a-random-32-character-string"}
MIN_SECRET_KEY_LENGTH = 32


def require_secure_secret_key() -> str:
    """
    Return SECRET_KEY, or raise if it is still the published placeholder or shorter than
    MIN_SECRET_KEY_LENGTH characters.

    SECRET_KEY signs every JWT this app issues; the default value above is
    checked into the repository and public, so leaving it in place lets
    anyone forge a valid token for any user, admin included, with no need to
    ever guess a password. Same fail-fast philosophy as
    resolve_cors_origins(): stop at startup
    with an actionable message rather than run in a silently compromised
    state.
    """
    key = settings.SECRET_KEY
    if key in _PUBLISHED_SECRET_KEYS:
        raise RuntimeError(
            "SECRET_KEY is still a published placeholder (config.py / .env.example). Generate "
            "a real one (e.g. `openssl rand -hex 32`) and set SECRET_KEY in the "
            "environment or .env file before starting the app."
        )
    # It is the HMAC key of every session token and the root of the keys that encrypt stored
    # secrets (credential_crypto): a short one can be brute-forced offline from a single token.
    if len(key) < MIN_SECRET_KEY_LENGTH:
        raise RuntimeError(
            f"SECRET_KEY is {len(key)} characters long; at least {MIN_SECRET_KEY_LENGTH} are required. "
            "Generate one with `openssl rand -hex 32` and set SECRET_KEY in the environment or .env "
            "file. Changing it signs everyone out and, unless a system backup is restored, makes "
            "stored secrets (scheduled-job credentials, SNMP, SMTP, ...) unreadable: re-enter them."
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
