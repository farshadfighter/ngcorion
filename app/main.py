"""
Ngicorn - Main Application

FastAPI application entry point with CORS middleware and route registration.
"""
import asyncio
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html

from app.core.database import Base, engine, SessionLocal
from app.core.config import (
    settings,
    require_license_server_url,
    require_secure_secret_key,
    resolve_cors_origins,
)
from app.core.dependencies import get_current_user
from app.modules.auth import router as auth_router
from app.modules.logs import router as logs_router
from app.modules.logs import clear_router as logs_clear_router
from app.modules.users import router as users_router
from app.modules.assets.enums_router import enums_router
from app.modules.discovery import router as discovery_router
from app.modules.discovery.discovery_logs_router import router as discovery_logs_router
from app.modules.hardening.hardening_logs_router import router as hardening_logs_router
from app.modules.hardening.dashboard_router import router as hardening_dashboard_router
from app.modules.hardening.harden_all import router as harden_all_router

# Cisco Audit and Hardening (new module structure)
from app.modules.cisco.audit import router as cisco_audit_router
from app.modules.cisco.audit import audit_logs_router as cisco_audit_logs_router
from app.modules.cisco.hardening import router as cisco_hardening_router

# Fortinet Audit and Hardening (new module structure)
from app.modules.fortinet.audit import router as fortinet_audit_router
from app.modules.fortinet.hardening import router as fortinet_hardening_router

# Linux Audit and Hardening (new module structure)
from app.modules.linux.audit import router as linux_audit_router
from app.modules.linux.hardening import router as linux_hardening_router

# Apache Audit and Hardening (new module)
from app.modules.apache.audit import router as apache_audit_router
from app.modules.apache.hardening import router as apache_hardening_router

# MongoDB Audit and Hardening
from app.modules.mongodb.audit import router as mongodb_audit_router
from app.modules.mongodb.hardening import router as mongodb_hardening_router

# SQL Server (MSSQL) Audit and Hardening
from app.modules.mssql.audit import router as mssql_audit_router
from app.modules.mssql.hardening import router as mssql_hardening_router

# Windows Server Audit and Hardening
from app.modules.windows.audit import router as windows_audit_router
from app.modules.windows.hardening import router as windows_hardening_router

# Shared hardening infrastructure
from app.modules.shared import hardening_router as unified_hardening_router

# Shared cross-family audit endpoints (get/delete session by ID)
from app.modules.audit.router import router as shared_audit_router
from app.modules.audit.dashboard_router import router as audit_dashboard_router
from app.modules.audit.events_router import router as security_events_router

# Deprecated routes for backward compatibility
from app.modules.deprecated_routes import deprecated_router

# Import authenticated routers
from app.modules.assets.router_with_auth import (
    asset_types_router,
    assets_router,
    owners_router,
    locations_router,
    zones_router,
    os_router,
    vendors_router,
    dependencies_router,
    security_router,
    views_router,
    requirements_router
)

# Import module audit log routers
from app.modules.assets.requirement_logs_router import router as requirement_logs_router
from app.modules.assets.asset_logs_router import router as asset_logs_router

# Import license router
from app.modules.license.router import router as license_router

# Import backup router
from app.modules.backup.router import router as backup_router

# Import topology router
from app.modules.topology.router import router as topology_router

# Import NOC (SNMP monitoring) router
from app.modules.noc.router import router as noc_router

# Import architecture validation router
from app.modules.architecture_validation.router import router as architecture_validation_router

# Import design and configuration routers
from app.modules.design.router import router as design_router
from app.modules.configuration.router import router as configuration_router

# Import deployment router
from app.modules.deployment.router import router as deployment_router

# Import drift router
from app.modules.drift.router import router as drift_router

# Import CVE router
from app.modules.cve.router import router as cve_router

# Import risk router
from app.modules.risk.router import router as risk_router

# Import system configuration router
from app.modules.system_config.router import router as system_config_router

# Import organization-wide dashboard routers
from app.modules.dashboard.security_score_router import router as security_score_router

# Import license components
from app.core.license_client import LicenseClient
from app.core.license_state import (
    attach_state_cache,
    get_license_state,
    refresh_license_state,
    restore_cached_state,
)
from app.core.heartbeat import start_heartbeat, stop_heartbeat
from app.modules.noc.poller import start_noc_poller, stop_noc_poller
from app.middleware.license_middleware import LicenseMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)

# Fails fast if SECRET_KEY is still the published placeholder - see
# require_secure_secret_key()'s docstring. Checked before anything else so a
# misconfigured deployment never issues a single forgeable token.
require_secure_secret_key()

# Create database tables
Base.metadata.create_all(bind=engine)

# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    # Misconfiguration fails fast (there is no localhost fallback); an
    # unreachable server does not — those are different problems.
    try:
        license_server_url = require_license_server_url()
    except RuntimeError as exc:
        logger.critical("[Startup] %s", exc)
        raise

    client = LicenseClient(license_server_url, settings.LICENSE_STORAGE_DIR)
    app.state.license_client = client
    logger.info(f"[Startup] license server: {license_server_url}")

    # Seed the in-memory state from the on-disk cache *before* the first
    # validation. If the license server is unreachable right now, the app comes
    # up on the last validated state (still bounded by the offline grace
    # window) instead of 403/503-ing every request until connectivity returns.
    attach_state_cache(client.storage)
    restored = restore_cached_state()

    try:
        # Blocking HTTP call: run it off the event loop so a slow or dead
        # license server cannot stall startup for other lifespan work.
        state = await asyncio.to_thread(refresh_license_state, client)
        if state.offline:
            logger.warning(
                "[Startup] license server unreachable; running on the last "
                "validated license state (cached: %s) until it can be reached "
                "again. The application still starts.",
                restored,
            )
        else:
            logger.info(
                "[Startup] license validated (valid=%s, plan=%s)",
                state.valid, state.plan_type,
            )
    except Exception as exc:
        # App starts even if license validation fails — never block startup on
        # the license server. The middleware reports the state per request.
        logger.error(
            "[Startup] license state refresh failed, starting without a "
            "refreshed license: %s: %s",
            type(exc).__name__, exc,
        )

    if not get_license_state().valid:
        logger.warning(
            "[Startup] no valid license state: /api/* requests will be refused "
            "until the license server confirms a license. Current status: %s",
            get_license_state().message,
        )

    start_heartbeat(client)

    # Seed default risk settings/zones (idempotent). Uses its own session so a
    # failure here never blocks startup.
    from app.modules.risk.seed import seed_risk_defaults
    db = SessionLocal()
    try:
        seed_risk_defaults(db)
    except Exception as e:
        logger.warning(f"Risk seed skipped: {e}")
    finally:
        db.close()

    # Seed curated CVE records (idempotent). Uses its own session so a
    # failure here never blocks startup.
    from app.modules.cve.seed import seed_cve_defaults
    db = SessionLocal()
    try:
        seed_cve_defaults(db)
    except Exception as e:
        logger.warning(f"CVE seed skipped: {e}")
    finally:
        db.close()

    start_noc_poller()

    yield
    # Shutdown
    stop_heartbeat()
    await stop_noc_poller()

# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    redirect_slashes=False,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    # The auto-registered /openapi.json is unauthenticated by default - it would
    # publish every route, parameter and model field of a security/hardening
    # product to anyone, unauthenticated. Disabled here; a gated replacement is
    # registered below alongside the custom /docs route.
    openapi_url=None,
)

# Mount static files (Swagger UI assets, etc.)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# --- Frontend (React SPA) ---------------------------------------------------
# The built bundle in front/dist is served directly by this backend (no nginx).
# The SPA shell, the hashed build files and the deep-link fallback are all
# handled by the catch-all route at the very end of this file (registered after
# all API routers so it never shadows them).
#
# There is deliberately no app.mount("/assets", StaticFiles(...)) here. A mount
# owns its whole path prefix: it answers every /assets/* request itself and
# 404s when no file matches, so the request never reaches the catch-all. The
# client-side routes /assets/inventory, /assets/requirements and
# /assets/discovery share that prefix, so reloading (Ctrl+F5) any Asset
# Management page returned {"detail":"Not Found"} instead of the app. Serving
# the build files from the catch-all keeps one consistent rule for the prefix.
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "front" / "dist"
FRONTEND_INDEX = FRONTEND_DIST / "index.html"

# ---------------------------------------------------------------------------
# Middleware ordering
# ---------------------------------------------------------------------------
# Starlette wraps user_middleware in the REVERSE of the order add_middleware()
# is called in: the last one added ends up outermost (runs first on the way
# in, last on the way out), the first one added ends up innermost, right next
# to the router. So LicenseMiddleware must be added FIRST, before CORS and
# the security headers middleware - it returns its own JSONResponse directly
# (never calls call_next) whenever the license is invalid, and if it were
# outermost that response would skip every middleware added after it. It used
# to be added last, which meant every license-blocked response - the ones an
# unauthenticated scan of an unlicensed instance would actually see - shipped
# with no CSP/X-Frame-Options/etc. and no CORS headers at all.
app.add_middleware(LicenseMiddleware)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# The allowlist is explicit and validated (resolve_cors_origins raises on "*",
# wildcards, paths and bad schemes), so an unsafe value stops the app at import
# time instead of silently reflecting whatever Origin a caller sends.
#
# Empty is the normal, correct configuration: this app serves the frontend
# itself (front/dist, below) and the frontend calls the API with a relative base
# URL, so those requests are same-origin and CORS never applies. The Vite dev
# server proxies /api and /auth for the same reason. Only a browser app hosted
# on a *different* origin needs entries here — see .env.example.
#
# The middleware is installed either way: with an empty list Starlette answers a
# cross-origin preflight with an explicit "Disallowed CORS origin" instead of a
# confusing 405 from the router, and never emits Access-Control-Allow-Origin.
CORS_ORIGINS = resolve_cors_origins()
if CORS_ORIGINS:
    logger.info("[Startup] CORS enabled for origins: %s", ", ".join(CORS_ORIGINS))
else:
    logger.info(
        "[Startup] No BACKEND_CORS_ORIGINS configured — cross-origin browser "
        "access is disabled. The bundled same-origin frontend is unaffected."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    # Credentials are granted only to the explicitly listed origins above; with
    # an empty list nothing is credentialed. Starlette refuses to pair this with
    # a literal "*", which is exactly the combination we validate against.
    allow_credentials=True,
    # Narrowed from "*" to the verbs this API actually exposes. A new verb
    # (e.g. PATCH) must be added here as well as to its router.
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    # Narrowed from "*": the frontend sends a bearer token and JSON, plus the
    # headers axios/browsers add for uploads and content negotiation.
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
    # Only what a cross-origin caller legitimately needs to read. Downloads
    # (Excel export/template) carry the filename here.
    expose_headers=["Content-Disposition"],
)

# Added last so it is outermost (see the ordering note above) - every
# response, including the ones LicenseMiddleware/CORSMiddleware short-circuit,
# still gets these headers.
app.add_middleware(SecurityHeadersMiddleware)

# Authenticated OpenAPI schema. The schema lists every route, parameter and
# model field in the application - reconnaissance material an unauthenticated
# caller has no business getting from a security/hardening product, so this
# requires a real bearer token rather than being served to anyone who asks.
@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_schema(current_user=Depends(get_current_user)):
    return JSONResponse(app.openapi())


# Custom Swagger UI endpoint. Deliberately NOT gated the same way as
# /openapi.json above: a plain browser navigation here never carries an
# Authorization header (that's only ever attached by JS to API calls), so a
# get_current_user dependency on this route would just make the page
# permanently 401. The page itself is inert chrome with no embedded schema -
# it fetches /openapi.json client-side, which is what actually enforces
# auth. Swagger UI's own "Authorize" button lets a logged-in operator paste
# their token to load the schema and try requests.
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=app.title + " - Swagger UI",
        swagger_js_url="/static/swagger/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger/swagger-ui.css",
        swagger_favicon_url="/static/swagger/favicon-32x32.png"
    )

# Authentication routes (no auth required)
app.include_router(auth_router.router, prefix="/auth", tags=["Authentication"])

# Protected routes (auth required)
app.include_router(logs_router.router, prefix="/api/logs", tags=["Logs"])
# DELETE /api/logs/clear — carries its own prefix, so no prefix= here.
app.include_router(logs_clear_router.router)
app.include_router(users_router.router, prefix="/api/users", tags=["Users"])
app.include_router(asset_types_router)
app.include_router(assets_router)
app.include_router(owners_router)
app.include_router(locations_router)
app.include_router(zones_router)
app.include_router(os_router)
app.include_router(vendors_router)
app.include_router(dependencies_router)
app.include_router(security_router)
app.include_router(views_router)
app.include_router(requirements_router)
app.include_router(enums_router)

# Auto Discovery routes
app.include_router(discovery_router.router)
app.include_router(discovery_logs_router)

# Hardening Logs routes
app.include_router(hardening_logs_router)

# Hardening Dashboard routes (risk-aware)
app.include_router(hardening_dashboard_router)

# Cisco CIS Audit routes
app.include_router(cisco_audit_router)

# Cisco Hardening routes
app.include_router(cisco_hardening_router)

# FortiGate Audit routes
app.include_router(fortinet_audit_router)

# FortiGate Hardening routes
app.include_router(fortinet_hardening_router)

# Linux CIS Audit routes
app.include_router(linux_audit_router)

# Linux Hardening routes
app.include_router(linux_hardening_router)

# Apache CIS Audit routes
app.include_router(apache_audit_router)

# Apache Hardening routes
app.include_router(apache_hardening_router)

# MongoDB CIS Audit routes
app.include_router(mongodb_audit_router)

# MongoDB Hardening routes
app.include_router(mongodb_hardening_router)

# SQL Server CIS Audit routes
app.include_router(mssql_audit_router)

# SQL Server Hardening routes
app.include_router(mssql_hardening_router)

# Windows Server CIS Audit routes
app.include_router(windows_audit_router)

# Windows Server Hardening routes
app.include_router(windows_hardening_router)

# Schema-driven Hardening routes (unified)
app.include_router(unified_hardening_router)

# Harden All — one plan/execute contract across every device family
app.include_router(harden_all_router)

# Shared cross-family audit routes (get/delete session by ID for any device)
app.include_router(shared_audit_router)

# Auditing dashboard — read-only aggregates for the KPI screen
app.include_router(audit_dashboard_router)

# Cross-module security event stream — read-only view over audit_logs
app.include_router(security_events_router)

# Module-specific audit log routes
app.include_router(requirement_logs_router)
app.include_router(asset_logs_router)
app.include_router(cisco_audit_logs_router)

# Deprecated routes (backward compatibility - 307 redirects)
app.include_router(deprecated_router)

# License routes
app.include_router(license_router)

# Backup routes
app.include_router(backup_router)

# Topology routes
app.include_router(topology_router)

# NOC (SNMP monitoring) routes
app.include_router(noc_router)

# Architecture Validation routes
app.include_router(architecture_validation_router)

# Design and Configuration routes
app.include_router(design_router)
app.include_router(configuration_router)

# Deployment routes
app.include_router(deployment_router)

# Configuration Drift routes
app.include_router(drift_router)

# CVE Vulnerability Management routes
app.include_router(cve_router)

# Risk & Exposure Intelligence routes
app.include_router(risk_router, prefix="/api/risk", tags=["Risk"])

# Organization dashboard routes (security score)
app.include_router(
    security_score_router, prefix="/api/dashboard", tags=["Dashboard"]
)

# System Configuration routes (time, SNMP, syslog, SMS, SMTP, certificate)
app.include_router(
    system_config_router, prefix="/api/system", tags=["System Configuration"]
)


@app.get("/api/info", tags=["Meta"])
def app_info():
    """Application info endpoint (project name, version, feature list)."""
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "running",
        "features": ["Asset Management", "Network Discovery", "Security Auditing", "Device Hardening"]
    }


@app.get("/health")
def health_check():
    """
    Health check endpoint for monitoring.

    Returns basic health status. For production, consider adding
    database connectivity check.
    """
    return {"status": "ok", "version": settings.VERSION}


# --- SPA catch-all ----------------------------------------------------------
# Serves the React build (front/dist) for the root and any client-side route.
# Registered LAST so every API/auth/docs router above takes precedence; only
# unmatched paths fall through here. A matching static file (e.g. logo2.png)
# is returned directly, otherwise index.html is returned so BrowserRouter can
# resolve deep links / refreshes (e.g. /audit/sessions/42). When no build is
# present (dev without `npm run build`, tests) this reports the info payload
# at "/" and 404s elsewhere, so the API still runs without a frontend bundle.
@app.get("/", include_in_schema=False)
@app.get("/{full_path:path}", include_in_schema=False)
def serve_spa(full_path: str = ""):
    # Reserved backend prefixes must 404 honestly rather than be masked by the
    # SPA shell — reaching here with one means no router above matched it.
    # "assets/" is NOT reserved: it is shared by the build output and by the
    # Asset Management client-side routes, and the file check below tells them
    # apart.
    if full_path.startswith(("api/", "auth/", "docs", "openapi.json", "static/")):
        raise HTTPException(status_code=404, detail="Not Found")

    if not FRONTEND_INDEX.is_file():
        if full_path == "":
            return app_info()
        raise HTTPException(status_code=404, detail="Frontend build not found")

    # Serve a real file from the build if it exists (and stays inside dist),
    # otherwise fall back to the SPA shell for client-side routing.
    if full_path:
        candidate = (FRONTEND_DIST / full_path).resolve()
        if candidate.is_file() and FRONTEND_DIST.resolve() in candidate.parents:
            return FileResponse(candidate)

        # The file does not exist. Anything that looks like a file request (it
        # has an extension) is a missing asset and must 404 — returning the
        # HTML shell for a missing .js/.css would make the browser fail on a
        # syntax error instead of a clear 404. Extensionless paths are
        # client-side routes and fall through to the shell below.
        if "." in Path(full_path).name:
            raise HTTPException(status_code=404, detail="Not Found")

    return FileResponse(FRONTEND_INDEX)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
