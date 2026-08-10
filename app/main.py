"""
Ngicorn - Main Application

FastAPI application entry point with CORS middleware and route registration.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import get_swagger_ui_html

from app.core.database import Base, engine, SessionLocal
from app.core.config import settings
from app.modules.auth import router as auth_router
from app.modules.logs import router as logs_router
from app.modules.users import router as users_router
from app.modules.assets.enums_router import enums_router
from app.modules.discovery import router as discovery_router
from app.modules.discovery.discovery_logs_router import router as discovery_logs_router
from app.modules.hardening.hardening_logs_router import router as hardening_logs_router
from app.modules.hardening.dashboard_router import router as hardening_dashboard_router
from app.modules.hardening.harden_all import router as harden_all_router
from app.modules.hardening.dashboard_router import router as hardening_dashboard_router

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

# Import risk router
from app.modules.risk.router import router as risk_router

# Import license components
from app.core.license_client import LicenseClient
from app.core.license_state import refresh_license_state
from app.core.heartbeat import start_heartbeat, stop_heartbeat
from app.middleware.license_middleware import LicenseMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    client = LicenseClient(settings.LICENSE_SERVER_URL, settings.LICENSE_STORAGE_DIR)
    app.state.license_client = client
    try:
        refresh_license_state(client)
    except Exception:
        pass  # App starts even if license server is unreachable
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
    yield
    # Shutdown
    stop_heartbeat()

# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    redirect_slashes=False,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Configure CORS middleware
# WARNING: Default allows all origins - configure BACKEND_CORS_ORIGINS in .env for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins if hasattr(settings, 'cors_origins') else settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],  # Allow all response headers to be accessible
)

# Add security headers middleware (after CORS, before routes)
app.add_middleware(SecurityHeadersMiddleware)

# Add license middleware (after CORS, before routes)
app.add_middleware(LicenseMiddleware)

# Custom Swagger UI endpoint
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Swagger UI",
        swagger_js_url="/static/swagger/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger/swagger-ui.css",
        swagger_favicon_url="/static/swagger/favicon-32x32.png"
    )

# Authentication routes (no auth required)
app.include_router(auth_router.router, prefix="/auth", tags=["Authentication"])

# Protected routes (auth required)
app.include_router(logs_router.router, prefix="/api/logs", tags=["Logs"])
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

# Hardening dashboard — read-only aggregates for the KPI screen
app.include_router(hardening_dashboard_router)

# Shared cross-family audit routes (get/delete session by ID for any device)
app.include_router(shared_audit_router)

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

# Risk & Exposure Intelligence routes
app.include_router(risk_router, prefix="/api/risk", tags=["Risk"])


@app.get("/")
def root():
    """Application root endpoint with basic info."""
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
