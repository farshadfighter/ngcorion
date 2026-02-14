"""
Ngicorn - Main Application

FastAPI application entry point with CORS middleware and route registration.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import Base, engine
from app.core.config import settings
from app.modules.auth import router as auth_router
from app.modules.logs import router as logs_router
from app.modules.users import router as users_router
from app.modules.assets.enums_router import enums_router
from app.modules.discovery import router as discovery_router

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

# Apache Audit (new module)
from app.modules.apache.audit import router as apache_audit_router

# Shared hardening infrastructure
from app.modules.shared import hardening_router as unified_hardening_router

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

# Create database tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    redirect_slashes=False
)

# Configure CORS middleware
# WARNING: Default allows all origins - configure BACKEND_CORS_ORIGINS in .env for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins if hasattr(settings, 'cors_origins') else settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],  # Allow all response headers to be accessible
    # hatman avaz shavad
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

# Schema-driven Hardening routes (unified)
app.include_router(unified_hardening_router)

# Module-specific audit log routes
app.include_router(requirement_logs_router)
app.include_router(asset_logs_router)
app.include_router(cisco_audit_logs_router)

# Deprecated routes (backward compatibility - 307 redirects)
app.include_router(deprecated_router)


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



