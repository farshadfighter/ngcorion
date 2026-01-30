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
from app.modules.audit import router as audit_router
from app.modules.hardening import router as hardening_router
from app.modules.fortinet import router as fortinet_router

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
from app.modules.audit.audit_logs_router import router as audit_logs_router

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

# NEW: Auto Discovery routes
app.include_router(discovery_router.router)

# NEW: Cisco CIS Audit routes
app.include_router(audit_router.router)

# NEW: Cisco Hardening routes
app.include_router(hardening_router.router)

# NEW: FortiGate Audit routes
app.include_router(fortinet_router.router)

# Module-specific audit log routes
app.include_router(requirement_logs_router)
app.include_router(asset_logs_router)
app.include_router(audit_logs_router)


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