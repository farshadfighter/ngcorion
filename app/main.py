"""
Ngicorn - Main Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import Base, engine
from app.modules.auth import router as auth_router
from app.modules.logs import router as logs_router
from app.modules.users import router as users_router
from app.modules.assets.enums_router import enums_router
from app.modules.discovery import router as discovery_router

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
    views_router
)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Ngiocorn",
    description="Network monitoring and asset management system",
    version="1.0.6",
    redirect_slashes=False
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # در production باید محدود شود
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
app.include_router(enums_router)

# NEW: Auto Discovery routes
app.include_router(discovery_router.router)


@app.get("/")
def root():
    return {
        "project": "Ngicorn",
        "version": "1.0.6",
        "status": "running",
        "features": ["Auditing", "Hardening"]
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)