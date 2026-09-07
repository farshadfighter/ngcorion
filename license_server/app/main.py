from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routers import licenses, admin
from .middleware.logging import LoggingMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .core.config import settings, resolve_cors_origins
from .utils.fingerprint import get_vm_fingerprint
from .schemas import FingerprintResponse

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="License Server API",
    description="License management and validation system",
    version="1.0.0"
)

# Add middleware
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware)

# CORS: explicit allowlist only. "*" with allow_credentials=True would reflect
# the caller's Origin back and expose these HTTP Basic protected admin endpoints
# to any site an administrator happens to visit. Empty (the default) is correct
# for the shipped deployment — the admin UI is same-origin behind nginx and the
# NGCorion backend is a server-to-server client, neither of which uses CORS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=resolve_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

app.include_router(licenses.router)
app.include_router(admin.router)

@app.get("/")
def root():
    return {"message": "License Server API is running"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.get("/api/fingerprint", response_model=FingerprintResponse)
def get_fingerprint():
    """Get VM fingerprint for this machine
    
    Returns a unique fingerprint identifier for the current virtual machine.
    This fingerprint is used to bind licenses to specific machines.
    
    Returns:
        FingerprintResponse: Object containing the VM fingerprint string
    """
    fingerprint = get_vm_fingerprint()
    return {"fingerprint": fingerprint}
