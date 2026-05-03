from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routers import licenses, admin
from .middleware.logging import LoggingMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .core.config import settings
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
