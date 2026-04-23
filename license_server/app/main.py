from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routers import licenses, admin
from .middleware.logging import LoggingMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .core.config import settings

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
