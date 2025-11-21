"""
Netease - Main Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import Base, engine
from app.modules.auth import router as auth_router
from app.modules.logs import router as logs_router
from app.modules.users import router as users_router

# ساخت جداول
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Netease Asset Manager")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth_router.router, prefix="/auth", tags=["Authentication"]) #authenticate
app.include_router(logs_router.router, prefix="/api/logs", tags=["Logs"])  #login/logs
app.include_router(users_router.router, prefix="/api/users", tags=["Users"]) #user_manager

@app.get("/")
def root():
    return {"message": "Netease API is running"}

@app.get("/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)