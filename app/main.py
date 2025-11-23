"""
Netease - Main Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware # Allow permison of diferent domains

from app.core.database import Base, engine # DB connection
from app.modules.auth import router as auth_router # auth router
from app.modules.logs import router as logs_router # logs router
from app.modules.users import router as users_router # users router

# Create database table
Base.metadata.create_all(bind=engine)

# Create app
app = FastAPI(title="Netease Asset Manager")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], #Allow permision of all domains #CHANGE BEFORE DEVELOPE#
    allow_credentials=True,
    allow_methods=["*"], #Allow all methods like : [POST , GET , PUT , DELETE]
    allow_headers=["*"], #Allow all heades
)

# Register routers
app.include_router(auth_router.router, prefix="/auth", tags=["Authentication"]) #authenticate
app.include_router(logs_router.router, prefix="/api/logs", tags=["Logs"])  #login/logs
app.include_router(users_router.router, prefix="/api/users", tags=["Users"]) #user_manager

@app.get("/")
def root():
    """
    return msg if app runnig well
    """
    return {"message": "Netease API is running"}

@app.get("/health")
def health_check():
    """
    for checking the health
    """
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
    
    # if run the app , server up in 8000 port