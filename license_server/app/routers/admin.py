from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import crud, schemas
from ..core.security import get_current_admin, create_access_token
from ..core.config import settings
from ..database import get_db
from pydantic import BaseModel
from datetime import timedelta

router = APIRouter(prefix="/api/admin", tags=["admin"])

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

@router.post("/login", response_model=TokenResponse)
def login(credentials: LoginRequest):
    """Admin login endpoint - returns JWT token"""
    if credentials.username != settings.ADMIN_USERNAME or credentials.password != settings.ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(
        data={"sub": credentials.username},
        expires_delta=timedelta(hours=settings.JWT_EXPIRE_HOURS)
    )
    return TokenResponse(access_token=access_token, token_type="bearer")

@router.post("/licenses", response_model=schemas.LicenseResponse)
def create_license(
    license_data: schemas.LicenseCreate,
    db: Session = Depends(get_db),
    admin: str = Depends(get_current_admin)
):
    return crud.create_license(db, license_data)

@router.get("/licenses", response_model=List[schemas.LicenseResponse])
def list_licenses(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: str = Depends(get_current_admin)
):
    return crud.get_all_licenses(db, skip, limit)

@router.get("/licenses/{license_key}", response_model=schemas.LicenseResponse)
def get_license(
    license_key: str,
    db: Session = Depends(get_db),
    admin: str = Depends(get_current_admin)
):
    license = crud.get_license_by_key(db, license_key)
    if not license:
        raise HTTPException(status_code=404, detail="License not found")
    return license

@router.delete("/licenses/{license_key}")
def deactivate_license(
    license_key: str,
    db: Session = Depends(get_db),
    admin: str = Depends(get_current_admin)
):
    success = crud.deactivate_license(db, license_key)
    if not success:
        raise HTTPException(status_code=404, detail="License not found")
    return {"message": "License deactivated successfully"}
