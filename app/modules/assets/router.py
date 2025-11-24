from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from .schemas import (
    AssetTypeResponse, AssetTypeCreate,
    AssetCreate, AssetResponse, AssetUpdate,
    AssetOwnerCreate, AssetOwnerResponse,
    AssetLocationCreate, AssetLocationResponse
)
from .service import AssetService

router = APIRouter(prefix="/asset-types", tags=["Asset Types"])


@router.get("/assets", response_model=List[AssetResponse])
def get_assets(db: Session = Depends(get_db)):
    """Get all assets"""
    return AssetService.get_all_assets(db)

@router.post("/assets", response_model=AssetResponse)
def create_asset(data: AssetCreate, db: Session = Depends(get_db)):
    """Create new asset"""
    return AssetService.create_asset(db, data.dict())

@router.get("/assets/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    """Get asset by id"""
    asset = AssetService.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset

@router.put("/assets/{asset_id}", response_model=AssetResponse)
def update_asset(asset_id: int, data: AssetUpdate, db: Session = Depends(get_db)):
    """Update asset"""
    asset = AssetService.update_asset(db, asset_id, data.dict(exclude_unset=True))
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset

@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    """Delete asset"""
    if not AssetService.delete_asset(db, asset_id):
        raise HTTPException(404, "Asset not found")
    return {"message": "Deleted"}

# ============================================
# Owner Endpoints
# ============================================

@router.post("/owners", response_model=AssetOwnerResponse)
def create_owner(data: AssetOwnerCreate, db: Session = Depends(get_db)):
    """Create asset owner"""
    return AssetService.create_owner(db, data.dict(), user_id=1)

# ============================================
# Location Endpoints
# ============================================

@router.post("/locations", response_model=AssetLocationResponse)
def create_location(data: AssetLocationCreate, db: Session = Depends(get_db)):
    """Create asset location"""
    return AssetService.create_location(db, data.dict(), user_id=1)

# ============================================
# Asset Types Endpoints (باید آخر باشن!)
# ============================================

@router.get("/", response_model=List[AssetTypeResponse])
def get_asset_types(db: Session = Depends(get_db)):
    """Get all asset types"""
    return AssetService.get_all_asset_types(db)

@router.post("/", response_model=AssetTypeResponse)
def create_asset_type(data: AssetTypeCreate, db: Session = Depends(get_db)):
    """Create new asset type"""
    return AssetService.create_asset_type(db, data)

@router.get("/{type_id}", response_model=AssetTypeResponse)
def get_asset_type(type_id: int, db: Session = Depends(get_db)):
    """Get asset type by id"""
    asset_type = AssetService.get_asset_type(db, type_id)
    if not asset_type:
        raise HTTPException(404, "Asset type not found")
    return asset_type

@router.delete("/{type_id}")
def delete_asset_type(type_id: int, db: Session = Depends(get_db)):
    """Delete asset type"""
    if not AssetService.delete_asset_type(db, type_id):
        raise HTTPException(404, "Asset type not found")
    return {"message": "Deleted"}