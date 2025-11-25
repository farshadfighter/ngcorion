from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from .schemas import *
from .service import AssetService

# === Asset Types Router ===
asset_types_router = APIRouter(prefix="/api/asset-types", tags=["Asset Types"])

@asset_types_router.get("/", response_model=List[AssetTypeResponse])
def get_asset_types(db: Session = Depends(get_db)):
    return AssetService.get_all_asset_types(db)

@asset_types_router.post("/", response_model=AssetTypeResponse)
def create_asset_type(data: AssetTypeCreate, db: Session = Depends(get_db)):
    return AssetService.create_asset_type(db, data)

@asset_types_router.get("/{type_id}", response_model=AssetTypeResponse)
def get_asset_type(type_id: int, db: Session = Depends(get_db)):
    asset_type = AssetService.get_asset_type(db, type_id)
    if not asset_type:
        raise HTTPException(404, "Asset type not found")
    return asset_type

@asset_types_router.delete("/{type_id}")
def delete_asset_type(type_id: int, db: Session = Depends(get_db)):
    if not AssetService.delete_asset_type(db, type_id):
        raise HTTPException(404, "Asset type not found")
    return {"message": "Deleted"}

# === Assets Router ===
assets_router = APIRouter(prefix="/api/assets", tags=["Assets"])

@assets_router.get("/", response_model=List[AssetResponse])
def get_assets(db: Session = Depends(get_db)):
    return AssetService.get_all_assets(db)

@assets_router.post("/", response_model=AssetResponse)
def create_asset(data: AssetCreate, db: Session = Depends(get_db)):
    return AssetService.create_asset(db, data.dict())

@assets_router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = AssetService.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset

@assets_router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(asset_id: int, data: AssetUpdate, db: Session = Depends(get_db)):
    asset = AssetService.update_asset(db, asset_id, data.dict(exclude_unset=True))
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset

@assets_router.delete("/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    if not AssetService.delete_asset(db, asset_id):
        raise HTTPException(404, "Asset not found")
    return {"message": "Deleted"}

# === Owners Router ===
owners_router = APIRouter(prefix="/api/owners", tags=["Owners"])

@owners_router.post("/", response_model=AssetOwnerResponse)
def create_owner(data: AssetOwnerCreate, db: Session = Depends(get_db)):
    return AssetService.create_owner(db, data.dict(), user_id=1)

# === Locations Router ===
locations_router = APIRouter(prefix="/api/locations", tags=["Locations"])

@locations_router.post("/", response_model=AssetLocationResponse)
def create_location(data: AssetLocationCreate, db: Session = Depends(get_db)):
    return AssetService.create_location(db, data.dict(), user_id=1)

# === Zones Router ===
zones_router = APIRouter(prefix="/api/zones", tags=["Zones"])

@zones_router.get("/", response_model=List[NetworkZoneResponse])
def get_zones(db: Session = Depends(get_db)):
    return AssetService.get_all_zones(db)

@zones_router.post("/", response_model=NetworkZoneResponse)
def create_zone(data: NetworkZoneCreate, db: Session = Depends(get_db)):
    return AssetService.create_zone(db, data.dict())

# === OS Catalog Router ===
os_router = APIRouter(prefix="/api/os-catalog", tags=["OS Catalog"])

@os_router.get("/", response_model=List[OSCatalogResponse])
def get_os_catalog(db: Session = Depends(get_db)):
    return AssetService.get_all_os(db)

@os_router.post("/", response_model=OSCatalogResponse)
def create_os(data: OSCatalogCreate, db: Session = Depends(get_db)):
    return AssetService.create_os(db, data.dict())

# === Vendors Router ===
vendors_router = APIRouter(prefix="/api/vendors", tags=["Vendors"])

@vendors_router.get("/", response_model=List[VendorCatalogResponse])
def get_vendors(db: Session = Depends(get_db)):
    return AssetService.get_all_vendors(db)

@vendors_router.post("/", response_model=VendorCatalogResponse)
def create_vendor(data: VendorCatalogCreate, db: Session = Depends(get_db)):
    return AssetService.create_vendor(db, data.dict())

# === Dependencies Router ===
dependencies_router = APIRouter(prefix="/api/dependencies", tags=["Dependencies"])

@dependencies_router.get("/asset/{asset_id}", response_model=List[AssetDependencyResponse])
def get_dependencies(asset_id: int, db: Session = Depends(get_db)):
    return AssetService.get_asset_dependencies(db, asset_id)

@dependencies_router.post("/", response_model=AssetDependencyResponse)
def create_dependency(data: AssetDependencyCreate, db: Session = Depends(get_db)):
    return AssetService.create_dependency(db, data.dict())

# === Security Router ===
security_router = APIRouter(prefix="/api/security", tags=["Security"])

@security_router.get("/asset/{asset_id}", response_model=AssetSecurityStatusResponse)
def get_security(asset_id: int, db: Session = Depends(get_db)):
    status = AssetService.get_security_status(db, asset_id)
    if not status:
        raise HTTPException(404, "Security status not found")
    return status

@security_router.post("/", response_model=AssetSecurityStatusResponse)
def create_security(data: AssetSecurityStatusCreate, db: Session = Depends(get_db)):
    return AssetService.create_security_status(db, data.dict())

views_router = APIRouter(prefix="/api/asset-views", tags=["Asset Views"])

@views_router.get("/overview")
def get_overview(db: Session = Depends(get_db)):
    return AssetService.get_assets_overview(db)

@views_router.get("/network-system")
def get_network_system(db: Session = Depends(get_db)):
    return AssetService.get_assets_network_system(db)

@views_router.get("/location-ownership")
def get_location_ownership(db: Session = Depends(get_db)):
    return AssetService.get_assets_location_ownership(db)

@views_router.get("/security-audit")
def get_security_audit(db: Session = Depends(get_db)):
    return AssetService.get_assets_security_audit(db)