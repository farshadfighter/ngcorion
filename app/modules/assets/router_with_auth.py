from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from .schemas import *
from .service import AssetService
from app.core.dependencies import get_current_user, require_admin
from app.models import User

# === Asset Types Router ===
asset_types_router = APIRouter(prefix="/api/asset-types", tags=["Asset Types"])

@asset_types_router.get("/", response_model=List[AssetTypeResponse])
def get_asset_types(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all asset types (authenticated users)"""
    return AssetService.get_all_asset_types(db)

@asset_types_router.post("/", response_model=AssetTypeResponse)
def create_asset_type(
    data: AssetTypeCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create asset type (admin only)"""
    return AssetService.create_asset_type(db, data)

@asset_types_router.get("/{type_id}", response_model=AssetTypeResponse)
def get_asset_type(
    type_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get asset type by id (authenticated users)"""
    asset_type = AssetService.get_asset_type(db, type_id)
    if not asset_type:
        raise HTTPException(404, "Asset type not found")
    return asset_type

@asset_types_router.delete("/{type_id}")
def delete_asset_type(
    type_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete asset type (admin only)"""
    if not AssetService.delete_asset_type(db, type_id):
        raise HTTPException(404, "Asset type not found")
    return {"message": "Deleted"}

# === Assets Router ===
assets_router = APIRouter(prefix="/api/assets", tags=["Assets"])

@assets_router.get("/", response_model=List[AssetResponse])
def get_assets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assets (admin sees all, user sees own)"""
    if current_user.role == "admin":
        return AssetService.get_all_assets(db)
    else:
        return AssetService.get_user_assets(db, current_user.id)

@assets_router.post("/", response_model=AssetResponse)
def create_asset(
    data: AssetCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create asset (admin only)"""
    return AssetService.create_asset(db, data.dict())

@assets_router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get asset by id"""
    asset = AssetService.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    
    # Check permission: admin or owner
    if current_user.role != "admin" and asset.user_id != current_user.id:
        raise HTTPException(403, "Access denied")
    
    return asset

@assets_router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    data: AssetUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update asset (admin only)"""
    asset = AssetService.update_asset(db, asset_id, data.dict(exclude_unset=True))
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset

@assets_router.delete("/{asset_id}")
def delete_asset(
    asset_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete asset (admin only)"""
    if not AssetService.delete_asset(db, asset_id):
        raise HTTPException(404, "Asset not found")
    return {"message": "Deleted"}

# === Owners Router ===
owners_router = APIRouter(prefix="/api/owners", tags=["Owners"])

@owners_router.post("/", response_model=AssetOwnerResponse)
def create_owner(
    data: AssetOwnerCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create owner (admin only)"""
    return AssetService.create_owner(db, data.dict(), user_id=current_user.id)

# === Locations Router ===
locations_router = APIRouter(prefix="/api/locations", tags=["Locations"])

@locations_router.post("/", response_model=AssetLocationResponse)
def create_location(
    data: AssetLocationCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create location (admin only)"""
    return AssetService.create_location(db, data.dict(), user_id=current_user.id)

# === Zones Router ===
zones_router = APIRouter(prefix="/api/zones", tags=["Zones"])

@zones_router.get("/", response_model=List[NetworkZoneResponse])
def get_zones(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all zones (authenticated users)"""
    return AssetService.get_all_zones(db)

@zones_router.post("/", response_model=NetworkZoneResponse)
def create_zone(
    data: NetworkZoneCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create zone (admin only)"""
    return AssetService.create_zone(db, data.dict())

# === OS Catalog Router ===
os_router = APIRouter(prefix="/api/os-catalog", tags=["OS Catalog"])

@os_router.get("/", response_model=List[OSCatalogResponse])
def get_os_catalog(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get OS catalog (authenticated users)"""
    return AssetService.get_all_os(db)

@os_router.post("/", response_model=OSCatalogResponse)
def create_os(
    data: OSCatalogCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create OS entry (admin only)"""
    return AssetService.create_os(db, data.dict())

# === Vendors Router ===
vendors_router = APIRouter(prefix="/api/vendors", tags=["Vendors"])

@vendors_router.get("/", response_model=List[VendorCatalogResponse])
def get_vendors(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get vendors (authenticated users)"""
    return AssetService.get_all_vendors(db)

@vendors_router.post("/", response_model=VendorCatalogResponse)
def create_vendor(
    data: VendorCatalogCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create vendor (admin only)"""
    return AssetService.create_vendor(db, data.dict())

# === Dependencies Router ===
dependencies_router = APIRouter(prefix="/api/dependencies", tags=["Dependencies"])

@dependencies_router.get("/asset/{asset_id}", response_model=List[AssetDependencyResponse])
def get_dependencies(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get asset dependencies"""
    return AssetService.get_asset_dependencies(db, asset_id)

@dependencies_router.post("/", response_model=AssetDependencyResponse)
def create_dependency(
    data: AssetDependencyCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create dependency (admin only)"""
    return AssetService.create_dependency(db, data.dict())

# === Security Router ===
security_router = APIRouter(prefix="/api/security", tags=["Security"])

@security_router.get("/asset/{asset_id}", response_model=AssetSecurityStatusResponse)
def get_security(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get security status"""
    status = AssetService.get_security_status(db, asset_id)
    if not status:
        raise HTTPException(404, "Security status not found")
    return status

@security_router.post("/", response_model=AssetSecurityStatusResponse)
def create_security(
    data: AssetSecurityStatusCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create security status (admin only)"""
    return AssetService.create_security_status(db, data.dict())

# === Asset Views Router ===
views_router = APIRouter(prefix="/api/asset-views", tags=["Asset Views"])

@views_router.get("/overview")
def get_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get overview view"""
    if current_user.role == "admin":
        return AssetService.get_assets_overview(db)
    else:
        return AssetService.get_assets_overview(db, current_user.id)

@views_router.get("/network-system")
def get_network_system(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get network & system view"""
    if current_user.role == "admin":
        return AssetService.get_assets_network_system(db)
    else:
        return AssetService.get_assets_network_system(db, current_user.id)

@views_router.get("/location-ownership")
def get_location_ownership(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get location & ownership view"""
    if current_user.role == "admin":
        return AssetService.get_assets_location_ownership(db)
    else:
        return AssetService.get_assets_location_ownership(db, current_user.id)

@views_router.get("/security-audit")
def get_security_audit(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get security/audit view"""
    if current_user.role == "admin":
        return AssetService.get_assets_security_audit(db)
    else:
        return AssetService.get_assets_security_audit(db, current_user.id)