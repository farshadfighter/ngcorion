"""
Asset Management Routers with Authentication
All routes require JWT authentication
Admin-only routes are protected with require_admin dependency
"""
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


@asset_types_router.put("/{type_id}", response_model=AssetTypeResponse)
def update_asset_type(
    type_id: int,
    data: AssetTypeCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update asset type (admin only)"""
    asset_type = AssetService.get_asset_type(db, type_id)
    if not asset_type:
        raise HTTPException(404, "Asset type not found")
    
    asset_type.type_name = data.type_name
    asset_type.category = data.category
    asset_type.description = data.description
    db.commit()
    db.refresh(asset_type)
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
    return {"message": "Deleted successfully"}


# === Assets Router ===
assets_router = APIRouter(prefix="/api/assets", tags=["Assets"])


@assets_router.get("/", response_model=List[AssetResponse])
def get_assets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assets (admin sees all, user sees own)"""
    if current_user.role.value == "admin":
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
    asset_data = data.dict()
    # If user_id not provided, use current user
    if not asset_data.get('user_id'):
        asset_data['user_id'] = current_user.id
    return AssetService.create_asset(db, asset_data)


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
    if current_user.role.value != "admin" and asset.user_id != current_user.id:
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
    return {"message": "Deleted successfully"}


# === Owners Router ===
owners_router = APIRouter(prefix="/api/owners", tags=["Owners"])


@owners_router.get("/", response_model=List[AssetOwnerResponse])
def get_owners(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get owners for current user (admin sees all)"""
    if current_user.role.value == "admin":
        return AssetService.get_all_owners(db)
    else:
        return AssetService.get_user_owners(db, current_user.id)


@owners_router.post("/", response_model=AssetOwnerResponse)
def create_owner(
    data: AssetOwnerCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create owner (admin only) - uses current_user.id dynamically"""
    return AssetService.create_owner(db, data.dict(), user_id=current_user.id)


@owners_router.get("/{owner_id}", response_model=AssetOwnerResponse)
def get_owner(
    owner_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get owner by id"""
    owner = AssetService.get_owner(db, owner_id)
    if not owner:
        raise HTTPException(404, "Owner not found")
    
    if current_user.role.value != "admin" and owner.user_id != current_user.id:
        raise HTTPException(403, "Access denied")
    
    return owner


@owners_router.put("/{owner_id}", response_model=AssetOwnerResponse)
def update_owner(
    owner_id: int,
    data: AssetOwnerCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update owner (admin only)"""
    owner = AssetService.update_owner(db, owner_id, data.dict())
    if not owner:
        raise HTTPException(404, "Owner not found")
    return owner


@owners_router.delete("/{owner_id}")
def delete_owner(
    owner_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete owner (admin only)"""
    if not AssetService.delete_owner(db, owner_id):
        raise HTTPException(404, "Owner not found")
    return {"message": "Deleted successfully"}


# === Locations Router ===
locations_router = APIRouter(prefix="/api/locations", tags=["Locations"])


@locations_router.get("/", response_model=List[AssetLocationResponse])
def get_locations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get locations (admin sees all, user sees own)"""
    if current_user.role.value == "admin":
        return AssetService.get_all_locations(db)
    else:
        return AssetService.get_user_locations(db, current_user.id)


@locations_router.post("/", response_model=AssetLocationResponse)
def create_location(
    data: AssetLocationCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create location (admin only) - uses current_user.id dynamically"""
    return AssetService.create_location(db, data.dict(), user_id=current_user.id)


@locations_router.get("/{location_id}", response_model=AssetLocationResponse)
def get_location(
    location_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get location by id"""
    location = AssetService.get_location(db, location_id)
    if not location:
        raise HTTPException(404, "Location not found")
    
    if current_user.role.value != "admin" and location.user_id != current_user.id:
        raise HTTPException(403, "Access denied")
    
    return location


@locations_router.put("/{location_id}", response_model=AssetLocationResponse)
def update_location(
    location_id: int,
    data: AssetLocationCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update location (admin only)"""
    location = AssetService.update_location(db, location_id, data.dict())
    if not location:
        raise HTTPException(404, "Location not found")
    return location


@locations_router.delete("/{location_id}")
def delete_location(
    location_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete location (admin only)"""
    if not AssetService.delete_location(db, location_id):
        raise HTTPException(404, "Location not found")
    return {"message": "Deleted successfully"}


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


@zones_router.delete("/{zone_id}")
def delete_zone(
    zone_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete zone (admin only)"""
    if not AssetService.delete_zone(db, zone_id):
        raise HTTPException(404, "Zone not found")
    return {"message": "Deleted successfully"}


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


@os_router.delete("/{os_id}")
def delete_os(
    os_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete OS entry (admin only)"""
    if not AssetService.delete_os(db, os_id):
        raise HTTPException(404, "OS not found")
    return {"message": "Deleted successfully"}


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


@vendors_router.delete("/{vendor_id}")
def delete_vendor(
    vendor_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete vendor (admin only)"""
    if not AssetService.delete_vendor(db, vendor_id):
        raise HTTPException(404, "Vendor not found")
    return {"message": "Deleted successfully"}


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


@dependencies_router.delete("/{dep_id}")
def delete_dependency(
    dep_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete dependency (admin only)"""
    if not AssetService.delete_dependency(db, dep_id):
        raise HTTPException(404, "Dependency not found")
    return {"message": "Deleted successfully"}


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


@security_router.put("/{status_id}", response_model=AssetSecurityStatusResponse)
def update_security(
    status_id: int,
    data: AssetSecurityStatusCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update security status (admin only)"""
    status = AssetService.update_security_status(db, status_id, data.dict())
    if not status:
        raise HTTPException(404, "Security status not found")
    return status


# === Asset Views Router ===
views_router = APIRouter(prefix="/api/asset-views", tags=["Asset Views"])


@views_router.get("/overview")
def get_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get overview view"""
    if current_user.role.value == "admin":
        return AssetService.get_assets_overview(db)
    else:
        return AssetService.get_assets_overview(db, current_user.id)


@views_router.get("/network-system")
def get_network_system(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get network & system view"""
    if current_user.role.value == "admin":
        return AssetService.get_assets_network_system(db)
    else:
        return AssetService.get_assets_network_system(db, current_user.id)


@views_router.get("/location-ownership")
def get_location_ownership(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get location & ownership view"""
    if current_user.role.value == "admin":
        return AssetService.get_assets_location_ownership(db)
    else:
        return AssetService.get_assets_location_ownership(db, current_user.id)


@views_router.get("/security-audit")
def get_security_audit(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get security/audit view"""
    if current_user.role.value == "admin":
        return AssetService.get_assets_security_audit(db)
    else:
        return AssetService.get_assets_security_audit(db, current_user.id)