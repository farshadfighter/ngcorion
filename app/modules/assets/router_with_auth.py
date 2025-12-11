"""
Asset Management Routers with Authentication
All routes require JWT authentication
Admin-only routes are protected with require_admin dependency
"""
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from .schemas import (
    AssetTypeCreate, AssetTypeResponse,
    AssetCreate, AssetUpdate, AssetResponse,
    AssetOwnerCreate, AssetOwnerResponse,
    AssetLocationCreate, AssetLocationResponse,
    NetworkZoneCreate, NetworkZoneResponse,
    OSCatalogCreate, OSCatalogResponse,
    VendorCatalogCreate, VendorCatalogResponse,
    AssetDependencyCreate, AssetDependencyResponse,
    AssetSecurityStatusCreate, AssetSecurityStatusResponse,
    PaginatedResponse
)
from .service import AssetService
from app.core.dependencies import get_current_user, require_admin, require_admin_or_manager, require_permission
from app.models import User


# === Asset Types Router ===
asset_types_router = APIRouter(prefix="/api/asset-types", tags=["Asset Types"])


@asset_types_router.get("/", response_model=List[AssetTypeResponse])
def get_asset_types(
    _current_user: User = Depends(get_current_user),
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
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get asset type by id (authenticated users)"""
    asset_type = AssetService.get_asset_type(db, type_id)
    if not asset_type:
        raise HTTPException(status_code=404, detail="Asset type not found")
    return asset_type


@asset_types_router.put("/{type_id}", response_model=AssetTypeResponse)
def update_asset_type(
    type_id: int,
    data: AssetTypeCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update asset type (admin only)"""
    asset_type = AssetService.update_asset_type(db, type_id, data.model_dump())
    if not asset_type:
        raise HTTPException(status_code=404, detail="Asset type not found")
    return asset_type


@asset_types_router.delete("/{type_id}")
def delete_asset_type(
    type_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete asset type (admin only)"""
    if not AssetService.delete_asset_type(db, type_id):
        raise HTTPException(status_code=404, detail="Asset type not found")
    return {"message": "Deleted successfully"}


# === Assets Router ===
assets_router = APIRouter(prefix="/api/assets", tags=["Assets"])


@assets_router.get("/", response_model=List[AssetResponse])
def get_assets(
    page: Optional[int] = Query(None, ge=1, description="Page number (1-indexed)"),
    page_size: Optional[int] = Query(None, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(require_permission("ASSET_LIST", "read")),
    db: Session = Depends(get_db)
):
    """
    Get assets (permission-based access)

    Supports optional pagination via page and page_size query parameters.
    If pagination params are omitted, returns all results (backward compatible).
    Users with read permission for ASSET_LIST can see all assets.
    """
    from app.models import Asset

    # Build base query - no user_id filtering, permission-based access
    query = db.query(Asset)

    # If pagination requested, return paginated results
    if page is not None and page_size is not None:
        items, total, total_pages = AssetService.paginate_query(query, page, page_size)
        # Return as PaginatedResponse in header but List in response for backward compatibility
        return items

    # Return all results (backward compatible)
    return query.all()


@assets_router.post("/", response_model=AssetResponse)
def create_asset(
    data: AssetCreate,
    current_user: User = Depends(require_permission("ASSET_LIST", "write")),
    db: Session = Depends(get_db)
):
    """Create asset (requires write permission)"""
    asset_data = data.model_dump()
    # If user_id not provided, use current user
    if not asset_data.get('user_id'):
        asset_data['user_id'] = current_user.id
    return AssetService.create_asset(db, asset_data)


@assets_router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    current_user: User = Depends(require_permission("ASSET_LIST", "read")),
    db: Session = Depends(get_db)
):
    """Get asset by id (requires read permission)"""
    asset = AssetService.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return asset


@assets_router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    data: AssetUpdate,
    current_user: User = Depends(require_permission("ASSET_LIST", "write")),
    db: Session = Depends(get_db)
):
    """Update asset (requires write permission)"""
    asset = AssetService.update_asset(db, asset_id, data.dict(exclude_unset=True))
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@assets_router.delete("/{asset_id}")
def delete_asset(
    asset_id: int,
    current_user: User = Depends(require_permission("ASSET_LIST", "delete")),
    db: Session = Depends(get_db)
):
    """Delete asset (requires delete permission)"""
    if not AssetService.delete_asset(db, asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"message": "Deleted successfully"}


@assets_router.get("/export/excel")
def export_assets_excel(
    current_user: User = Depends(require_permission("ASSET_LIST", "read")),
    db: Session = Depends(get_db)
):
    """
    Export assets to Excel file (requires read permission)

    Returns all assets that the user has permission to access
    """
    from app.models import Asset
    from app.utils.excel_utils import export_assets_to_excel
    from datetime import datetime

    # Build query - permission-based access
    query = db.query(Asset)
    assets = query.all()

    # Generate Excel file
    excel_file = export_assets_to_excel(assets, include_data=True)

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"assets_export_{timestamp}.xlsx"

    # Return as downloadable file
    return StreamingResponse(
        excel_file,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@assets_router.get("/export/template")
def download_asset_template(
    _current_user: User = Depends(get_current_user)
):
    """
    Download empty Excel template for asset import

    Returns a template file with all required columns but no data
    """
    from app.utils.excel_utils import create_asset_template

    # Generate template
    excel_file = create_asset_template()

    # Return as downloadable file
    return StreamingResponse(
        excel_file,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=asset_import_template.xlsx"}
    )


@assets_router.post("/import/excel")
async def import_assets_excel(
    file: bytes = None,
    current_user: User = Depends(require_permission("ASSET_LIST", "write")),
    db: Session = Depends(get_db)
):
    """
    Import assets from Excel file

    Supports:
    - Adding new assets
    - Updating existing assets (matched by ID, asset_name, or IP)
    - Validation and error reporting

    **Request:** Upload Excel file as multipart/form-data with key 'file'

    **Returns:**
    - created: Number of new assets created
    - updated: Number of existing assets updated
    - skipped: Number of empty rows skipped
    - errors: List of error messages
    - details: Detailed results for each processed row
    """
    # This endpoint expects multipart/form-data
    # Redirect to the upload endpoint
    raise HTTPException(
        status_code=501,
        detail="Please use the /import/excel/upload endpoint instead"
    )


@assets_router.post("/import/excel/upload")
async def import_assets_excel_upload(
    file: UploadFile = File(...),
    current_user: User = Depends(require_admin_or_manager),
    db: Session = Depends(get_db)
):
    """
    Import assets from Excel file

    Supports:
    - Adding new assets
    - Updating existing assets (matched by ID, asset_name, or IP)
    - Validation and error reporting

    **Returns:**
    - created: Number of new assets created
    - updated: Number of existing assets updated
    - skipped: Number of empty rows skipped
    - errors: List of error messages
    - details: Detailed results for each processed row
    """
    from app.utils.excel_utils import import_assets_from_excel
    from io import BytesIO

    # Validate file type
    if not file.filename.endswith(('.xlsx', '.xls')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload an Excel file (.xlsx or .xls)"
        )

    try:
        # Read file content
        content = await file.read()
        file_buffer = BytesIO(content)

        # Import assets
        results = import_assets_from_excel(file_buffer, db, current_user)

        return {
            "status": "success",
            "created": results["created"],
            "updated": results["updated"],
            "skipped": results["skipped"],
            "errors": results["errors"],
            "details": results["details"],
            "message": f"Import completed: {results['created']} created, {results['updated']} updated, {results['skipped']} skipped, {len(results['errors'])} errors"
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Import failed: {str(e)}"
        )


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
    return AssetService.create_owner(db, data.model_dump(), user_id=current_user.id)


@owners_router.get("/{owner_id}", response_model=AssetOwnerResponse)
def get_owner(
    owner_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get owner by id"""
    owner = AssetService.get_owner(db, owner_id)
    if not owner:
        raise HTTPException(status_code=404, detail="Owner not found")
    
    if current_user.role.value != "admin" and owner.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return owner


@owners_router.put("/{owner_id}", response_model=AssetOwnerResponse)
def update_owner(
    owner_id: int,
    data: AssetOwnerCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update owner (admin only)"""
    owner = AssetService.update_owner(db, owner_id, data.model_dump())
    if not owner:
        raise HTTPException(status_code=404, detail="Owner not found")
    return owner


@owners_router.delete("/{owner_id}")
def delete_owner(
    owner_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete owner (admin only)"""
    if not AssetService.delete_owner(db, owner_id):
        raise HTTPException(status_code=404, detail="Owner not found")
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
    return AssetService.create_location(db, data.model_dump(), user_id=current_user.id)


@locations_router.get("/{location_id}", response_model=AssetLocationResponse)
def get_location(
    location_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get location by id"""
    location = AssetService.get_location(db, location_id)
    if not location:
        raise HTTPException(status_code=404, detail="Location not found")
    
    if current_user.role.value != "admin" and location.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return location


@locations_router.put("/{location_id}", response_model=AssetLocationResponse)
def update_location(
    location_id: int,
    data: AssetLocationCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update location (admin only)"""
    location = AssetService.update_location(db, location_id, data.model_dump())
    if not location:
        raise HTTPException(status_code=404, detail="Location not found")
    return location


@locations_router.delete("/{location_id}")
def delete_location(
    location_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete location (admin only)"""
    if not AssetService.delete_location(db, location_id):
        raise HTTPException(status_code=404, detail="Location not found")
    return {"message": "Deleted successfully"}


# === Zones Router ===
zones_router = APIRouter(prefix="/api/zones", tags=["Zones"])


@zones_router.get("/", response_model=List[NetworkZoneResponse])
def get_zones(
    _current_user: User = Depends(get_current_user),
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
    return AssetService.create_zone(db, data.model_dump())


@zones_router.delete("/{zone_id}")
def delete_zone(
    zone_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete zone (admin only)"""
    if not AssetService.delete_zone(db, zone_id):
        raise HTTPException(status_code=404, detail="Zone not found")
    return {"message": "Deleted successfully"}


# === OS Catalog Router ===
os_router = APIRouter(prefix="/api/os-catalog", tags=["OS Catalog"])


@os_router.get("/", response_model=List[OSCatalogResponse])
def get_os_catalog(
    _current_user: User = Depends(get_current_user),
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
    return AssetService.create_os(db, data.model_dump())


@os_router.delete("/{os_id}")
def delete_os(
    os_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete OS entry (admin only)"""
    if not AssetService.delete_os(db, os_id):
        raise HTTPException(status_code=404, detail="OS not found")
    return {"message": "Deleted successfully"}


# === Vendors Router ===
vendors_router = APIRouter(prefix="/api/vendors", tags=["Vendors"])


@vendors_router.get("/", response_model=List[VendorCatalogResponse])
def get_vendors(
    _current_user: User = Depends(get_current_user),
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
    return AssetService.create_vendor(db, data.model_dump())


@vendors_router.delete("/{vendor_id}")
def delete_vendor(
    vendor_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete vendor (admin only)"""
    if not AssetService.delete_vendor(db, vendor_id):
        raise HTTPException(status_code=404, detail="Vendor not found")
    return {"message": "Deleted successfully"}


# === Dependencies Router ===
dependencies_router = APIRouter(prefix="/api/dependencies", tags=["Dependencies"])


@dependencies_router.get("/asset/{asset_id}", response_model=List[AssetDependencyResponse])
def get_dependencies(
    asset_id: int,
    _current_user: User = Depends(get_current_user),
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
    return AssetService.create_dependency(db, data.model_dump())


@dependencies_router.delete("/{dep_id}")
def delete_dependency(
    dep_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete dependency (admin only)"""
    if not AssetService.delete_dependency(db, dep_id):
        raise HTTPException(status_code=404, detail="Dependency not found")
    return {"message": "Deleted successfully"}


# === Security Router ===
security_router = APIRouter(prefix="/api/security", tags=["Security"])


@security_router.get("/asset/{asset_id}", response_model=AssetSecurityStatusResponse)
def get_security(
    asset_id: int,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get security status"""
    status = AssetService.get_security_status(db, asset_id)
    if not status:
        raise HTTPException(status_code=404, detail="Security status not found")
    return status


@security_router.post("/", response_model=AssetSecurityStatusResponse)
def create_security(
    data: AssetSecurityStatusCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create security status (admin only)"""
    return AssetService.create_security_status(db, data.model_dump())


@security_router.put("/{status_id}", response_model=AssetSecurityStatusResponse)
def update_security(
    status_id: int,
    data: AssetSecurityStatusCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update security status (admin only)"""
    status = AssetService.update_security_status(db, status_id, data.model_dump())
    if not status:
        raise HTTPException(status_code=404, detail="Security status not found")
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


# === Asset Requirements Import/Export Router ===
requirements_router = APIRouter(prefix="/api/asset-requirements", tags=["Asset Requirements"])


@requirements_router.get("/export/excel")
def export_requirements_excel(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Export all asset requirements to Excel file with multiple sheets

    Returns a single Excel file with sheets for:
    - Asset Types
    - Owners
    - Locations
    - Network Zones
    - OS Catalog
    - Vendors
    - Dependencies

    Admin sees all data, regular users see only their own data
    """
    from app.utils.excel_utils import export_asset_requirements_to_excel
    from datetime import datetime

    # Gather all data
    data_dict = {}

    # Asset Types (available to all users)
    data_dict["asset_types"] = AssetService.get_all_asset_types(db)

    # Owners (user-specific)
    if current_user.role.value == "admin":
        data_dict["owners"] = AssetService.get_all_owners(db)
    else:
        data_dict["owners"] = AssetService.get_user_owners(db, current_user.id)

    # Locations (user-specific)
    if current_user.role.value == "admin":
        data_dict["locations"] = AssetService.get_all_locations(db)
    else:
        data_dict["locations"] = AssetService.get_user_locations(db, current_user.id)

    # Network Zones (available to all users)
    data_dict["zones"] = AssetService.get_all_zones(db)

    # OS Catalog (available to all users)
    data_dict["os_catalog"] = AssetService.get_all_os(db)

    # Vendors (available to all users)
    data_dict["vendors"] = AssetService.get_all_vendors(db)

    # Dependencies (all)
    from app.models import AssetDependency
    data_dict["dependencies"] = db.query(AssetDependency).all()

    # Generate Excel file
    excel_file = export_asset_requirements_to_excel(data_dict)

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"asset_requirements_export_{timestamp}.xlsx"

    # Return as downloadable file
    return StreamingResponse(
        excel_file,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@requirements_router.get("/export/template")
def download_requirements_template(
    _current_user: User = Depends(get_current_user)
):
    """
    Download empty Excel template for asset requirements import

    Returns a template file with all required sheets and columns but no data
    """
    from app.utils.excel_utils import create_asset_requirements_template

    # Generate template
    excel_file = create_asset_requirements_template()

    # Return as downloadable file
    return StreamingResponse(
        excel_file,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=asset_requirements_template.xlsx"}
    )


@requirements_router.post("/import/excel")
async def import_requirements_excel(
    file: UploadFile = File(...),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Import asset requirements from Excel file

    Supports importing:
    - Asset Types
    - Owners
    - Locations
    - Network Zones
    - OS Catalog
    - Vendors
    - Dependencies

    The Excel file should have separate sheets for each type of requirement.
    Supports both creating new items and updating existing ones (matched by ID or name).

    **Returns:**
    - Results for each sheet with counts of created, updated, and skipped items
    - List of errors if any occurred
    """
    from app.utils.excel_utils import import_asset_requirements_from_excel
    from io import BytesIO

    # Validate file type
    if not file.filename.endswith(('.xlsx', '.xls')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload an Excel file (.xlsx or .xls)"
        )

    try:
        # Read file content
        content = await file.read()
        file_buffer = BytesIO(content)

        # Import requirements
        results = import_asset_requirements_from_excel(file_buffer, db, current_user)

        # Calculate totals
        total_created = sum(r["created"] for r in results.values())
        total_updated = sum(r["updated"] for r in results.values())
        total_skipped = sum(r["skipped"] for r in results.values())
        total_errors = sum(len(r["errors"]) for r in results.values())

        return {
            "status": "success",
            "summary": {
                "created": total_created,
                "updated": total_updated,
                "skipped": total_skipped,
                "errors": total_errors
            },
            "details": results,
            "message": f"Import completed: {total_created} created, {total_updated} updated, {total_skipped} skipped, {total_errors} errors"
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Import failed: {str(e)}"
        )