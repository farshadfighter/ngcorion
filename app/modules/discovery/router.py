"""
NGCORION - Auto Discovery Router
app/modules/discovery/router.py

API endpoints for network scanning and asset discovery
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User, UserRole
from app.models.asset import Asset
from app.modules.users.service import UserService

from .schemas import (
    ScanRequest, ScanResponse,
    ApplyDiscoveryRequest, ApplyDiscoveryResponse,
    AssetMatchResponse, CreateAssetFromDiscoveryRequest,
    DiscoveredHost, PendingHostsListResponse, PendingHostResponse,
    AddPortsRequest, OverwritePortsRequest, PortManagementResponse
)
from .service import DiscoveryService
from .port_service import PortService


router = APIRouter(
    prefix="/api/discovery",
    tags=["Auto Discovery"]
)


# ====================================
# Permission Check Helper
# ====================================

def check_discovery_permission(current_user: User, action: str, db: Session):
    """
    Check if current user can perform action on asset_auto_discovery module

    Admin: Always allowed
    Others: Check permission table
    """
    # Admin has all permissions
    if current_user.role == UserRole.ADMIN:
        return True

    service_obj = UserService(db)
    has_permission = service_obj.check_permission(
        user_id=current_user.id,
        module="asset_auto_discovery",
        action=action
    )

    if not has_permission:
        raise HTTPException(
            status_code=403,
            detail=f"You don't have {action} permission for Asset Auto Discovery"
        )

    return True


# ====================================
# Scan Endpoints
# ====================================

@router.post("/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Start a new network scan

    **Parameters:**
    - **target**: IP address or range
        - Single IP: `192.168.1.1`
        - CIDR range: `192.168.1.0/24`
        - IP range: `192.168.1.1-254`
    - **scan_type**: Scan intensity
        - `basic`: Quick scan, ~30 seconds
        - `detailed`: Service + OS detection, ~2-3 minutes
        - `full`: All ports, ~10+ minutes

    **Returns:**
    Scan object with `scan_id` to poll for results

    **Permissions:** Requires write permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "write", db)

    try:
        scan = await DiscoveryService.start_scan(db, request, current_user.id)
        return scan
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start scan: {str(e)}"
        )


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get status and results of a scan

    Poll this endpoint to check scan progress.
    When `status` is `completed`, the `hosts` array contains results.
    """
    scan = DiscoveryService.get_scan_status(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans", response_model=List[ScanResponse])
async def get_all_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all recent scans (last 20)

    **Permissions:** Requires read permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "read", db)
    return DiscoveryService.get_all_scans(db)


@router.delete("/scan/{scan_id}")
async def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a scan from history

    **Permissions:** Requires delete permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "delete", db)

    if DiscoveryService.delete_scan(db, scan_id):
        return {"message": "Scan deleted"}
    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/pending", response_model=PendingHostsListResponse)
async def get_pending_hosts(
    scan_id: str = Query(None, description="Filter by specific scan ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all discovered hosts pending approval

    Returns hosts that have been discovered but not yet approved or rejected.
    These are candidates for asset creation or merging.

    **Permissions:** Requires read permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "read", db)

    # Get pending hosts (filter by user if not admin)
    user_id = None if current_user.role == UserRole.ADMIN else current_user.id
    pending_hosts = DiscoveryService.get_pending_hosts(db, scan_id=scan_id, user_id=user_id)

    # Convert to response format
    pending_list = []
    for host in pending_hosts:
        pending_list.append({
            "id": host.id,
            "scan_id": host.scan_id,
            "ip_address": host.ip_address,
            "mac_address": host.mac_address,
            "hostname": host.hostname,
            "os_info": host.os_info,
            "os_accuracy": host.os_accuracy,
            "open_ports": host.open_ports or [],
            "status": host.status,
            "state": host.state,
            "discovered_at": host.discovered_at,
            "matched_asset_id": host.matched_asset_id,
            "highlight": True
        })

    return {
        "total": len(pending_list),
        "pending": pending_list
    }


# ====================================
# Asset Matching
# ====================================

@router.get("/match/{ip_address}", response_model=AssetMatchResponse)
async def find_matching_asset(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Check if a discovered IP matches an existing asset
    
    Use this to determine whether to update an existing asset
    or create a new one.
    
    **Returns:**
    - `found`: Whether asset exists
    - `empty_fields`: Fields that can be filled by discovery
    - `current_values`: Current values in asset
    """
    # Check user's assets only
    query = db.query(Asset).filter(Asset.ip_address == ip_address)
    
    # Non-admin users only see their own assets
    if current_user.role != 'admin':
        query = query.filter(Asset.user_id == current_user.id)
    
    asset = query.first()
    
    if asset:
        # List of fields that can be auto-filled
        discoverable_fields = [
            'hostname', 'mac_address', 'os_name', 
            'os_version', 'manufacturer'
        ]
        
        empty_fields = []
        current_values = {}
        
        for field in discoverable_fields:
            value = getattr(asset, field, None)
            current_values[field] = value
            if not value:
                empty_fields.append(field)
        
        return AssetMatchResponse(
            found=True,
            asset_id=asset.id,
            asset_name=asset.asset_name,
            empty_fields=empty_fields,
            current_values=current_values
        )
    
    return AssetMatchResponse(found=False)


# ====================================
# Apply Discovery to Asset
# ====================================

@router.post("/apply", response_model=ApplyDiscoveryResponse)
async def apply_discovery_to_asset(
    request: ApplyDiscoveryRequest,
    scan_id: str = Query(..., description="Scan ID to get discovered data from"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Apply discovered data to an existing asset

    **Only updates empty fields!**
    If a field already has data, it will be skipped.

    **Parameters:**
    - **asset_id**: Target asset ID
    - **ip_address**: IP of discovered host (to get data from scan)
    - **fields_to_apply**: List of fields to update
    - **scan_id**: Query param - which scan results to use

    **Marks fields with `discovered_fields` JSON for frontend highlighting**

    **Permissions:** Requires write permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "write", db)
    
    # Get asset
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Check ownership
    if current_user.role != 'admin' and asset.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your asset")
    
    # Get discovered host from scan
    discovered_host = DiscoveryService.get_discovered_host_by_ip(db, scan_id, request.ip_address)
    if not discovered_host:
        raise HTTPException(
            status_code=404,
            detail=f"Host {request.ip_address} not found in scan {scan_id}"
        )
    
    # Mapping: discovered field → asset field
    field_mapping = {
        'hostname': 'hostname',
        'ip_address': 'ip_address',
        'mac_address': 'mac_address',
        'os_name': 'os_name',
        'os_version': 'os_version',
        'vendor': 'manufacturer',
    }
    
    updated_fields = []
    skipped_fields = []
    
    # Get current discovered_fields or initialize
    discovered_fields = asset.discovered_fields or {}
    
    for field in request.fields_to_apply:
        if field not in field_mapping:
            continue
        
        asset_field = field_mapping[field]
        discovered_value = getattr(discovered_host, field, None)
        current_value = getattr(asset, asset_field, None)
        
        # Only update if current is empty AND discovered has value
        if discovered_value and not current_value:
            setattr(asset, asset_field, discovered_value)
            discovered_fields[asset_field] = True  # Mark as discovered
            updated_fields.append(asset_field)
        elif current_value:
            skipped_fields.append(f"{asset_field} (already has data)")
    
    # Save discovered_fields marker
    asset.discovered_fields = discovered_fields
    
    db.commit()
    
    return ApplyDiscoveryResponse(
        asset_id=request.asset_id,
        updated_fields=updated_fields,
        skipped_fields=skipped_fields,
        message=f"Updated {len(updated_fields)} fields, skipped {len(skipped_fields)}"
    )


# ====================================
# Create Asset from Discovery
# ====================================

@router.post("/create-asset")
async def create_asset_from_discovery(
    request: CreateAssetFromDiscoveryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new asset from discovered host data

    **User must provide:**
    - `asset_name`: Name for the new asset
    - `asset_type_id`: Asset type ID
    - `discovered_host`: The discovered host data

    **Auto-filled from discovery:**
    - hostname, ip_address, mac_address
    - os_name, os_version, manufacturer

    **Permissions:** Requires write permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "write", db)
    
    host = request.discovered_host
    
    # Check if IP already exists
    existing = db.query(Asset).filter(
        Asset.ip_address == host.ip_address,
        Asset.user_id == current_user.id
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Asset with IP {host.ip_address} already exists (ID: {existing.id})"
        )
    
    # Mark all auto-filled fields
    discovered_fields = {}
    if host.hostname:
        discovered_fields['hostname'] = True
    if host.mac_address:
        discovered_fields['mac_address'] = True
    if host.os_name:
        discovered_fields['os_name'] = True
    if host.os_version:
        discovered_fields['os_version'] = True
    if host.vendor:
        discovered_fields['manufacturer'] = True
    
    # Create asset
    asset = Asset(
        asset_name=request.asset_name,
        hostname=host.hostname,
        ip_address=host.ip_address,
        mac_address=host.mac_address,
        os_name=host.os_name,
        os_version=host.os_version,
        manufacturer=host.vendor,
        asset_type_id=request.asset_type_id,
        user_id=current_user.id,
        discovered_fields=discovered_fields
    )
    
    db.add(asset)
    db.commit()
    db.refresh(asset)
    
    return {
        "message": "Asset created from discovery",
        "asset_id": asset.id,
        "asset_name": asset.asset_name,
        "discovered_fields": list(discovered_fields.keys())
    }


# ====================================
# Bulk Operations
# ====================================

@router.post("/apply-bulk")
async def apply_discovery_bulk(
    scan_id: str = Query(..., description="Scan ID to get discovered data from"),
    asset_mappings: List[Dict[str, Any]] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Apply discovery results to multiple assets at once

    **Request body:**
    ```json
    [
        {"asset_id": 1, "ip_address": "192.168.1.10", "fields": ["hostname", "os_name"]},
        {"asset_id": 2, "ip_address": "192.168.1.20", "fields": ["mac_address"]}
    ]
    ```

    **Permissions:** Requires write permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "write", db)
    
    results = []
    
    for mapping in asset_mappings:
        try:
            request = ApplyDiscoveryRequest(
                asset_id=mapping['asset_id'],
                ip_address=mapping['ip_address'],
                fields_to_apply=mapping.get('fields', [])
            )
            
            # Reuse single apply logic
            result = await apply_discovery_to_asset(
                request=request,
                scan_id=scan_id,
                db=db,
                current_user=current_user
            )
            results.append({
                "asset_id": mapping['asset_id'],
                "status": "success",
                "updated": result.updated_fields
            })
            
        except Exception as e:
            results.append({
                "asset_id": mapping.get('asset_id'),
                "status": "error",
                "error": str(e)
            })
    
    return {
        "total": len(asset_mappings),
        "results": results
    }


# ====================================
# Port Management Endpoints
# ====================================

@router.post("/ports/add", response_model=PortManagementResponse)
async def add_ports_to_asset(
    request: AddPortsRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Add new ports to an asset (non-destructive)

    Only adds ports that don't already exist for the asset.
    This is useful when you want to add newly discovered ports without affecting existing ones.
    """
    # Check permission
    check_discovery_permission(current_user, "edit", db)

    # Verify asset belongs to user (if not admin)
    if current_user.role != UserRole.ADMIN:
        asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
        if not asset or asset.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to modify this asset")

    # Convert PortInfo objects to dictionaries
    ports_data = [
        {
            "port_number": port.port_number,
            "protocol": port.protocol,
            "service_name": port.service_name,
            "service_product": port.service_product,
            "service_version": port.service_version,
            "state": port.state
        }
        for port in request.ports
    ]

    result = PortService.add_ports(
        db=db,
        asset_id=request.asset_id,
        ports_data=ports_data,
        scan_id=request.scan_id
    )

    if not result["success"]:
        raise HTTPException(status_code=404, detail=result.get("error", "Failed to add ports"))

    return result


@router.post("/ports/overwrite", response_model=PortManagementResponse)
async def overwrite_asset_ports(
    request: OverwritePortsRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Overwrite all ports for an asset (destructive)

    Removes all existing ports and replaces them with the new ones.
    This is useful when you want the scan results to be the single source of truth for ports.
    """
    # Check permission
    check_discovery_permission(current_user, "edit", db)

    # Verify asset belongs to user (if not admin)
    if current_user.role != UserRole.ADMIN:
        asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
        if not asset or asset.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to modify this asset")

    # Convert PortInfo objects to dictionaries
    ports_data = [
        {
            "port_number": port.port_number,
            "protocol": port.protocol,
            "service_name": port.service_name,
            "service_product": port.service_product,
            "service_version": port.service_version,
            "state": port.state
        }
        for port in request.ports
    ]

    result = PortService.overwrite_ports(
        db=db,
        asset_id=request.asset_id,
        ports_data=ports_data,
        scan_id=request.scan_id
    )

    if not result["success"]:
        raise HTTPException(status_code=404, detail=result.get("error", "Failed to overwrite ports"))

    return result


@router.get("/assets/{asset_id}/ports")
async def get_asset_ports(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all ports for an asset
    """
    # Check permission
    check_discovery_permission(current_user, "view", db)

    # Verify asset belongs to user (if not admin)
    if current_user.role != UserRole.ADMIN:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset or asset.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to view this asset")

    ports = PortService.get_asset_ports(db, asset_id)
    return {"asset_id": asset_id, "ports": ports, "total": len(ports)}


@router.delete("/ports/{port_id}")
async def delete_port(
    port_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete a specific port
    """
    # Check permission
    check_discovery_permission(current_user, "delete", db)

    success = PortService.delete_port(db, port_id)
    if not success:
        raise HTTPException(status_code=404, detail="Port not found")

    return {"success": True, "message": "Port deleted successfully"}