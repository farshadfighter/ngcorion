"""
NGCORION - Auto Discovery Router
app/modules/discovery/router.py

API endpoints for network scanning and asset discovery
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks , Request
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user, 
    require_quota ,
    check_quota_available ,
    consume_quota_on_success
    )

from app.models.user import User, UserRole
from app.models.asset import Asset
from app.models.discovery import DiscoveredHost as DiscoveredHostModel
from app.models import (
    log_scan_cancelled, 
    log_scan_deleted, 
    log_host_applied, 
    log_bulk_application_started, 
    log_bulk_application_completed, 
    log_discovery_preview
)
from app.modules.users.service import UserService

from .schemas import (
    ScanRequest, ScanResponse, ScanListItem,
    ApplyDiscoveryRequest, ApplyDiscoveryResponse,
    AssetMatchResponse, CreateAssetFromDiscoveryRequest,
    DiscoveredHost as DiscoveredHostSchema, DiscoveredPort,
    PendingHostsListResponse, PendingHostResponse,
    ApproveHostRequest, BulkApproveRequest,
    AddPortsRequest, OverwritePortsRequest, PortManagementResponse,
    ApplyDiscoveryMode, ApplyDiscoveryModeResponse, DiscoveryPreviewResponse
)
from .service import DiscoveryService
from .port_service import PortService


router = APIRouter(
    prefix="/api/discovery",
    tags=["Auto Discovery"]
)


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


@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(check_quota_available("discovery"))])
async def start_scan(
    http_request : Request,
    request: ScanResponse,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    
):
    """
    Start a new network scan

    **Parameters:**
    - **job_name**: User-friendly name for the scan (optional)
    - **target**: IP address or range
        - Single IP: `192.168.1.1`
        - CIDR range: `192.168.1.0/24`
        - IP range: `192.168.1.1-254`
    - **scan_type**: Port scan type
        - `all_ports`: Scans all 65535 ports (slowest, most thorough)
        - `well_known_ports`: Scans ports 1-1024 (default, balanced)
        - `custom_ports`: Scans specific ports (requires ports parameter)
    - **ports**: Port specification (required for custom_ports)
        - Single port: `80`
        - Port list: `80,443,8080`
        - Port range: `1-1000`
    - **protocol**: TCP, UDP, or BOTH (default: TCP)

    **Returns:**
    Scan object with `scan_id` and `job_name` to poll for results.
    Status will be `pending` — poll `GET /scan/{scan_id}` for progress.

    **Permissions:** Requires write permission for asset_auto_discovery module
    """
    consume_quota = consume_quota_on_success("discovery")
    check_discovery_permission(current_user, "write", db)

    try:
        scan_response = DiscoveryService.start_scan(db, request, current_user.id)
        scan_id = scan_response["scan_id"]

        # Run the actual nmap scan in the background so the HTTP response returns immediately
        background_tasks.add_task(DiscoveryService.execute_scan, db, scan_id)

        await consume_quota(http_request)

        return scan_response

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


@router.get("/scans", response_model=List[ScanListItem])
async def get_all_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all recent scans (last 100)

    Returns a lightweight list without full host data.
    Use `GET /scan/{scan_id}` to get full details including hosts.

    **Permissions:** Requires read permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "read", db)
    scans = DiscoveryService.get_all_scans(db)
    return [
        {
            "scan_id": scan.scan_id,
            "job_name": scan.job_name,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "hosts_up": scan.hosts_up or 0,
            "hosts_total": scan.hosts_discovered or 0,
            "error": scan.error_message,
        }
        for scan in scans
    ]


@router.post("/scan/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Cancel a running scan

    Terminates the nmap process and marks the scan as cancelled.
    Only works on scans with status 'pending' or 'running'.

    **Permissions:** Requires write permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "write", db)

    result = DiscoveryService.cancel_scan(db, scan_id)

    if result["success"]:
        # Log scan cancellation
        try:
            from app.models.discovery import DiscoveryScan
            scan = db.query(DiscoveryScan).filter(DiscoveryScan.scan_id == scan_id).first()
            if scan:
                log_scan_cancelled(db, current_user.id, scan_id, scan.target)
        except Exception as log_err:
            pass
        return result
    else:
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Failed to cancel scan")
        )


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

    # Get scan info before deletion for logging
    scan_target = ""
    try:
        from app.models.discovery import DiscoveryScan
        scan = db.query(DiscoveryScan).filter(DiscoveryScan.scan_id == scan_id).first()
        if scan:
            scan_target = scan.target
    except Exception:
        pass

    if DiscoveryService.delete_scan(db, scan_id):
        # Log scan deletion
        try:
            log_scan_deleted(db, current_user.id, scan_id, scan_target)
        except Exception as log_err:
            pass
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
        # Transform raw nmap port dicts to DiscoveredPort schema format
        raw_ports = host.open_ports or []
        transformed_ports = [
            {
                "port": p.get("port"),
                "protocol": p.get("protocol", "tcp"),
                "state": p.get("state", "open"),
                "service": p.get("service"),
                "product": p.get("product"),
                "version": p.get("version"),
                "ostype": p.get("ostype"),
            }
            for p in raw_ports
        ]

        pending_list.append({
            "id": host.id,
            "scan_id": host.scan_id,
            "ip_address": host.ip_address,
            "mac_address": host.mac_address,
            "hostname": host.hostname,
            "os_info": host.os_info,
            "os_accuracy": host.os_accuracy,
            "os_guessed": host.os_guessed,
            "open_ports": transformed_ports,
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


@router.get("/hosts/{host_id}/check-matches")
async def check_host_matches(
    host_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Check for matching assets for a discovered host

    Returns potential asset matches based on IP, MAC address, and hostname.
    Used by the "Check & Approve" workflow to find existing assets that might
    match the discovered host.

    **Permissions:** Requires read permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "read", db)

    # Get the discovered host
    host = db.query(DiscoveredHostModel).filter(DiscoveredHostModel.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Discovered host not found")

    # Find potential matching assets
    matches = []

    # Search by IP address (strongest match)
    if host.ip_address:
        ip_match = db.query(Asset).filter(
            Asset.ip_address == host.ip_address
        )
        if current_user.role != UserRole.ADMIN:
            ip_match = ip_match.filter(Asset.user_id == current_user.id)

        ip_asset = ip_match.first()
        if ip_asset:
            matches.append({
                "asset_id": ip_asset.id,
                "asset_name": ip_asset.asset_name,
                "match_type": "ip_address",
                "match_value": host.ip_address,
                "confidence": "high",
                "asset_type": ip_asset.asset_type.type_name if ip_asset.asset_type else None,
                "hostname": ip_asset.hostname,
                "mac_address": ip_asset.mac_address
            })

    # Search by MAC address (strong match)
    if host.mac_address and not matches:
        mac_match = db.query(Asset).filter(
            Asset.mac_address == host.mac_address
        )
        if current_user.role != UserRole.ADMIN:
            mac_match = mac_match.filter(Asset.user_id == current_user.id)

        mac_asset = mac_match.first()
        if mac_asset:
            matches.append({
                "asset_id": mac_asset.id,
                "asset_name": mac_asset.asset_name,
                "match_type": "mac_address",
                "match_value": host.mac_address,
                "confidence": "medium",
                "asset_type": mac_asset.asset_type.type_name if mac_asset.asset_type else None,
                "hostname": mac_asset.hostname,
                "ip_address": mac_asset.ip_address
            })

    # Search by hostname (weaker match)
    if host.hostname and not matches:
        hostname_match = db.query(Asset).filter(
            Asset.hostname == host.hostname
        )
        if current_user.role != UserRole.ADMIN:
            hostname_match = hostname_match.filter(Asset.user_id == current_user.id)

        hostname_asset = hostname_match.first()
        if hostname_asset:
            matches.append({
                "asset_id": hostname_asset.id,
                "asset_name": hostname_asset.asset_name,
                "match_type": "hostname",
                "match_value": host.hostname,
                "confidence": "low",
                "asset_type": hostname_asset.asset_type.type_name if hostname_asset.asset_type else None,
                "ip_address": hostname_asset.ip_address,
                "mac_address": hostname_asset.mac_address
            })

    return {
        "host_id": host_id,
        "discovered_host": {
            "ip_address": host.ip_address,
            "mac_address": host.mac_address,
            "hostname": host.hostname,
            "os_info": host.os_info,
            "os_guessed": host.os_guessed,  # OS guessed from service detection (-sV)
            "open_ports": host.open_ports
        },
        "matches": matches,
        "match_count": len(matches)
    }


@router.post("/hosts/{host_id}/approve")
async def approve_discovered_host(
    host_id: int,
    request_body: ApproveHostRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Approve a discovered host

    **Actions:**
    - `merge_with_existing`: Merge with existing asset (requires asset_id)
    - `create_new`: Create new asset (requires asset_data)
    - `skip`: Mark as reviewed but don't create/merge

    **Permissions:** Requires write permission for asset_auto_discovery module
    """

    check_discovery_permission(current_user, "write", db)

    # Get the discovered host
    host = db.query(DiscoveredHostModel).filter(DiscoveredHostModel.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Discovered host not found")

    # Extract parameters from validated request body
    action = request_body.action
    asset_id = request_body.asset_id
    asset_data = request_body.asset_data

    if action == "merge_with_existing":
        if not asset_id:
            raise HTTPException(status_code=400, detail="asset_id required for merge action")

        # Get the asset
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        # Check ownership
        if current_user.role != UserRole.ADMIN and asset.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to modify this asset")

        # Update asset with discovered data (only empty fields)
        updated_fields = []
        if host.hostname and not asset.hostname:
            asset.hostname = host.hostname
            updated_fields.append("hostname")
        if host.mac_address and not asset.mac_address:
            asset.mac_address = host.mac_address
            updated_fields.append("mac_address")
        if host.os_info and not asset.os_name:
            asset.os_name = host.os_info
            updated_fields.append("os_name")

        # Mark host as approved
        host.status = "merged"
        host.matched_asset_id = asset_id
        host.approved_by_user_id = current_user.id
        host.approved_at = datetime.now(timezone.utc)

        db.commit()

        return {
            "message": f"Host merged with asset {asset.asset_name}",
            "asset_id": asset_id,
            "action_taken": "merge_with_existing",
            "updated_fields": updated_fields
        }

    elif action == "create_new":
        if not asset_data:
            raise HTTPException(status_code=400, detail="asset_data required for create_new action")

        # Create new asset
        asset = Asset(
            asset_name=asset_data.get("asset_name"),
            hostname=host.hostname,
            ip_address=host.ip_address,
            mac_address=host.mac_address,
            os_name=host.os_info,
            asset_type_id=asset_data.get("asset_type_id"),
            user_id=current_user.id,
            discovered_fields={
                "hostname": True,
                "ip_address": True,
                "mac_address": True,
                "os_name": True
            }
        )

        db.add(asset)
        db.flush()  # Get the ID

        # Mark host as approved
        host.status = "approved"
        host.matched_asset_id = asset.id
        host.approved_by_user_id = current_user.id
        host.approved_at = datetime.now(timezone.utc)

        db.commit()

        return {
            "message": f"New asset created: {asset.asset_name}",
            "asset_id": asset.id,
            "action_taken": "create_new"
        }

    elif action == "skip":
        # Mark as reviewed but don't do anything
        host.status = "skipped"
        host.approved_by_user_id = current_user.id
        host.approved_at = datetime.now(timezone.utc)
        db.commit()

        return {
            "message": "Host marked as reviewed",
            "action_taken": "skip"
        }

    else:
        raise HTTPException(status_code=400, detail=f"Invalid action: {action}")


@router.post("/hosts/{host_id}/reject")
async def reject_discovered_host(
    host_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Reject a discovered host

    Marks the host as rejected and removes it from pending list.

    **Permissions:** Requires write permission for asset_auto_discovery module
    """

    check_discovery_permission(current_user, "write", db)

    # Get the discovered host
    host = db.query(DiscoveredHostModel).filter(DiscoveredHostModel.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Discovered host not found")

    # Mark as rejected
    host.status = "rejected"
    host.approved_by_user_id = current_user.id
    host.approved_at = datetime.now(timezone.utc)

    db.commit()

    return {
        "message": f"Host {host.ip_address} rejected",
        "host_id": host_id
    }


@router.post("/bulk-approve")
async def bulk_approve_hosts(
    request_body: BulkApproveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Bulk approve multiple discovered hosts

    Creates new assets for all specified hosts with default values.

    **Permissions:** Requires write permission for asset_auto_discovery module
    """

    check_discovery_permission(current_user, "write", db)

    host_ids = request_body.host_ids
    default_asset_type_id = request_body.default_asset_type_id
    default_location_id = request_body.default_location_id
    default_owner_id = request_body.default_owner_id

    created_assets = []
    errors = []

    for host_id in host_ids:
        try:
            host = db.query(DiscoveredHostModel).filter(DiscoveredHostModel.id == host_id).first()
            if not host:
                errors.append(f"Host {host_id} not found")
                continue

            # Create asset name from IP or hostname
            asset_name = host.hostname or f"Host-{host.ip_address}"

            # Create new asset
            asset = Asset(
                asset_name=asset_name,
                hostname=host.hostname,
                ip_address=host.ip_address,
                mac_address=host.mac_address,
                os_name=host.os_info,
                asset_type_id=default_asset_type_id,
                location_id=default_location_id,
                owner_id=default_owner_id,
                user_id=current_user.id,
                discovered_fields={
                    "hostname": True,
                    "ip_address": True,
                    "mac_address": True,
                    "os_name": True
                }
            )

            db.add(asset)
            db.flush()

            # Mark host as approved
            host.status = "approved"
            host.matched_asset_id = asset.id
            host.approved_by_user_id = current_user.id
            host.approved_at = datetime.now(timezone.utc)

            created_assets.append({
                "host_id": host_id,
                "asset_id": asset.id,
                "asset_name": asset_name
            })

        except Exception as e:
            errors.append(f"Host {host_id}: {str(e)}")

    db.commit()

    return {
        "message": f"Bulk approved {len(created_assets)} hosts",
        "approved": len(created_assets),
        "errors": errors if errors else None,
        "created_assets": created_assets
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
    if current_user.role != UserRole.ADMIN:
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
    if current_user.role != UserRole.ADMIN and asset.user_id != current_user.id:
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
    
    # Log bulk application start
    try:
        log_bulk_application_started(db, current_user.id, scan_id, len(asset_mappings))
    except Exception as log_err:
        pass
    
    results = []
    created_count = 0
    merged_count = 0
    updated_count = 0
    failed_count = 0
    
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
            updated_count += 1
            
        except Exception as e:
            results.append({
                "asset_id": mapping.get('asset_id'),
                "status": "error",
                "error": str(e)
            })
            failed_count += 1
    
    # Log bulk application completion
    try:
        log_bulk_application_completed(db, current_user.id, scan_id, created_count, merged_count, updated_count, failed_count)
    except Exception as log_err:
        pass
    
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
    check_discovery_permission(current_user, "write", db)

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
    check_discovery_permission(current_user, "write", db)

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
    check_discovery_permission(current_user, "read", db)

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

    # Add ownership verification
    from app.models import Port
    port = db.query(Port).filter(Port.id == port_id).first()
    if not port:
        raise HTTPException(status_code=404, detail="Port not found")

    # Non-admin users can only delete ports from assets they own
    if current_user.role != UserRole.ADMIN:
        asset = db.query(Asset).filter(Asset.id == port.asset_id).first()
        if not asset or asset.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to delete this port")

    success = PortService.delete_port(db, port_id)
    if not success:
        raise HTTPException(status_code=404, detail="Port not found")

    return {"success": True, "message": "Port deleted successfully"}


# ====================================
# Apply Discovery with Modes
# ====================================

@router.get("/hosts/{host_id}/preview")
async def preview_discovery_application(
    host_id: int,
    asset_id: int = Query(None, description="Asset ID to compare against"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Preview what changes will be made when applying discovery

    Returns the discovered data and optionally compares it with an existing asset
    to show what would change in each mode (overwrite, merge, create_new).

    **Permissions:** Requires read permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "read", db)

    # Get the discovered host
    host = db.query(DiscoveredHostModel).filter(DiscoveredHostModel.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Discovered host not found")

    # Build discovered data dict
    discovered_data = {
        "ip_address": host.ip_address,
        "hostname": host.hostname,
        "mac_address": host.mac_address,
        "os_info": host.os_info,
        "os_accuracy": host.os_accuracy,
        "os_guessed": host.os_guessed,  # OS guessed from service detection (-sV)
        "open_ports": host.open_ports or [],
        "state": host.state
    }

    response = {
        "host_id": host_id,
        "discovered_data": discovered_data,
        "discovered_ports_count": len(host.open_ports or []),
        "has_existing_data": False,
        "existing_ports_count": 0
    }

    # If asset_id provided, compare with existing asset
    if asset_id:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        # Check ownership
        if current_user.role != UserRole.ADMIN and asset.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to view this asset")

        # Get existing ports
        existing_ports = PortService.get_asset_ports(db, asset_id)

        existing_data = {
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "mac_address": asset.mac_address,
            "os_name": asset.os_name,
            "ports": existing_ports
        }

        response["asset_id"] = asset_id
        response["asset_name"] = asset.asset_name
        response["existing_data"] = existing_data
        response["existing_ports_count"] = len(existing_ports)
        response["has_existing_data"] = bool(
            asset.ip_address or asset.hostname or asset.mac_address or
            asset.os_name or existing_ports
        )

        # Calculate what would change in each mode
        overwrite_changes = {
            "fields_to_replace": [],
            "ports_to_remove": len(existing_ports),
            "ports_to_add": len(host.open_ports or [])
        }
        merge_changes = {
            "fields_to_fill": [],
            "ports_to_add": 0
        }

        # Check which fields would be overwritten/merged
        field_mapping = [
            ("hostname", "hostname"),
            ("mac_address", "mac_address"),
            ("os_info", "os_name")
        ]

        for discovered_field, asset_field in field_mapping:
            discovered_value = getattr(host, discovered_field, None)
            current_value = getattr(asset, asset_field, None)

            if discovered_value:
                if current_value:
                    overwrite_changes["fields_to_replace"].append({
                        "field": asset_field,
                        "current": current_value,
                        "new": discovered_value
                    })
                else:
                    merge_changes["fields_to_fill"].append({
                        "field": asset_field,
                        "value": discovered_value
                    })

        # Calculate new ports for merge mode
        existing_port_keys = set()
        for port in existing_ports:
            key = f"{port.get('port_number', port.get('port'))}:{port.get('protocol', 'tcp').upper()}"
            existing_port_keys.add(key)

        for port in (host.open_ports or []):
            key = f"{port.get('port')}:{port.get('protocol', 'tcp').upper()}"
            if key not in existing_port_keys:
                merge_changes["ports_to_add"] += 1

        response["overwrite_changes"] = overwrite_changes
        response["merge_changes"] = merge_changes

    # Log discovery preview
    try:
        log_discovery_preview(db, current_user.id, host.scan_id, host_id, host.ip_address)
    except Exception as log_err:
        pass

    return response


@router.post("/hosts/{host_id}/apply", response_model=ApplyDiscoveryModeResponse)
async def apply_discovery_with_mode(
    host_id: int,
    request: ApplyDiscoveryMode,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Apply discovery results with a specific mode

    **Modes:**
    - `overwrite`: Replace ALL existing data with discovered data (destructive)
        - Replaces hostname, MAC address, OS info
        - Removes all existing ports and adds discovered ports
    - `merge`: Keep existing data + add new discovered data (non-destructive)
        - Only fills empty fields (hostname, MAC, OS)
        - Adds new ports without removing existing ones
    - `create_new`: Create a new asset with the discovered data
        - Requires asset_name and asset_type_id

    **Permissions:** Requires write permission for asset_auto_discovery module
    """
    check_discovery_permission(current_user, "write", db)

    # Get the discovered host
    host = db.query(DiscoveredHostModel).filter(DiscoveredHostModel.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Discovered host not found")

    mode = request.mode

    if mode == "create_new":
        # Create new asset
        if not request.asset_name:
            raise HTTPException(status_code=400, detail="asset_name required for create_new mode")
        if not request.asset_type_id:
            raise HTTPException(status_code=400, detail="asset_type_id required for create_new mode")

        # Check if IP already exists for this user
        existing = db.query(Asset).filter(
            Asset.ip_address == host.ip_address,
            Asset.user_id == current_user.id
        ).first()

        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Asset with IP {host.ip_address} already exists (ID: {existing.id})"
            )

        # Create new asset
        asset = Asset(
            asset_name=request.asset_name,
            hostname=host.hostname,
            ip_address=host.ip_address,
            mac_address=host.mac_address,
            os_name=host.os_info,
            asset_type_id=request.asset_type_id,
            location_id=request.location_id,
            owner_id=request.owner_id,
            user_id=current_user.id,
            discovered_fields={
                "hostname": bool(host.hostname),
                "ip_address": bool(host.ip_address),
                "mac_address": bool(host.mac_address),
                "os_name": bool(host.os_info)
            }
        )

        db.add(asset)
        db.flush()  # Get the ID

        # Add discovered ports
        ports_added = 0
        if host.open_ports:
            ports_data = []
            for port in host.open_ports:
                ports_data.append({
                    "port_number": port.get("port"),
                    "protocol": port.get("protocol", "tcp").upper(),
                    "service_name": port.get("service"),
                    "service_product": port.get("product"),
                    "service_version": port.get("version"),
                    "state": port.get("state", "open")
                })
            if ports_data:
                result = PortService.add_ports(db, asset.id, ports_data, host.scan_id)
                ports_added = result.get("ports_added", 0)

        # Mark host as approved
        host.status = "approved"
        host.matched_asset_id = asset.id
        host.approved_by_user_id = current_user.id
        host.approved_at = datetime.now(timezone.utc)

        db.commit()

        fields_updated = []
        if host.hostname:
            fields_updated.append("hostname")
        if host.ip_address:
            fields_updated.append("ip_address")
        if host.mac_address:
            fields_updated.append("mac_address")
        if host.os_info:
            fields_updated.append("os_name")

        # Log host application
        try:
            log_host_applied(db, current_user.id, host.scan_id, host_id, host.ip_address, "create", asset.id, asset.asset_name)
        except Exception as log_err:
            pass

        return ApplyDiscoveryModeResponse(
            success=True,
            mode="create_new",
            asset_id=asset.id,
            asset_name=asset.asset_name,
            message=f"New asset '{asset.asset_name}' created from discovery",
            fields_updated=fields_updated,
            ports_added=ports_added
        )

    elif mode in ["overwrite", "merge"]:
        # Both modes require asset_id
        if not request.asset_id:
            raise HTTPException(status_code=400, detail="asset_id required for overwrite/merge mode")

        # Get the asset
        asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

        # Check ownership
        if current_user.role != UserRole.ADMIN and asset.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to modify this asset")

        # Store before state for response
        before_state = {
            "hostname": asset.hostname,
            "mac_address": asset.mac_address,
            "os_name": asset.os_name,
            "ip_address": asset.ip_address
        }

        fields_updated = []
        fields_overwritten = []
        discovered_fields = asset.discovered_fields or {}

        if mode == "overwrite":
            # Overwrite mode: Replace everything with discovered data

            # Update fields (even if they have data)
            if host.hostname:
                if asset.hostname and asset.hostname != host.hostname:
                    fields_overwritten.append("hostname")
                asset.hostname = host.hostname
                discovered_fields["hostname"] = True
                fields_updated.append("hostname")

            if host.mac_address:
                if asset.mac_address and asset.mac_address != host.mac_address:
                    fields_overwritten.append("mac_address")
                asset.mac_address = host.mac_address
                discovered_fields["mac_address"] = True
                fields_updated.append("mac_address")

            if host.os_info:
                if asset.os_name and asset.os_name != host.os_info:
                    fields_overwritten.append("os_name")
                asset.os_name = host.os_info
                discovered_fields["os_name"] = True
                fields_updated.append("os_name")

            # Overwrite ports - remove all existing and add discovered
            ports_removed = 0
            ports_added = 0
            if host.open_ports:
                ports_data = []
                for port in host.open_ports:
                    ports_data.append({
                        "port_number": port.get("port"),
                        "protocol": port.get("protocol", "tcp").upper(),
                        "service_name": port.get("service"),
                        "service_product": port.get("product"),
                        "service_version": port.get("version"),
                        "state": port.get("state", "open")
                    })
                result = PortService.overwrite_ports(db, asset.id, ports_data, host.scan_id)
                ports_removed = result.get("ports_removed", 0)
                ports_added = result.get("ports_added", 0)

        else:  # merge mode
            # Merge mode: Only fill empty fields and add new ports

            if host.hostname and not asset.hostname:
                asset.hostname = host.hostname
                discovered_fields["hostname"] = True
                fields_updated.append("hostname")

            if host.mac_address and not asset.mac_address:
                asset.mac_address = host.mac_address
                discovered_fields["mac_address"] = True
                fields_updated.append("mac_address")

            if host.os_info and not asset.os_name:
                asset.os_name = host.os_info
                discovered_fields["os_name"] = True
                fields_updated.append("os_name")

            # Merge ports - add only new ones
            ports_removed = 0
            ports_added = 0
            if host.open_ports:
                ports_data = []
                for port in host.open_ports:
                    ports_data.append({
                        "port_number": port.get("port"),
                        "protocol": port.get("protocol", "tcp").upper(),
                        "service_name": port.get("service"),
                        "service_product": port.get("product"),
                        "service_version": port.get("version"),
                        "state": port.get("state", "open")
                    })
                result = PortService.add_ports(db, asset.id, ports_data, host.scan_id)
                ports_added = result.get("ports_added", 0)

        # Update discovered_fields marker
        asset.discovered_fields = discovered_fields

        # Mark host as approved/merged
        host.status = "merged"
        host.matched_asset_id = asset.id
        host.approved_by_user_id = current_user.id
        host.approved_at = datetime.now(timezone.utc)

        db.commit()

        after_state = {
            "hostname": asset.hostname,
            "mac_address": asset.mac_address,
            "os_name": asset.os_name,
            "ip_address": asset.ip_address
        }

        mode_name = "Overwrite" if mode == "overwrite" else "Merge"
        
        # Log host application
        try:
            log_host_applied(db, current_user.id, host.scan_id, host_id, host.ip_address, mode, asset.id, asset.asset_name)
        except Exception as log_err:
            pass
        
        return ApplyDiscoveryModeResponse(
            success=True,
            mode=mode,
            asset_id=asset.id,
            asset_name=asset.asset_name,
            message=f"{mode_name} applied successfully to '{asset.asset_name}'",
            fields_updated=fields_updated,
            fields_overwritten=fields_overwritten,
            ports_added=ports_added,
            ports_removed=ports_removed,
            before=before_state,
            after=after_state
        )

    else:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {mode}")
