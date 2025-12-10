"""
Discovery Service Layer
Handles all network discovery operations with database persistence
"""

import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.models import (
    DiscoveryScan,
    DiscoveredHost,
    Asset,
    DiscoveryApplication,
    User
)
from app.models.discovery import (
    log_scan_started,
    log_scan_completed,
    log_scan_failed,
    log_discovery_applied,
    log_asset_created
)
from .nmap_scanner import NmapScanner
from .schemas import ScanRequest

logger = logging.getLogger(__name__)


class DiscoveryService:
    """Service layer for asset discovery operations"""

    # ==========================================
    # Scan Management
    # ==========================================

    @staticmethod
    def create_scan(
        db: Session,
        user_id: int,
        target: str,
        scan_type: str = "well_known_ports",
        ports: Optional[str] = None,
        protocol: str = "TCP",
        job_name: Optional[str] = None
    ) -> DiscoveryScan:
        """
        Create a new scan record in database

        Args:
            db: Database session
            user_id: User initiating the scan
            target: IP address, CIDR, or range
            scan_type: all_ports, well_known_ports, or custom_ports
            ports: Port specification (required for custom_ports)
            protocol: TCP, UDP, or BOTH
            job_name: User-friendly name for the scan job

        Returns:
            DiscoveryScan object with pending status
        """
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())[:8].upper()

        # Generate job name in format: Scan-{random_number}-{ip}
        if not job_name:
            import random
            # Extract first IP from target for job name
            target_ip = target.split('/')[0].split('-')[0].strip()  # Handle CIDR and ranges
            random_num = str(random.randint(10, 99)).zfill(2)  # 2-digit random number (01-99)
            job_name = f"Scan-{random_num}-{target_ip}"

        # Create scan record
        scan = DiscoveryScan(
            scan_id=scan_id,
            job_name=job_name,
            user_id=user_id,
            target=target,
            scan_type=scan_type,
            ports=ports,
            protocol=protocol,
            status="pending",
            started_at=datetime.utcnow()
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Log audit trail
        log_scan_started(db, user_id, scan_id, target, scan_type)

        logger.info(f"Created scan {scan_id} ({job_name}) for target {target}")
        return scan

    @staticmethod
    def get_scan(db: Session, scan_id: str) -> Optional[DiscoveryScan]:
        """Get scan by ID"""
        return db.query(DiscoveryScan).filter(DiscoveryScan.scan_id == scan_id).first()

    @staticmethod
    def get_user_scans(
        db: Session,
        user_id: int,
        limit: int = 50
    ) -> List[DiscoveryScan]:
        """Get all scans for a user (most recent first)"""
        return (
            db.query(DiscoveryScan)
            .filter(DiscoveryScan.user_id == user_id)
            .order_by(DiscoveryScan.started_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_all_scans(
        db: Session,
        limit: int = 100
    ) -> List[DiscoveryScan]:
        """Get all scans (admin only, most recent first)"""
        return (
            db.query(DiscoveryScan)
            .order_by(DiscoveryScan.started_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def update_scan_status(
        db: Session,
        scan_id: str,
        status: str,
        error_message: Optional[str] = None
    ):
        """Update scan status"""
        scan = DiscoveryService.get_scan(db, scan_id)
        if scan:
            scan.status = status
            if error_message:
                scan.error_message = error_message
            if status in ["completed", "failed"]:
                scan.completed_at = datetime.utcnow()
            db.commit()

    # ==========================================
    # Scan Execution
    # ==========================================

    @staticmethod
    def execute_scan(db: Session, scan_id: str) -> Dict[str, Any]:
        """
        Execute the actual nmap scan

        This method should be called in a background task

        Returns:
            Dict with success status and details
        """
        scan = DiscoveryService.get_scan(db, scan_id)
        if not scan:
            return {"success": False, "error": "Scan not found"}

        try:
            # Update status to running
            scan.status = "running"
            scan.started_at = datetime.utcnow()
            db.commit()

            logger.info(f"Executing scan {scan_id}: {scan.target}")

            # Run nmap scan
            result = NmapScanner.scan_and_parse(
                target=scan.target,
                ports=scan.ports,
                protocol=scan.protocol,
                scan_type=scan.scan_type,
                timeout=600
            )

            if not result["success"]:
                # Scan failed
                scan.status = "failed"
                scan.error_message = result.get("error", "Unknown error")
                scan.completed_at = datetime.utcnow()
                db.commit()

                log_scan_failed(db, scan.user_id, scan_id, scan.error_message)
                return result

            # Process discovered hosts
            hosts_up = 0
            hosts_total = len(result["hosts"])

            for host_data in result["hosts"]:
                if host_data.get("state") == "up":
                    hosts_up += 1

                # Create DiscoveredHost record
                discovered_host = DiscoveredHost(
                    scan_id=scan_id,
                    ip_address=host_data["ip"],
                    mac_address=host_data.get("mac"),
                    hostname=host_data.get("hostname"),
                    os_info=host_data.get("os", {}).get("name"),
                    os_accuracy=host_data.get("os", {}).get("accuracy"),
                    open_ports=host_data.get("ports", []),
                    status="pending",
                    state=host_data.get("state", "unknown"),
                    discovery_source="nmap",
                    additional_info=host_data,
                    discovered_at=datetime.utcnow()
                )

                db.add(discovered_host)

            # Update scan record
            scan.status = "completed"
            scan.hosts_discovered = hosts_total
            scan.hosts_up = hosts_up
            scan.completed_at = datetime.utcnow()
            db.commit()

            log_scan_completed(db, scan.user_id, scan_id, hosts_up, hosts_total)

            logger.info(f"Scan {scan_id} completed: {hosts_up}/{hosts_total} hosts up")

            return {
                "success": True,
                "scan_id": scan_id,
                "hosts_discovered": hosts_total,
                "hosts_up": hosts_up
            }

        except Exception as e:
            logger.exception(f"Scan execution failed for {scan_id}")
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            db.commit()

            log_scan_failed(db, scan.user_id, scan_id, str(e))

            return {"success": False, "error": str(e)}

    # ==========================================
    # Discovered Hosts Management
    # ==========================================

    @staticmethod
    def get_pending_hosts(
        db: Session,
        scan_id: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> List[DiscoveredHost]:
        """
        Get all discovered hosts with pending status

        Args:
            db: Database session
            scan_id: Optional filter by scan
            user_id: Optional filter by user (via scan relationship)

        Returns:
            List of DiscoveredHost objects
        """
        query = db.query(DiscoveredHost).filter(DiscoveredHost.status == "pending")

        if scan_id:
            query = query.filter(DiscoveredHost.scan_id == scan_id)

        if user_id:
            # Join with DiscoveryScan to filter by user
            query = query.join(DiscoveryScan).filter(DiscoveryScan.user_id == user_id)

        return query.order_by(DiscoveredHost.discovered_at.desc()).all()

    @staticmethod
    def get_discovered_host(db: Session, host_id: int) -> Optional[DiscoveredHost]:
        """Get discovered host by ID"""
        return db.query(DiscoveredHost).filter(DiscoveredHost.id == host_id).first()

    @staticmethod
    def get_discovered_host_by_ip(
        db: Session,
        scan_id: str,
        ip_address: str
    ) -> Optional[DiscoveredHost]:
        """Get discovered host by scan ID and IP address"""
        return (
            db.query(DiscoveredHost)
            .filter(
                DiscoveredHost.scan_id == scan_id,
                DiscoveredHost.ip_address == ip_address
            )
            .first()
        )

    @staticmethod
    def reject_discovered_host(
        db: Session,
        host_id: int,
        user_id: int
    ) -> bool:
        """
        Reject a discovered host (mark as rejected)

        Args:
            db: Database session
            host_id: Discovered host ID
            user_id: User performing the action

        Returns:
            True if successful
        """
        host = DiscoveryService.get_discovered_host(db, host_id)
        if not host:
            return False

        host.status = "rejected"
        host.approved_by_user_id = user_id
        host.approved_at = datetime.utcnow()
        db.commit()

        logger.info(f"Host {host_id} ({host.ip_address}) rejected by user {user_id}")
        return True

    # ==========================================
    # Asset Matching
    # ==========================================

    @staticmethod
    def check_asset_matches(
        db: Session,
        host_id: int
    ) -> Dict[str, Any]:
        """
        Check if discovered host matches existing assets

        Matching criteria (in order of priority):
        1. MAC address (exact match)
        2. IP address (exact match)
        3. Hostname (exact or similar match)

        Returns:
            {
                "matches_found": bool,
                "matches": [
                    {
                        "asset_id": int,
                        "asset_name": str,
                        "match_criteria": str,
                        "match_confidence": str,
                        "current_data": dict,
                        "discovered_data": dict
                    }
                ],
                "recommendation": str  # merge, create_new, or review
            }
        """
        host = DiscoveryService.get_discovered_host(db, host_id)
        if not host:
            return {"matches_found": False, "matches": [], "recommendation": "create_new"}

        matches = []

        # 1. Check MAC address match
        if host.mac_address:
            mac_match = db.query(Asset).filter(Asset.mac_address == host.mac_address).first()
            if mac_match:
                matches.append({
                    "asset_id": mac_match.id,
                    "asset_name": mac_match.asset_name,
                    "match_criteria": "mac_address",
                    "match_confidence": "high",
                    "current_ip": mac_match.ip_address,
                    "discovered_ip": host.ip_address,
                    "asset": mac_match
                })

        # 2. Check IP address match
        if host.ip_address and not matches:  # Only if no MAC match
            ip_match = db.query(Asset).filter(Asset.ip_address == host.ip_address).first()
            if ip_match:
                matches.append({
                    "asset_id": ip_match.id,
                    "asset_name": ip_match.asset_name,
                    "match_criteria": "ip_address",
                    "match_confidence": "medium",
                    "current_mac": ip_match.mac_address,
                    "discovered_mac": host.mac_address,
                    "asset": ip_match
                })

        # 3. Check hostname match
        if host.hostname and not matches:  # Only if no other match
            hostname_match = db.query(Asset).filter(Asset.hostname == host.hostname).first()
            if hostname_match:
                matches.append({
                    "asset_id": hostname_match.id,
                    "asset_name": hostname_match.asset_name,
                    "match_criteria": "hostname",
                    "match_confidence": "medium",
                    "current_ip": hostname_match.ip_address,
                    "discovered_ip": host.ip_address,
                    "asset": hostname_match
                })

        # Determine recommendation
        recommendation = "create_new"
        if matches:
            if matches[0]["match_confidence"] == "high":
                recommendation = "merge"
            else:
                recommendation = "review"

        return {
            "matches_found": len(matches) > 0,
            "matches": matches,
            "recommendation": recommendation
        }

    # ==========================================
    # Asset Creation and Merging
    # ==========================================

    @staticmethod
    def approve_discovered_host(
        db: Session,
        host_id: int,
        user_id: int,
        action: str,
        asset_id: Optional[int] = None,
        asset_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Approve a discovered host and either create new asset or merge with existing

        Args:
            db: Database session
            host_id: Discovered host ID
            user_id: User approving
            action: "create_new" or "merge_with_existing"
            asset_id: Required if action is merge_with_existing
            asset_data: Additional data for new asset creation

        Returns:
            {
                "success": bool,
                "asset_id": int,
                "message": str,
                "fields_applied": List[str],
                "action_taken": str
            }
        """
        host = DiscoveryService.get_discovered_host(db, host_id)
        if not host:
            return {"success": False, "error": "Discovered host not found"}

        try:
            fields_applied = []

            if action == "create_new":
                # Create new asset from discovered data
                new_asset = Asset(
                    asset_name=asset_data.get("asset_name", f"Discovered-{host.ip_address}"),
                    asset_type_id=asset_data.get("asset_type_id"),
                    user_id=user_id,
                    ip_address=host.ip_address,
                    mac_address=host.mac_address,
                    hostname=host.hostname,
                    os_name=host.os_info,
                    location_id=asset_data.get("location_id"),
                    owner_id=asset_data.get("owner_id"),
                    status="ACTIVE",
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )

                db.add(new_asset)
                db.flush()  # Get the ID

                asset_id = new_asset.id
                action_taken = "created"
                fields_applied = ["ip_address", "mac_address", "hostname", "os_name"]

                log_asset_created(db, user_id, host.scan_id, asset_id, host.ip_address)

            elif action == "merge_with_existing":
                # Update existing asset (non-destructive)
                existing_asset = db.query(Asset).filter(Asset.id == asset_id).first()
                if not existing_asset:
                    return {"success": False, "error": "Asset not found"}

                # Only update empty fields (non-destructive merge)
                if not existing_asset.ip_address and host.ip_address:
                    existing_asset.ip_address = host.ip_address
                    fields_applied.append("ip_address")

                if not existing_asset.mac_address and host.mac_address:
                    existing_asset.mac_address = host.mac_address
                    fields_applied.append("mac_address")

                if not existing_asset.hostname and host.hostname:
                    existing_asset.hostname = host.hostname
                    fields_applied.append("hostname")

                if not existing_asset.os_name and host.os_info:
                    existing_asset.os_name = host.os_info
                    fields_applied.append("os_name")

                existing_asset.updated_at = datetime.utcnow()
                action_taken = "merged"

                log_discovery_applied(db, user_id, host.scan_id, asset_id,
                                    host.ip_address, {f: True for f in fields_applied})

            else:
                return {"success": False, "error": "Invalid action"}

            # Update discovered host status
            host.status = "approved"
            host.approved_by_user_id = user_id
            host.approved_at = datetime.utcnow()
            host.matched_asset_id = asset_id

            # Create DiscoveryApplication record
            application = DiscoveryApplication(
                scan_id=host.scan_id,
                asset_id=asset_id,
                applied_by_user_id=user_id,
                ip_address=host.ip_address,
                fields_applied={f: True for f in fields_applied},
                applied_at=datetime.utcnow()
            )
            db.add(application)

            db.commit()

            logger.info(f"Host {host_id} approved and {action_taken} to asset {asset_id}")

            return {
                "success": True,
                "asset_id": asset_id,
                "message": f"Asset {action_taken} successfully",
                "fields_applied": fields_applied,
                "action_taken": action_taken
            }

        except Exception as e:
            db.rollback()
            logger.exception(f"Failed to approve host {host_id}")
            return {"success": False, "error": str(e)}

    # ==========================================
    # Bulk Operations
    # ==========================================

    @staticmethod
    def bulk_approve_hosts(
        db: Session,
        host_ids: List[int],
        user_id: int,
        default_asset_type_id: int,
        default_location_id: Optional[int] = None,
        default_owner_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Approve multiple discovered hosts at once

        Creates new assets for all hosts with default values

        Returns:
            {
                "success": bool,
                "approved": int,
                "created_assets": List[int],
                "errors": List[dict]
            }
        """
        created_assets = []
        errors = []

        for host_id in host_ids:
            try:
                result = DiscoveryService.approve_discovered_host(
                    db=db,
                    host_id=host_id,
                    user_id=user_id,
                    action="create_new",
                    asset_data={
                        "asset_type_id": default_asset_type_id,
                        "location_id": default_location_id,
                        "owner_id": default_owner_id
                    }
                )

                if result["success"]:
                    created_assets.append(result["asset_id"])
                else:
                    errors.append({"host_id": host_id, "error": result.get("error")})

            except Exception as e:
                logger.exception(f"Failed to bulk approve host {host_id}")
                errors.append({"host_id": host_id, "error": str(e)})

        return {
            "success": len(errors) == 0,
            "approved": len(created_assets),
            "created_assets": created_assets,
            "errors": errors
        }

    # ==========================================
    # Statistics and Reports
    # ==========================================

    @staticmethod
    def get_discovery_stats(db: Session, user_id: Optional[int] = None) -> Dict[str, Any]:
        """Get discovery statistics"""
        query = db.query(DiscoveryScan)
        if user_id:
            query = query.filter(DiscoveryScan.user_id == user_id)

        total_scans = query.count()
        completed_scans = query.filter(DiscoveryScan.status == "completed").count()
        failed_scans = query.filter(DiscoveryScan.status == "failed").count()

        pending_hosts = db.query(DiscoveredHost).filter(DiscoveredHost.status == "pending").count()
        approved_hosts = db.query(DiscoveredHost).filter(DiscoveredHost.status == "approved").count()

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "pending_hosts": pending_hosts,
            "approved_hosts": approved_hosts
        }

    @staticmethod
    def delete_scan(db: Session, scan_id: str) -> bool:
        """
        Delete a scan and all associated discovered hosts

        Returns:
            True if scan was deleted, False if not found
        """
        scan = DiscoveryService.get_scan(db, scan_id)
        if not scan:
            return False

        # Delete associated discovered hosts
        db.query(DiscoveredHost).filter(DiscoveredHost.scan_id == scan_id).delete()

        # Delete scan
        db.delete(scan)
        db.commit()

        logger.info(f"Deleted scan {scan_id}")
        return True

    @staticmethod
    def get_scan_status(db: Session, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get scan status with discovered hosts in ScanResponse format

        Returns:
            Dict matching ScanResponse schema, or None if not found
        """
        scan = DiscoveryService.get_scan(db, scan_id)
        if not scan:
            return None

        # Get discovered hosts for this scan
        discovered_hosts = (
            db.query(DiscoveredHost)
            .filter(DiscoveredHost.scan_id == scan_id)
            .all()
        )

        # Convert discovered hosts to schema format
        hosts_list = []
        for host in discovered_hosts:
            host_dict = {
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "mac_address": host.mac_address,
                "vendor": None,  # TODO: Add vendor lookup
                "os_name": host.os_info,
                "os_version": None,
                "os_accuracy": host.os_accuracy,
                "ports": host.open_ports or [],
                "state": host.state or "unknown"
            }
            hosts_list.append(host_dict)

        return {
            "scan_id": scan.scan_id,
            "job_name": scan.job_name,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "hosts_up": scan.hosts_up or 0,
            "hosts_total": scan.hosts_discovered or 0,
            "hosts": hosts_list,
            "error": scan.error_message
        }

    @staticmethod
    async def start_scan(db: Session, request: ScanRequest, user_id: int) -> Dict[str, Any]:
        """
        Start a new scan (async)

        Creates scan record and executes scan in background

        Returns:
            Dict matching ScanResponse schema
        """
        # Create scan record
        scan = DiscoveryService.create_scan(
            db=db,
            user_id=user_id,
            target=request.target,
            scan_type=request.scan_type,
            ports=request.ports,
            protocol=request.protocol,
            job_name=request.job_name
        )

        # Execute scan in background (for now, run synchronously)
        # TODO: Use background task for proper async execution
        import asyncio
        from concurrent.futures import ThreadPoolExecutor

        def run_scan():
            return DiscoveryService.execute_scan(db, scan.scan_id)

        # Run scan in thread pool to avoid blocking
        with ThreadPoolExecutor() as executor:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(executor, run_scan)

        # Return scan status
        return DiscoveryService.get_scan_status(db, scan.scan_id)
