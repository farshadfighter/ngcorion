"""
Port Management Service

Handles adding and overwriting ports for assets discovered during scans.
"""

import logging
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models import Port, Protocol, Asset

logger = logging.getLogger(__name__)


class PortService:
    """Service for managing asset ports"""

    @staticmethod
    def get_protocol_by_name(db: Session, name: str) -> Protocol:
        """Get protocol by name, creating it if it doesn't exist"""
        protocol = db.query(Protocol).filter(Protocol.name == name.upper()).first()
        if not protocol:
            protocol = Protocol(name=name.upper(), description=f"{name.upper()} Protocol")
            db.add(protocol)
            db.commit()
            db.refresh(protocol)
        return protocol

    @staticmethod
    def add_ports(
        db: Session,
        asset_id: int,
        ports_data: List[Dict[str, Any]],
        scan_id: str = None
    ) -> Dict[str, Any]:
        """
        Add new ports to an asset (non-destructive)

        Only adds ports that don't already exist for the asset.

        Args:
            db: Database session
            asset_id: Asset ID
            ports_data: List of port dictionaries with:
                - port_number: int
                - protocol: str (TCP, UDP)
                - service_name: optional str
                - service_product: optional str
                - service_version: optional str
                - state: optional str
            scan_id: Optional scan ID that discovered these ports

        Returns:
            Dict with success status and count of ports added
        """
        from app.models import DiscoveryScan

        # Verify asset exists
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            return {"success": False, "error": "Asset not found"}

        # Validate scan_id exists if provided
        valid_scan_id = None
        if scan_id:
            scan = db.query(DiscoveryScan).filter(DiscoveryScan.scan_id == scan_id).first()
            if scan:
                valid_scan_id = scan_id
            else:
                logger.warning(f"Scan ID {scan_id} not found, setting to None")

        # Get existing ports for this asset
        existing_ports = db.query(Port).filter(Port.asset_id == asset_id).all()
        existing_port_tuples = {(p.port_number, p.protocol.name) for p in existing_ports}

        ports_added = 0

        for port_data in ports_data:
            port_number = port_data.get("port_number")
            protocol_name = port_data.get("protocol", "TCP").upper()

            # Check if port already exists
            if (port_number, protocol_name) in existing_port_tuples:
                logger.debug(f"Port {port_number}/{protocol_name} already exists for asset {asset_id}")
                continue

            # Get or create protocol
            protocol = PortService.get_protocol_by_name(db, protocol_name)

            # Create new port
            new_port = Port(
                asset_id=asset_id,
                port_number=port_number,
                protocol_id=protocol.id,
                service_name=port_data.get("service_name"),
                service_product=port_data.get("service_product"),
                service_version=port_data.get("service_version"),
                state=port_data.get("state", "open"),
                discovered_by_scan_id=valid_scan_id,
                is_active=True
            )

            db.add(new_port)
            ports_added += 1

        db.commit()

        logger.info(f"Added {ports_added} new ports to asset {asset_id}")

        return {
            "success": True,
            "asset_id": asset_id,
            "ports_added": ports_added,
            "ports_removed": 0,
            "message": f"Successfully added {ports_added} new port(s) to asset"
        }

    @staticmethod
    def overwrite_ports(
        db: Session,
        asset_id: int,
        ports_data: List[Dict[str, Any]],
        scan_id: str = None
    ) -> Dict[str, Any]:
        """
        Overwrite all ports for an asset (destructive)

        Removes all existing ports and replaces with new ones.

        Args:
            db: Database session
            asset_id: Asset ID
            ports_data: List of port dictionaries (same format as add_ports)
            scan_id: Optional scan ID that discovered these ports

        Returns:
            Dict with success status and counts of ports added/removed
        """
        from app.models import DiscoveryScan

        # Verify asset exists
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            return {"success": False, "error": "Asset not found"}

        # Validate scan_id exists if provided
        valid_scan_id = None
        if scan_id:
            scan = db.query(DiscoveryScan).filter(DiscoveryScan.scan_id == scan_id).first()
            if scan:
                valid_scan_id = scan_id
            else:
                logger.warning(f"Scan ID {scan_id} not found, setting to None")

        # Get count of existing ports
        existing_ports = db.query(Port).filter(Port.asset_id == asset_id).all()
        ports_removed = len(existing_ports)

        # Delete all existing ports for this asset
        db.query(Port).filter(Port.asset_id == asset_id).delete()

        # Add new ports
        ports_added = 0

        for port_data in ports_data:
            port_number = port_data.get("port_number")
            protocol_name = port_data.get("protocol", "TCP").upper()

            # Get or create protocol
            protocol = PortService.get_protocol_by_name(db, protocol_name)

            # Create new port
            new_port = Port(
                asset_id=asset_id,
                port_number=port_number,
                protocol_id=protocol.id,
                service_name=port_data.get("service_name"),
                service_product=port_data.get("service_product"),
                service_version=port_data.get("service_version"),
                state=port_data.get("state", "open"),
                discovered_by_scan_id=valid_scan_id,
                is_active=True
            )

            db.add(new_port)
            ports_added += 1

        db.commit()

        logger.info(f"Overwrote ports for asset {asset_id}: removed {ports_removed}, added {ports_added}")

        return {
            "success": True,
            "asset_id": asset_id,
            "ports_added": ports_added,
            "ports_removed": ports_removed,
            "message": f"Successfully overwrote ports for asset (removed {ports_removed}, added {ports_added})"
        }

    @staticmethod
    def get_asset_ports(db: Session, asset_id: int) -> List[Dict[str, Any]]:
        """
        Get all ports for an asset

        Args:
            db: Database session
            asset_id: Asset ID

        Returns:
            List of port dictionaries
        """
        ports = db.query(Port).filter(Port.asset_id == asset_id).all()
        return [port.to_dict() for port in ports]

    @staticmethod
    def delete_port(db: Session, port_id: int) -> bool:
        """
        Delete a specific port

        Args:
            db: Database session
            port_id: Port ID

        Returns:
            True if deleted, False if not found
        """
        port = db.query(Port).filter(Port.id == port_id).first()
        if not port:
            return False

        db.delete(port)
        db.commit()
        logger.info(f"Deleted port {port_id}")
        return True
