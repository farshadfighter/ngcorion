"""
Asset Inventory Model (Main Table)

This is the main table that stores all asset information.
Connects to all helper tables and contains 23+ columns.

This table represents the core asset data that users fill in through
the Asset Requirement form (5 pages) and view in Asset List.
"""

from sqlalchemy import Column, Integer, String, ForeignKey, Date, DateTime, Text, Enum, Numeric
from sqlalchemy.orm import relationship
from datetime import datetime, date, timedelta
from typing import Optional, Dict, Any, List
from decimal import Decimal
import re
from app.core.database import Base
from app.models.enums import StatusEnum, ConfidentialityLevelEnum, RiskLevelEnum
from sqlalchemy.dialects.postgresql import JSON

class Asset(Base):
    """
    Main Asset Inventory Table
    
    Stores complete information about each asset.
    Each user maintains their own asset inventory.
    
    Form Pages (Asset Requirement):
    -------------------------------
    Page 1: Basic Info
        - asset_name, hostname, asset_type, asset_role, manufacturer, model
    
    Page 2: Technical Details
        - serial_number, os_name, os_version, ip_address, mac_address
    
    Page 3: Location & Ownership
        - location, network_zone, owner, status
    
    Page 4: Network Ports
        - (handled separately in future table)
    
    Page 5: Security & Audit
        - confidentiality_level, risk_level, last_audit_date, 
          last_patch_date, asset_value, description

    """
    
    __tablename__ = "asset_inventory"
    
    # ====================================
    # Primary Key
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier (asset_id in forms)"
    )
    
    # ====================================
    # Page 1: Basic Information
    # ====================================
    
    asset_name = Column(
        String(200),
        nullable=False,
        index=True,
        comment="Name of the asset (e.g., Core-Switch-01, FW-Main)"
    )
    
    hostname = Column(
        String(200),
        nullable=True,
        index=True,
        comment="Network hostname"
    )
    
    asset_type_id = Column(
        Integer,
        ForeignKey('asset_types.id', ondelete='RESTRICT'),
        nullable=False,
        index=True,
        comment="FK to asset_types (Firewall, Router, Switch, etc.)"
    )
    
    asset_role = Column(
        String(200),
        nullable=True,
        comment="Role or purpose of the asset (e.g., Core Network, DMZ Gateway)"
    )
    
    manufacturer = Column(
        String(200),
        nullable=True,
        index=True,
        comment="Vendor/manufacturer name (e.g., Cisco, HP, Dell)"
    )
    
    model = Column(
        String(200),
        nullable=True,
        comment="Model name or number (e.g., Catalyst 9300, ProLiant DL380)"
    )
    
    # ====================================
    # Page 2: Technical Details
    # ====================================
    
    serial_number = Column(
        String(200),
        nullable=True,
        unique=True,
        index=True,
        comment="Serial number (should be unique)"
    )
    
    os_name = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Operating system name (e.g., Windows Server, Ubuntu, FortiOS)"
    )
    
    os_version = Column(
        String(50),
        nullable=True,
        comment="OS version (e.g., 2019, 22.04, 7.2)"
    )
    
    ip_address = Column(
        String(50),
        nullable=True,
        index=True,
        comment="IP address (e.g., 10.0.0.1, 192.168.1.100)"
    )
    
    mac_address = Column(
        String(50),
        nullable=True,
        index=True,
        comment="MAC address (e.g., 00:11:22:33:44:55)"
    )
    
    # ====================================
    # Page 3: Location & Ownership
    # ====================================
    
    location_id = Column(
        Integer,
        ForeignKey('asset_locations.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="FK to asset_locations (physical/logical location)"
    )
    
    owner_id = Column(
        Integer,
        ForeignKey('asset_owners.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="FK to asset_owners (person responsible for asset)"
    )
    
    status = Column(
        Enum(StatusEnum),
        nullable=False,
        default=StatusEnum.ACTIVE,
        index=True,
        comment="Asset status (active, standby, decommissioned, unknown)"
    )
    
    # ====================================
    # Page 5: Security, Risk & Audit
    # ====================================
    
    confidentiality_level = Column(
        Enum(ConfidentialityLevelEnum),
        nullable=True,
        index=True,
        comment="Data classification (public, internal, confidential, critical)"
    )
    
    risk_level = Column(
        Enum(RiskLevelEnum),
        nullable=True,
        index=True,
        comment="Risk assessment (low, medium, high, critical)"
    )
    
    last_audit_date = Column(
        Date,
        nullable=True,
        comment="Date of last audit or review"
    )
    
    last_patch_date = Column(
        Date,
        nullable=True,
        comment="Date of last security patch or update"
    )
    
    asset_value = Column(
        Numeric(15, 2),
        nullable=True,
        comment="Financial value of the asset (with 2 decimal places)"
    )
    
    description = Column(
        Text,
        nullable=True,
        comment="Additional notes or description"
    )
    
    discovered_fields = Column(
        JSON,
        nullable=True,
        comment="Fields populated by auto-discovery (JSON: {field_name: true})"
    )
    
    # ====================================
    # User Ownership (Data Isolation)
    # ====================================
    
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="FK to users - determines which user owns this asset"
    )
    
    # ====================================
    # Timestamps
    # ====================================
    
    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        comment="Record creation timestamp"
    )
    
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
        comment="Last update timestamp"
    )
    
    # ====================================
    # Relationships
    # ====================================
    
    # Relationship to User
    user = relationship(
        "User",
        backref="assets"
    )
    
    # Relationship to AssetType
    asset_type = relationship(
        "AssetType",
        backref="assets"
    )
    
    # Relationship to AssetLocation
    location = relationship(
        "AssetLocation",
        backref="assets"
    )
    
    # Relationship to AssetOwner
    owner = relationship(
        "AssetOwner",
        backref="assets"
    )
    
    # Note: Relationships with asset_dependencies and asset_security_status
    # are defined in those models using backref
    
    
    # ====================================
    # Helper Methods
    # ====================================
    
    def __repr__(self) -> str:
        """Developer-friendly representation: <Asset(id=1, name='...', type='...')>"""
        asset_type_name = self.asset_type.type_name if self.asset_type else 'Unknown'
        return f"<Asset(id={self.id}, name='{self.asset_name}', type='{asset_type_name}')>"

    def __str__(self) -> str:
        """User-friendly representation: Asset Name (Type)"""
        asset_type_name = self.asset_type.type_name if self.asset_type else 'Unknown Type'
        return f"{self.asset_name} ({asset_type_name})"
    
    
    def get_overview(self) -> Dict[str, Any]:
        """
        Returns overview information (Page 1 data).
        Used for "Overview" view in Asset List.

        Returns:
            Dict[str, Any]: Dictionary containing:
                - asset_id (int): Unique asset identifier
                - asset_name (str): Name of the asset
                - hostname (str | None): Network hostname
                - asset_type (str | None): Type of asset (e.g., 'Firewall', 'Switch')
                - role (str | None): Asset role or purpose
                - vendor (str | None): Manufacturer/vendor name
                - model (str | None): Model name or number

        Example:
            >>> asset.get_overview()
            {
                'asset_id': 1,
                'asset_name': 'Core-Switch-01',
                'hostname': 'sw-core-01.company.local',
                'asset_type': 'Switch',
                'role': 'Core Network Switch',
                'vendor': 'Cisco',
                'model': 'Catalyst 9300'
            }
        """
        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'hostname': self.hostname,
            'asset_type': self.asset_type.type_name if self.asset_type else None,
            'role': self.asset_role,
            'vendor': self.manufacturer,
            'model': self.model
        }
    
    
    def get_network_system(self) -> Dict[str, Any]:
        """
        Returns network and system information (Page 2 data).
        Used for "Network and System" view in Asset List.

        Returns:
            Dict[str, Any]: Dictionary containing:
                - asset_id (int): Unique asset identifier
                - asset_name (str): Name of the asset
                - serial_number (str | None): Hardware serial number
                - os (str | None): Full OS string (name + version)
                - ip_address (str | None): IP address
                - mac_address (str | None): MAC address

        Example:
            >>> asset.get_network_system()
            {
                'asset_id': 1,
                'asset_name': 'Core-Switch-01',
                'serial_number': 'FCW2234G0XX',
                'os': 'Cisco IOS-XE 17.9.3',
                'ip_address': '10.0.0.10',
                'mac_address': '00:11:22:33:44:55'
            }
        """
        os_full = f"{self.os_name} {self.os_version}" if self.os_name and self.os_version else self.os_name

        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'serial_number': self.serial_number,
            'os': os_full,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address
        }
    
    
    def get_location_ownership(self) -> Dict[str, Any]:
        """
        Returns location and ownership information (Page 3 data).
        Used for "Location and Ownership" view in Asset List.

        Returns:
            Dict[str, Any]: Dictionary containing:
                - asset_id (int): Unique asset identifier
                - asset_name (str): Name of the asset
                - location (str | None): Site/location name
                - network_zone (str | None): Network zone (e.g., 'DMZ', 'Internal')
                - owner (str | None): Full name of asset owner
                - status (str | None): Asset status ('active', 'standby', etc.)

        Example:
            >>> asset.get_location_ownership()
            {
                'asset_id': 1,
                'asset_name': 'Core-Switch-01',
                'location': 'Main Data Center',
                'network_zone': 'Core',
                'owner': 'Ali Rezaei',
                'status': 'active'
            }
        """
        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'location': self.location.site_name if self.location else None,
            'network_zone': self.location.network_zone if self.location else None,
            'owner': self.owner.full_name if self.owner else None,
            'status': self.status.value if self.status else None
        }
    
    
    def get_security_risk_audit(self) -> Dict[str, Any]:
        """
        Returns security, risk and audit information (Page 5 data).
        Used for "Security / Risk / Audit" view in Asset List.

        Returns:
            Dict[str, Any]: Dictionary containing:
                - asset_id (int): Unique asset identifier
                - asset_name (str): Name of the asset
                - confidentiality (str | None): Confidentiality level ('public', 'internal', etc.)
                - risk_level (str | None): Risk level ('low', 'medium', 'high', 'critical')
                - last_audit_date (str | None): Last audit date (YYYY-MM-DD format)
                - last_patch_date (str | None): Last patch date (YYYY-MM-DD format)
                - asset_value (float | None): Financial value of the asset
                - description (str | None): Additional notes or description

        Example:
            >>> asset.get_security_risk_audit()
            {
                'asset_id': 1,
                'asset_name': 'Core-Switch-01',
                'confidentiality': 'critical',
                'risk_level': 'high',
                'last_audit_date': '2025-01-15',
                'last_patch_date': '2025-01-20',
                'asset_value': 15000.00,
                'description': 'Core network infrastructure switch'
            }
        """
        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'confidentiality': self.confidentiality_level.value if self.confidentiality_level else None,
            'risk_level': self.risk_level.value if self.risk_level else None,
            'last_audit_date': self.last_audit_date.strftime('%Y-%m-%d') if self.last_audit_date else None,
            'last_patch_date': self.last_patch_date.strftime('%Y-%m-%d') if self.last_patch_date else None,
            'asset_value': float(self.asset_value) if self.asset_value else None,
            'description': self.description
        }
    
    
    def is_active(self) -> bool:
        """
        Check if asset is currently active.

        Returns:
            bool: True if asset status is ACTIVE, False otherwise

        Example:
            >>> asset.is_active()
            True
        """
        return self.status == StatusEnum.ACTIVE

    def needs_audit(self, days_threshold: int = 90) -> bool:
        """
        Check if asset needs audit based on last_audit_date.

        Args:
            days_threshold (int): Maximum days since last audit (default: 90)

        Returns:
            bool: True if audit is needed (never audited or exceeds threshold)

        Example:
            >>> asset.needs_audit(90)
            True
            >>> asset.needs_audit(30)  # More frequent audits
            False
        """
        if not self.last_audit_date:
            return True

        days_since_audit = (date.today() - self.last_audit_date).days
        return days_since_audit > days_threshold

    def needs_patching(self, days_threshold: int = 30) -> bool:
        """
        Check if asset needs patching based on last_patch_date.

        Args:
            days_threshold (int): Maximum days since last patch (default: 30)

        Returns:
            bool: True if patching is needed (never patched or exceeds threshold)

        Example:
            >>> asset.needs_patching(30)
            True
            >>> asset.needs_patching(7)  # Weekly patching schedule
            False
        """
        if not self.last_patch_date:
            return True

        days_since_patch = (date.today() - self.last_patch_date).days
        return days_since_patch > days_threshold

    # ====================================
    # Validation Methods
    # ====================================

    @staticmethod
    def validate_ip_address(ip_addr: str) -> bool:
        """
        Validate IPv4 address format.

        Args:
            ip_addr (str): IP address string to validate

        Returns:
            bool: True if valid IPv4 format, False otherwise

        Example:
            >>> Asset.validate_ip_address('192.168.1.1')
            True
            >>> Asset.validate_ip_address('999.999.999.999')
            False
        """
        if not ip_addr:
            return False

        # IPv4 pattern
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ipv4_pattern, ip_addr))

    @staticmethod
    def validate_mac_address(mac_addr: str) -> bool:
        """
        Validate MAC address format.

        Args:
            mac_addr (str): MAC address string to validate

        Returns:
            bool: True if valid MAC format, False otherwise

        Supported formats:
            - 00:11:22:33:44:55
            - 00-11-22-33-44-55
            - 0011.2233.4455

        Example:
            >>> Asset.validate_mac_address('00:11:22:33:44:55')
            True
            >>> Asset.validate_mac_address('00-11-22-33-44-55')
            True
            >>> Asset.validate_mac_address('invalid')
            False
        """
        if not mac_addr:
            return False

        # Common MAC address patterns
        mac_patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # 00:11:22:33:44:55 or 00-11-22-33-44-55
            r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$'      # 0011.2233.4455
        ]

        return any(re.match(pattern, mac_addr) for pattern in mac_patterns)

    def is_ip_valid(self) -> bool:
        """
        Check if the asset's IP address is valid.

        Returns:
            bool: True if IP address is valid or not set, False if invalid

        Example:
            >>> asset.is_ip_valid()
            True
        """
        if not self.ip_address:
            return True  # No IP address set is considered valid
        return self.validate_ip_address(self.ip_address)

    def is_mac_valid(self) -> bool:
        """
        Check if the asset's MAC address is valid.

        Returns:
            bool: True if MAC address is valid or not set, False if invalid

        Example:
            >>> asset.is_mac_valid()
            True
        """
        if not self.mac_address:
            return True  # No MAC address set is considered valid
        return self.validate_mac_address(self.mac_address)

    # ====================================
    # Computed Properties
    # ====================================

    @property
    def full_os_string(self) -> Optional[str]:
        """
        Get the full operating system string (name + version).

        Returns:
            Optional[str]: Full OS string or None if not available

        Example:
            >>> asset.full_os_string
            'Cisco IOS-XE 17.9.3'
        """
        if self.os_name and self.os_version:
            return f"{self.os_name} {self.os_version}"
        return self.os_name

    @property
    def is_high_risk(self) -> bool:
        """
        Check if asset is classified as high or critical risk.

        Returns:
            bool: True if risk level is high or critical

        Example:
            >>> asset.is_high_risk
            True
        """
        if not self.risk_level:
            return False
        return self.risk_level in [RiskLevelEnum.HIGH, RiskLevelEnum.CRITICAL]

    @property
    def is_critical(self) -> bool:
        """
        Check if asset is classified as critical (confidentiality or risk).

        Returns:
            bool: True if confidentiality is critical or risk level is critical

        Example:
            >>> asset.is_critical
            True
        """
        confidentiality_critical = (
            self.confidentiality_level == ConfidentialityLevelEnum.CRITICAL
            if self.confidentiality_level else False
        )
        risk_critical = (
            self.risk_level == RiskLevelEnum.CRITICAL
            if self.risk_level else False
        )
        return confidentiality_critical or risk_critical

    @property
    def age_days(self) -> int:
        """
        Calculate the age of the asset in days since creation.

        Returns:
            int: Number of days since asset creation

        Example:
            >>> asset.age_days
            45
        """
        return (datetime.utcnow() - self.created_at).days

    @property
    def days_since_audit(self) -> Optional[int]:
        """
        Calculate days since last audit.

        Returns:
            Optional[int]: Number of days since last audit, or None if never audited

        Example:
            >>> asset.days_since_audit
            15
        """
        if not self.last_audit_date:
            return None
        return (date.today() - self.last_audit_date).days

    @property
    def days_since_patch(self) -> Optional[int]:
        """
        Calculate days since last patch.

        Returns:
            Optional[int]: Number of days since last patch, or None if never patched

        Example:
            >>> asset.days_since_patch
            5
        """
        if not self.last_patch_date:
            return None
        return (date.today() - self.last_patch_date).days

    # ====================================
    # Discovery Helper Methods
    # ====================================

    def mark_field_discovered(self, field_name: str) -> None:
        """
        Mark a field as populated by auto-discovery.

        Args:
            field_name (str): Name of the field that was auto-discovered

        Example:
            >>> asset.mark_field_discovered('ip_address')
            >>> asset.mark_field_discovered('mac_address')
        """
        if self.discovered_fields is None:
            self.discovered_fields = {}
        self.discovered_fields[field_name] = True

    def is_field_discovered(self, field_name: str) -> bool:
        """
        Check if a field was populated by auto-discovery.

        Args:
            field_name (str): Name of the field to check

        Returns:
            bool: True if field was auto-discovered, False otherwise

        Example:
            >>> asset.is_field_discovered('ip_address')
            True
        """
        if not self.discovered_fields:
            return False
        return self.discovered_fields.get(field_name, False)

    def get_discovered_fields(self) -> List[str]:
        """
        Get list of all fields that were auto-discovered.

        Returns:
            List[str]: List of field names that were auto-discovered

        Example:
            >>> asset.get_discovered_fields()
            ['ip_address', 'mac_address', 'os_name']
        """
        if not self.discovered_fields:
            return []
        return [field for field, discovered in self.discovered_fields.items() if discovered]

    # ====================================
    # Serialization Methods
    # ====================================

    def to_dict(self, include_relationships: bool = True) -> Dict[str, Any]:
        """
        Convert asset to dictionary for serialization.

        Args:
            include_relationships (bool): Include related object names (default: True)

        Returns:
            Dict[str, Any]: Complete asset data as dictionary

        Example:
            >>> asset.to_dict()
            {
                'id': 1,
                'asset_name': 'Core-Switch-01',
                'hostname': 'sw-core-01.company.local',
                ...
            }
        """
        data = {
            'id': self.id,
            'asset_name': self.asset_name,
            'hostname': self.hostname,
            'asset_type_id': self.asset_type_id,
            'asset_role': self.asset_role,
            'manufacturer': self.manufacturer,
            'model': self.model,
            'serial_number': self.serial_number,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'location_id': self.location_id,
            'owner_id': self.owner_id,
            'status': self.status.value if self.status else None,
            'confidentiality_level': self.confidentiality_level.value if self.confidentiality_level else None,
            'risk_level': self.risk_level.value if self.risk_level else None,
            'last_audit_date': self.last_audit_date.isoformat() if self.last_audit_date else None,
            'last_patch_date': self.last_patch_date.isoformat() if self.last_patch_date else None,
            'asset_value': float(self.asset_value) if self.asset_value else None,
            'description': self.description,
            'discovered_fields': self.discovered_fields,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_relationships:
            data['asset_type'] = self.asset_type.type_name if self.asset_type else None
            data['location'] = self.location.site_name if self.location else None
            data['owner'] = self.owner.full_name if self.owner else None
            data['user'] = self.user.username if self.user else None

        return data

    def to_json_safe(self) -> Dict[str, Any]:
        """
        Convert asset to JSON-safe dictionary (simplified for API responses).

        Returns:
            Dict[str, Any]: JSON-safe asset data

        Example:
            >>> asset.to_json_safe()
            {
                'id': 1,
                'name': 'Core-Switch-01',
                'type': 'Switch',
                'status': 'active'
            }
        """
        return {
            'id': self.id,
            'name': self.asset_name,
            'hostname': self.hostname,
            'type': self.asset_type.type_name if self.asset_type else None,
            'role': self.asset_role,
            'manufacturer': self.manufacturer,
            'model': self.model,
            'ip_address': self.ip_address,
            'location': self.location.site_name if self.location else None,
            'owner': self.owner.full_name if self.owner else None,
            'status': self.status.value if self.status else None,
            'risk_level': self.risk_level.value if self.risk_level else None,
        }

    # ====================================
    # Comparison and Utility Methods
    # ====================================

    def __eq__(self, other: object) -> bool:
        """
        Compare assets for equality based on ID.

        Args:
            other (object): Another asset to compare with

        Returns:
            bool: True if assets have the same ID

        Example:
            >>> asset1 == asset2
            False
        """
        if not isinstance(other, Asset):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        """
        Generate hash for the asset based on ID.

        Returns:
            int: Hash value

        Example:
            >>> hash(asset)
            123456
        """
        return hash(self.id)

    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get a comprehensive security summary for the asset.

        Returns:
            Dict[str, Any]: Security-related information and flags

        Example:
            >>> asset.get_security_summary()
            {
                'asset_id': 1,
                'asset_name': 'Core-Switch-01',
                'is_critical': True,
                'is_high_risk': True,
                'needs_audit': False,
                'needs_patching': True,
                'days_since_audit': 15,
                'days_since_patch': 45
            }
        """
        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'is_critical': self.is_critical,
            'is_high_risk': self.is_high_risk,
            'needs_audit': self.needs_audit(),
            'needs_patching': self.needs_patching(),
            'days_since_audit': self.days_since_audit,
            'days_since_patch': self.days_since_patch,
            'confidentiality_level': self.confidentiality_level.value if self.confidentiality_level else None,
            'risk_level': self.risk_level.value if self.risk_level else None,
        }

    def get_maintenance_status(self) -> Dict[str, Any]:
        """
        Get maintenance status information for the asset.

        Returns:
            Dict[str, Any]: Maintenance-related information

        Example:
            >>> asset.get_maintenance_status()
            {
                'asset_id': 1,
                'asset_name': 'Core-Switch-01',
                'last_audit_date': '2025-01-15',
                'needs_audit': False,
                'last_patch_date': '2024-12-01',
                'needs_patching': True,
                'age_days': 120
            }
        """
        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'last_audit_date': self.last_audit_date.isoformat() if self.last_audit_date else None,
            'needs_audit': self.needs_audit(),
            'days_since_audit': self.days_since_audit,
            'last_patch_date': self.last_patch_date.isoformat() if self.last_patch_date else None,
            'needs_patching': self.needs_patching(),
            'days_since_patch': self.days_since_patch,
            'age_days': self.age_days,
        }


# ====================================
# Detailed Explanation:
# ====================================
"""
1. Foreign Key Strategies:
   =======================
   Different ondelete behaviors for different relationships:
   
   a) RESTRICT (asset_type_id):
      - Cannot delete asset_type if assets use it
      - Prevents accidental data loss
      - Must reassign or delete assets first
   
   b) SET NULL (location_id, owner_id):
      - If location/owner deleted, asset remains
      - FK becomes NULL (asset loses location/owner)
      - Asset data preserved
   
   c) CASCADE (user_id):
      - If user deleted, all their assets deleted
      - Makes sense: user's data belongs to them


2. Data Types:
   ===========
   - String(N): Text with max length
   - Text: Unlimited text
   - Integer: Whole numbers
   - Numeric(15,2): Decimal numbers (15 digits, 2 after decimal)
   - Date: Date only (YYYY-MM-DD)
   - DateTime: Date and time
   - Enum: Predefined values only
   - Boolean: True/False


3. Indexes:
   ========
   Fields with index=True for fast searching:
   - asset_name: Search by name
   - hostname: Search by hostname
   - asset_type_id: Filter by type
   - manufacturer: Filter by vendor
   - serial_number: Unique lookup
   - os_name: Filter by OS
   - ip_address, mac_address: Network searches
   - location_id, owner_id: Filter by location/owner
   - status: Filter by status
   - confidentiality_level, risk_level: Security queries
   - user_id: Most common filter (data isolation)


4. Unique Constraint:
   ==================
   serial_number is unique=True:
   - No two assets can have same serial number
   - Makes sense: serial numbers are unique in real world


5. Default Values:
   ===============
   - status: Default is ACTIVE
   - created_at: Automatically set to current time
   - updated_at: Automatically updated on changes


6. Helper Methods for Asset List Views:
   ====================================
   Each method returns data for one view:
   
   a) get_overview() → Overview table
   b) get_network_system() → Network and System table
   c) get_location_ownership() → Location and Ownership table
   d) get_security_risk_audit() → Security/Risk/Audit table
   
   These make it easy to build frontend tables!


7. Practical Usage Examples:
   =========================
   # Create a complete asset
   asset = Asset(
       # Page 1: Basic Info
       asset_name="Core-Switch-01",
       hostname="sw-core-01.company.local",
       asset_type_id=3,  # Switch
       asset_role="Core Network Switch",
       manufacturer="Cisco",
       model="Catalyst 9300",
       
       # Page 2: Technical Details
       serial_number="FCW2234G0XX",
       os_name="Cisco IOS-XE",
       os_version="17.9.3",
       ip_address="10.0.0.10",
       mac_address="00:11:22:33:44:55",
       
       # Page 3: Location & Ownership
       location_id=1,  # Main DC
       owner_id=1,  # Ali Rezaei
       status=StatusEnum.ACTIVE,
       
       # Page 5: Security & Audit
       confidentiality_level=ConfidentialityLevelEnum.CRITICAL,
       risk_level=RiskLevelEnum.HIGH,
       last_audit_date=date(2025, 1, 15),
       last_patch_date=date(2025, 1, 20),
       asset_value=15000.00,
       description="Core network infrastructure switch",
       
       # User ownership
       user_id=1  # sina
   )
   db.add(asset)
   db.commit()
   
   
   # Query user's assets
   sina_assets = db.query(Asset).filter(Asset.user_id == 1).all()
   
   
   # Get specific views
   for asset in sina_assets:
       overview = asset.get_overview()
       print(f"Asset: {overview['asset_name']}")
       print(f"Type: {overview['asset_type']}")
       print(f"Vendor: {overview['vendor']}")
       print()
   
   
   # Access relationships
   asset = db.query(Asset).filter(Asset.id == 1).first()
   print(f"Type: {asset.asset_type.type_name}")
   print(f"Location: {asset.location.site_name}")
   print(f"Owner: {asset.owner.full_name}")
   print(f"User: {asset.user.username}")


8. Data Isolation:
   ===============
   Each user sees only their assets:
   
   # User "sina" (user_id=1) assets
   sina_assets = db.query(Asset).filter(Asset.user_id == 1).all()
   
   # User "reza" (user_id=2) assets
   reza_assets = db.query(Asset).filter(Asset.user_id == 2).all()
   
   These are completely separate!


9. Complete Asset List Queries:
   ============================
   For frontend Asset List views:
   
   # Overview view
   assets = db.query(Asset).filter(Asset.user_id == current_user_id).all()
   overview_data = [asset.get_overview() for asset in assets]
   
   # Network and System view
   network_data = [asset.get_network_system() for asset in assets]
   
   # Location and Ownership view
   location_data = [asset.get_location_ownership() for asset in assets]
   
   # Security/Risk/Audit view
   security_data = [asset.get_security_risk_audit() for asset in assets]


10. Validation Methods:
    ===================
    Validate data formats before saving:

    # Validate IP address format
    if Asset.validate_ip_address('192.168.1.1'):
        print("Valid IP address")

    # Validate MAC address format (supports multiple formats)
    if Asset.validate_mac_address('00:11:22:33:44:55'):
        print("Valid MAC address")

    # Check asset's IP and MAC validity
    if asset.is_ip_valid() and asset.is_mac_valid():
        print("Asset network info is valid")


11. Computed Properties:
    ====================
    Access calculated values as properties:

    # Full OS string
    print(asset.full_os_string)  # "Cisco IOS-XE 17.9.3"

    # Check if asset is high risk
    if asset.is_high_risk:
        print("This asset requires extra attention")

    # Check if asset is critical
    if asset.is_critical:
        print("Critical asset - handle with care")

    # Get asset age
    print(f"Asset created {asset.age_days} days ago")

    # Days since last audit/patch
    print(f"Last audited {asset.days_since_audit} days ago")
    print(f"Last patched {asset.days_since_patch} days ago")


12. Maintenance Methods:
    ====================
    Check if maintenance is needed:

    # Check if audit is needed (default: 90 days)
    if asset.needs_audit():
        print("Asset needs audit")

    # Check with custom threshold
    if asset.needs_audit(days_threshold=30):
        print("Asset needs monthly audit")

    # Check if patching is needed (default: 30 days)
    if asset.needs_patching():
        print("Asset needs patching")

    # Get complete maintenance status
    maintenance = asset.get_maintenance_status()
    print(f"Needs audit: {maintenance['needs_audit']}")
    print(f"Needs patching: {maintenance['needs_patching']}")


13. Security Summary:
    =================
    Get comprehensive security information:

    security_summary = asset.get_security_summary()
    print(f"Critical: {security_summary['is_critical']}")
    print(f"High Risk: {security_summary['is_high_risk']}")
    print(f"Needs Audit: {security_summary['needs_audit']}")
    print(f"Needs Patching: {security_summary['needs_patching']}")


14. Discovery Field Tracking:
    =========================
    Track which fields were auto-discovered:

    # Mark fields as discovered
    asset.mark_field_discovered('ip_address')
    asset.mark_field_discovered('mac_address')
    asset.mark_field_discovered('os_name')

    # Check if field was discovered
    if asset.is_field_discovered('ip_address'):
        print("IP was auto-discovered")

    # Get all discovered fields
    discovered = asset.get_discovered_fields()
    print(f"Auto-discovered fields: {', '.join(discovered)}")


15. Serialization Methods:
    ======================
    Convert assets to dictionaries for API responses:

    # Full serialization with relationships
    full_data = asset.to_dict(include_relationships=True)
    # Returns complete asset data with related object names

    # Without relationships (IDs only)
    data = asset.to_dict(include_relationships=False)
    # Returns asset data with foreign key IDs

    # JSON-safe simplified version
    api_response = asset.to_json_safe()
    # Returns simplified data suitable for API responses


16. Filtering and Querying Examples:
    =================================
    Common query patterns:

    # Find all critical assets
    critical_assets = db.query(Asset).filter(
        Asset.user_id == current_user_id,
        Asset.risk_level == RiskLevelEnum.CRITICAL
    ).all()

    # Find assets needing audit (manual query)
    from datetime import date, timedelta
    audit_threshold = date.today() - timedelta(days=90)
    needs_audit = db.query(Asset).filter(
        Asset.user_id == current_user_id,
        or_(
            Asset.last_audit_date == None,
            Asset.last_audit_date < audit_threshold
        )
    ).all()

    # Find assets by manufacturer
    cisco_assets = db.query(Asset).filter(
        Asset.user_id == current_user_id,
        Asset.manufacturer.ilike('%cisco%')
    ).all()

    # Find active high-risk assets
    high_risk_active = db.query(Asset).filter(
        Asset.user_id == current_user_id,
        Asset.status == StatusEnum.ACTIVE,
        Asset.risk_level.in_([RiskLevelEnum.HIGH, RiskLevelEnum.CRITICAL])
    ).all()


17. Type Hints and IDE Support:
    ============================
    All methods now include comprehensive type hints:
    - Better IDE autocompletion
    - Type checking with mypy
    - Clear documentation of expected types
    - Examples in docstrings for all methods


18. Best Practices:
    ================
    a) Always validate data before saving:
       if Asset.validate_ip_address(ip):
           asset.ip_address = ip

    b) Use properties for computed values:
       # Use property (no parentheses)
       print(asset.full_os_string)
       # Don't calculate manually

    c) Use helper methods for views:
       # Use helper method
       overview = asset.get_overview()
       # Don't build dict manually

    d) Track discovered fields:
       # Mark discovered fields
       asset.mark_field_discovered('ip_address')
       # Check before overwriting
       if not asset.is_field_discovered('ip_address'):
           asset.ip_address = new_ip

    e) Use serialization methods:
       # For API responses
       return asset.to_json_safe()
       # For detailed exports
       return asset.to_dict(include_relationships=True)
"""
