"""
Asset Inventory Model (Main Table)

This is the main table that stores all asset information.
Connects to all helper tables and contains 23+ columns.

This table represents the core asset data that users fill in through
the Asset Requirement form (5 pages) and view in Asset List.
"""

from sqlalchemy import Column, Integer, String, ForeignKey, Date, DateTime, Text, Enum, Numeric
from sqlalchemy.orm import relationship
from datetime import datetime, date, timedelta, timezone
from typing import Optional, Dict, Any, List
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

    # Relationship to Ports
    ports = relationship(
        "Port",
        back_populates="asset",
        cascade="all, delete-orphan",
        # The FK is ON DELETE CASCADE, so let the database remove the rows
        # instead of loading every port just to delete it one by one.
        passive_deletes=True,
        lazy="select"
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
        """Returns overview information (Page 1): asset_id, name, hostname, type, role, vendor, model."""
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
        """Returns network/system info (Page 2): asset_id, name, serial_number, os, ip_address, mac_address, ports, protocols."""
        os_full = f"{self.os_name} {self.os_version}" if self.os_name and self.os_version else self.os_name

        # Get ports information
        ports_data = []
        protocols_set = set()

        if hasattr(self, 'ports') and self.ports:
            for port in self.ports:
                if port.is_active:
                    ports_data.append({
                        'port_number': port.port_number,
                        'protocol': port.protocol.name if port.protocol else None,
                        'service': port.service_name
                    })
                    if port.protocol:
                        protocols_set.add(port.protocol.name)

        # Format ports display: "80(http), 443(https), 22(ssh)" etc
        ports_summary = ', '.join([f"{p['port_number']}/{p['protocol']}" for p in ports_data[:5]])
        if len(ports_data) > 5:
            ports_summary += f" +{len(ports_data) - 5} more"

        # Format protocols display: "TCP, UDP"
        protocols_summary = ', '.join(sorted(protocols_set)) if protocols_set else None

        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'hostname': self.hostname,
            'serial_number': self.serial_number,
            'os': os_full,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'ports': ports_summary or None,
            'ports_count': len(ports_data),
            'protocols': protocols_summary
        }
    
    
    def get_location_ownership(self) -> Dict[str, Any]:
        """Returns location/ownership info (Page 3): asset_id, name, location, network_zone, owner, status."""
        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'location': self.location.site_name if self.location else None,
            'network_zone': self.location.network_zone if self.location else None,
            'owner': self.owner.full_name if self.owner else None,
            'status': self.status.value if self.status else None
        }
    
    
    def get_security_risk_audit(self) -> Dict[str, Any]:
        """Returns security/audit info (Page 5): asset_id, name, confidentiality, risk_level, audit/patch dates, value, description."""
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
        """Check if asset status is ACTIVE."""
        return self.status == StatusEnum.ACTIVE

    def needs_audit(self, days_threshold: int = 90) -> bool:
        """Check if audit needed (never audited or exceeds threshold days)."""
        if not self.last_audit_date:
            return True
        days_since_audit = (date.today() - self.last_audit_date).days
        return days_since_audit > days_threshold

    def needs_patching(self, days_threshold: int = 30) -> bool:
        """Check if patching needed (never patched or exceeds threshold days)."""
        if not self.last_patch_date:
            return True
        days_since_patch = (date.today() - self.last_patch_date).days
        return days_since_patch > days_threshold

    # ====================================
    # Validation Methods
    # ====================================

    @staticmethod
    def validate_ip_address(ip_addr: str) -> bool:
        """Validate IPv4 address format."""
        if not ip_addr:
            return False
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ipv4_pattern, ip_addr))

    @staticmethod
    def validate_mac_address(mac_addr: str) -> bool:
        """Validate MAC address format (supports 00:11:22:33:44:55, 00-11-22-33-44-55, 0011.2233.4455, 001122334455)."""
        if not mac_addr:
            return False
        mac_patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # Colon or hyphen separated
            r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$',    # Cisco dot notation
            r'^[0-9A-Fa-f]{12}$'                             # No separators (compact)
        ]
        return any(re.match(pattern, mac_addr) for pattern in mac_patterns)

    def is_ip_valid(self) -> bool:
        """Check if asset's IP address is valid (None is considered valid)."""
        if not self.ip_address:
            return True
        return self.validate_ip_address(self.ip_address)

    def is_mac_valid(self) -> bool:
        """Check if asset's MAC address is valid (None is considered valid)."""
        if not self.mac_address:
            return True
        return self.validate_mac_address(self.mac_address)

    # ====================================
    # Computed Properties
    # ====================================

    @property
    def full_os_string(self) -> Optional[str]:
        """Full OS string (name + version)."""
        if self.os_name and self.os_version:
            return f"{self.os_name} {self.os_version}"
        return self.os_name

    @property
    def inferred_device_type(self) -> Optional[str]:
        """Best-effort hardening/audit device family (cisco, fortinet, linux, ...).

        Heuristic over manufacturer/os_name/model/asset_type/name; None when it
        can't be determined. Used to filter the asset list by selected service.
        """
        from app.utils.device_classification import infer_device_family
        return infer_device_family(self)

    @property
    def is_high_risk(self) -> bool:
        """True if risk level is high or critical."""
        if not self.risk_level:
            return False
        return self.risk_level in [RiskLevelEnum.HIGH, RiskLevelEnum.CRITICAL]

    @property
    def is_critical(self) -> bool:
        """True if confidentiality or risk level is critical."""
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
        """Days since asset creation."""
        return (datetime.now(timezone.utc) - self.created_at).days

    @property
    def days_since_audit(self) -> Optional[int]:
        """Days since last audit (None if never audited)."""
        if not self.last_audit_date:
            return None
        return (date.today() - self.last_audit_date).days

    @property
    def days_since_patch(self) -> Optional[int]:
        """Days since last patch (None if never patched)."""
        if not self.last_patch_date:
            return None
        return (date.today() - self.last_patch_date).days

    # ====================================
    # Discovery Helper Methods
    # ====================================

    def mark_field_discovered(self, field_name: str) -> None:
        """Mark a field as populated by auto-discovery."""
        if self.discovered_fields is None:
            self.discovered_fields = {}
        self.discovered_fields[field_name] = True

    def is_field_discovered(self, field_name: str) -> bool:
        """Check if field was auto-discovered."""
        if not self.discovered_fields:
            return False
        return self.discovered_fields.get(field_name, False)

    def get_discovered_fields(self) -> List[str]:
        """Get list of all auto-discovered fields."""
        if not self.discovered_fields:
            return []
        return [field for field, discovered in self.discovered_fields.items() if discovered]

    # ====================================
    # Serialization Methods
    # ====================================

    def to_dict(self, include_relationships: bool = True) -> Dict[str, Any]:
        """Convert asset to dictionary. Set include_relationships=False for IDs only."""
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
        """Simplified JSON-safe dictionary for API responses."""
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
        """Compare assets by ID."""
        if not isinstance(other, Asset):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        """Hash based on ID."""
        return hash(self.id)

    def get_security_summary(self) -> Dict[str, Any]:
        """Comprehensive security summary with risk flags and maintenance status."""
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
        """Maintenance status with audit/patch dates and requirements."""
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
# Usage Guide
# ====================================
"""
FOREIGN KEY STRATEGIES:
- asset_type_id: RESTRICT (prevent deletion if assets exist)
- location_id, owner_id: SET NULL (preserve asset if deleted)
- user_id: CASCADE (delete user's assets with user)

KEY FEATURES:
- View methods: get_overview(), get_network_system(), get_location_ownership(), get_security_risk_audit()
- Validation: validate_ip_address(), validate_mac_address(), is_ip_valid(), is_mac_valid()
- Properties: full_os_string, is_high_risk, is_critical, age_days, days_since_audit, days_since_patch
- Maintenance: needs_audit(), needs_patching(), get_maintenance_status(), get_security_summary()
- Discovery: mark_field_discovered(), is_field_discovered(), get_discovered_fields()
- Serialization: to_dict(), to_json_safe()

BASIC USAGE:
    # Create asset
    asset = Asset(asset_name="Core-Switch-01", asset_type_id=3, user_id=1, ...)
    db.add(asset)
    db.commit()

    # Query user's assets
    assets = db.query(Asset).filter(Asset.user_id == current_user_id).all()

    # Get view data
    overview_data = [asset.get_overview() for asset in assets]

    # Check maintenance
    if asset.needs_audit() or asset.needs_patching():
        print("Maintenance required")

    # Validate and serialize
    if asset.is_ip_valid():
        return asset.to_json_safe()
"""
