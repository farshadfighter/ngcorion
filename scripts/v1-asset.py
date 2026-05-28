"""
Asset Inventory Model (Main Table)

This is the main table that stores all asset information.
Connects to all helper tables and contains 23+ columns.

This table represents the core asset data that users fill in through
the Asset Requirement form (5 pages) and view in Asset List.
"""

from sqlalchemy import Column, Integer, String, ForeignKey, Date, DateTime, Text, Enum, Numeric
from sqlalchemy.orm import relationship
from datetime import datetime
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
    
    def __repr__(self):
        return f"<Asset(id={self.id}, name='{self.asset_name}', type='{self.asset_type.type_name if self.asset_type else 'Unknown'}')>"
    
    def __str__(self):
        return f"{self.asset_name} ({self.asset_type.type_name if self.asset_type else 'Unknown Type'})"
    
    
    def get_overview(self):
        """
        Returns overview information (Page 1 data)
        Used for "Overview" view in Asset List
        
        Returns:
            dict: Overview data
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
    
    
    def get_network_system(self):
        """
        Returns network and system information (Page 2 data)
        Used for "Network and System" view in Asset List
        
        Returns:
            dict: Network/system data
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
    
    
    def get_location_ownership(self):
        """
        Returns location and ownership information (Page 3 data)
        Used for "Location and Ownership" view in Asset List
        
        Returns:
            dict: Location/ownership data
        """
        return {
            'asset_id': self.id,
            'asset_name': self.asset_name,
            'location': self.location.site_name if self.location else None,
            'network_zone': self.location.network_zone if self.location else None,
            'owner': self.owner.full_name if self.owner else None,
            'status': self.status.value if self.status else None
        }
    
    
    def get_security_risk_audit(self):
        """
        Returns security, risk and audit information (Page 5 data)
        Used for "Security / Risk / Audit" view in Asset List
        
        Returns:
            dict: Security/risk/audit data
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
    
    
    def is_active(self):
        """Check if asset is active"""
        return self.status == StatusEnum.ACTIVE
    
    
    def needs_audit(self, days_threshold=90):
        """
        Check if asset needs audit (based on last_audit_date)
        
        Args:
            days_threshold: Maximum days since last audit (default 90)
        
        Returns:
            bool: True if audit is needed
        """
        if not self.last_audit_date:
            return True
        
        from datetime import date
        days_since_audit = (date.today() - self.last_audit_date).days
        return days_since_audit > days_threshold



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
"""
