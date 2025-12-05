"""
Asset Locations Model

This table stores physical and logical location information for assets.
Each user maintains their own list of locations.

Example:
    location = AssetLocation(
        site_name="Main Data Center",
        rack_name="Rack-12",
        room="Server Room A",
        floor="2nd Floor",
        network_zone="DMZ",
        vlan_id=100,
        subnet="10.0.0.0/24",
        user_id=1
    )
"""

from sqlalchemy import Column, Integer, String, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


class AssetLocation(Base):
    """
    Asset Locations Table
    
    Relationships:
        user: The user who created this location record
        assets: List of assets at this location (reverse relationship)
    """
    
    __tablename__ = "asset_locations"
    
    # ====================================
    # Primary Key
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier for location"
    )
    
    # ====================================
    # Physical Location Information
    # ====================================
    
    site_name = Column(
        String(200),
        nullable=False,
        index=True,
        comment="Site or building name (e.g., Main DC, Branch Office)"
    )
    
    rack_name = Column(
        String(100),
        nullable=True,
        comment="Rack identifier (e.g., Rack-12, R-A-05)"
    )
    
    room = Column(
        String(100),
        nullable=True,
        comment="Room name or number (e.g., Server Room A, Room 204)"
    )
    
    floor = Column(
        String(50),
        nullable=True,
        comment="Floor number or name (e.g., 2nd Floor, Basement)"
    )
    
    # ====================================
    # Logical/Network Location Information
    # ====================================
    
    network_zone = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Network zone or segment (e.g., DMZ, Internal, Management)"
    )
    
    vlan_id = Column(
        Integer,
        nullable=True,
        comment="VLAN identifier (e.g., 100, 200)"
    )
    
    subnet = Column(
        String(50),
        nullable=True,
        comment="Network subnet in CIDR notation (e.g., 10.0.0.0/24, 192.168.1.0/24)"
    )
    
    # ====================================
    # Additional Information
    # ====================================
    
    description = Column(
        Text,
        nullable=True,
        comment="Additional notes or description about this location"
    )
    
    # ====================================
    # Foreign Key - User Ownership
    # ====================================
    
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to users table - determines which user owns this location record"
    )
    
    # ====================================
    # Relationships
    # ====================================
    
    user = relationship(
        "User",
        backref="asset_locations"
    )
    
    # Note: Relationship with Asset will be defined in asset.py
    # assets = relationship("Asset", backref="location")
    
    
    # ====================================
    # Helper Methods
    # ====================================
    
    def __repr__(self):
        return f"<AssetLocation(id={self.id}, site='{self.site_name}', rack='{self.rack_name}')>"
    
    def __str__(self):
        location_parts = [self.site_name]
        if self.rack_name:
            location_parts.append(self.rack_name)
        if self.room:
            location_parts.append(self.room)
        return " - ".join(location_parts)
    
    
    def get_full_address(self):
        """
        Returns a complete location description
        
        Returns:
            str: Full location string
        
        Example:
            >>> location.get_full_address()
            "Main DC - Rack-12 - Server Room A - 2nd Floor (VLAN 100: 10.0.0.0/24)"
        """
        parts = []
        
        # Physical location
        if self.site_name:
            parts.append(self.site_name)
        if self.rack_name:
            parts.append(self.rack_name)
        if self.room:
            parts.append(self.room)
        if self.floor:
            parts.append(self.floor)
        
        physical = " - ".join(parts) if parts else "Unknown Location"
        
        # Network location
        network_parts = []
        if self.network_zone:
            network_parts.append(self.network_zone)
        if self.vlan_id:
            network_parts.append(f"VLAN {self.vlan_id}")
        if self.subnet:
            network_parts.append(self.subnet)
        
        if network_parts:
            network = f"({', '.join(network_parts)})"
            return f"{physical} {network}"
        
        return physical


# ====================================
# Detailed Explanation:
# ====================================
"""
1. Physical vs Logical Location
   =============================
   Physical Location (where device is physically):
   - site_name: Building/Data center
   - rack_name: Which rack
   - room: Which room
   - floor: Which floor
   
   Logical Location (network perspective):
   - network_zone: Network segment (DMZ, Internal, etc.)
   - vlan_id: VLAN number
   - subnet: IP subnet range
   
   Example:
   Physical: Main DC - Rack-12 - Server Room - 2nd Floor
   Logical: DMZ, VLAN 100, 10.0.0.0/24


2. Why CASCADE delete?
   ====================
   Same reason as asset_owners:
   - If user is deleted
   - Their location records are meaningless
   - So delete them too automatically


3. Data Isolation per User
   ========================
   Each user has their own locations:
   
   Database:
   id | site_name  | rack_name | user_id
   1  | Main DC    | Rack-12   | 1 (sina)
   2  | Branch Off | Rack-03   | 1 (sina)
   3  | Cloud AWS  | N/A       | 2 (ahad)
   
   User "sina" sees only: Main DC, Branch Off
   User "ahad" sees only: Cloud AWS


4. Flexible Location Definition
   =============================
   Not all fields are required (nullable=True):
   
   Example 1 - Full physical location:
   site_name="Main DC"
   rack_name="Rack-12"
   room="Server Room A"
   floor="2nd Floor"
   
   Example 2 - Cloud location (no physical rack):
   site_name="AWS US-East"
   rack_name=NULL
   room=NULL
   floor=NULL
   network_zone="Production"
   subnet="10.100.0.0/16"
   
   Example 3 - Branch office:
   site_name="Tehran Branch"
   room="IT Room"
   floor="3rd Floor"


5. Helper Method: get_full_address()
   ==================================
   Builds a readable location string:
   
   >>> location.get_full_address()
   "Main DC - Rack-12 - Server Room A - 2nd Floor (DMZ, VLAN 100, 10.0.0.0/24)"
   
   Useful for:
   - Display in frontend dropdown
   - Reports
   - Logging


6. Practical Usage Example
   ========================
   # User "sina" creates a location
   dc_location = AssetLocation(
       site_name="Main Data Center",
       rack_name="Rack-12",
       room="Server Room A",
       floor="2nd Floor",
       network_zone="DMZ",
       vlan_id=100,
       subnet="10.0.0.0/24",
       description="Core network infrastructure rack",
       user_id=1  # sina's user_id
   )
   db.add(dc_location)
   db.commit()
   
   # Get all sina's locations
   sina_locations = db.query(AssetLocation).filter(
       AssetLocation.user_id == 1
   ).all()
   
   for loc in sina_locations:
       print(loc.get_full_address())
   
   # Output:
   # Main Data Center - Rack-12 - Server Room A - 2nd Floor (DMZ, VLAN 100, 10.0.0.0/24)


7. Integration with Asset
   =======================
   Later in asset.py, we'll add:
   
   class Asset(Base):
       location_id = Column(Integer, ForeignKey('asset_locations.id'))
       location = relationship("AssetLocation", backref="assets")
   
   Then we can do:
   - asset.location.site_name
   - asset.location.get_full_address()
   - location.assets (list of all assets at this location)


8. Index on Important Fields
   ==========================
   site_name: For searching by site
   network_zone: For filtering by zone
   user_id: Most common filter (data isolation)
   
   Speeds up queries like:
   - "Show all locations in DMZ"
   - "Show all locations at Main DC"
   - "Show all my locations"
"""