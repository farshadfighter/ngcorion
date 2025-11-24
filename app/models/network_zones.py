"""
Network Zones Model

This table stores standardized network zones/segments.
This is a shared reference table (not per-user).

Example zones: DMZ, Internal, Management, Guest, External
"""

from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base


class NetworkZone(Base):
    """
    Network Zones Reference Table
    
    Stores standardized network zone definitions.
    Shared across all users (reference data).
    
    Attributes:
        id: Unique identifier (auto-generated)
        zone_name: Name of the network zone
        description: Description of the zone purpose
    
    Common zones:
        - DMZ (Demilitarized Zone)
        - Internal (Internal network)
        - Management (Management network)
        - Guest (Guest access)
        - External (Internet-facing)
    """
    
    __tablename__ = "network_zones"
    
    # ====================================
    # Columns
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier"
    )
    
    zone_name = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Network zone name (e.g., DMZ, Internal, Management)"
    )
    
    description = Column(
        Text,
        nullable=True,
        comment="Description of the zone purpose and characteristics"
    )
    
    
    # ====================================
    # Helper Methods
    # ====================================
    
    def __repr__(self):
        return f"<NetworkZone(id={self.id}, name='{self.zone_name}')>"
    
    def __str__(self):
        return self.zone_name


# ====================================
# Detailed Explanation:
# ====================================
"""
1. Why is this a shared table?
   ===========================
   Network zones are standard terminology:
   - DMZ, Internal, Management, etc.
   - All users should use the same terms
   - Ensures consistency across organization


2. No user_id field
   ================
   Unlike asset_owners and asset_locations:
   - This is NOT per-user data
   - One list for entire system
   - Admin can manage this list centrally


3. Default data to insert:
   =======================
   INSERT INTO network_zones (zone_name, description) VALUES
   ('DMZ', 'Demilitarized Zone - Public-facing services'),
   ('Internal', 'Internal corporate network'),
   ('Management', 'Management and administration network'),
   ('Guest', 'Guest and visitor access'),
   ('External', 'Internet-facing resources');


4. Usage in asset_locations:
   ==========================
   asset_locations.network_zone references this
   Either as:
   - String field (stores zone name directly)
   - Or FK field (references network_zones.id)
   
   Current implementation in asset_locations uses String
   For flexibility (users can type custom zones)


5. Practical example:
   ==================
   # Get all zones
   zones = db.query(NetworkZone).all()
   for zone in zones:
       print(zone.zone_name)
   
   # Output:
   # DMZ
   # Internal
   # Management
   # Guest
   # External
"""