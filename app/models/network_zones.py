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
    

    
    def __repr__(self):
        return f"<NetworkZone(id={self.id}, name='{self.zone_name}')>"
    
    def __str__(self):
        return self.zone_name
