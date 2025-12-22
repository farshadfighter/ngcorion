"""
Port and Protocol Models

These models store port and protocol information for assets.
Each asset can have multiple ports, and each port has associated protocol information (TCP/UDP).
"""

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class Protocol(Base):
    """
    Protocol reference table

    Stores protocol information (TCP, UDP, etc.)
    This is a reference table that can be extended with more protocol types.
    """
    __tablename__ = "protocols"

    id = Column(
        Integer,  
        primary_key=True,
        autoincrement=True,
        comment="Protocol ID"
    )

    name = Column(
        String(20),
        unique=True,
        nullable=False,
        index=True,
        comment="Protocol name (TCP, UDP, SCTP, etc.)"
    )

    description = Column(
        String(200),
        nullable=True,
        comment="Protocol description"
    )

    # Timestamps
    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        comment="Record creation timestamp"
    )

    # Relationships
    ports = relationship("Port", back_populates="protocol")

    def __repr__(self):
        return f"<Protocol(id={self.id}, name='{self.name}')>"


class Port(Base):
    """
    Port information for assets

    Stores port numbers and their associated protocol for each asset.
    Tracks which ports are open/discovered on each asset.

    Attributes:
        id: Primary key
        asset_id: Foreign key to asset_inventory
        port_number: Port number (1-65535)
        protocol_id: Foreign key to protocols table
        service_name: Service running on this port (e.g., http, ssh, mysql)
        service_product: Product name (e.g., nginx, OpenSSH, MySQL)
        service_version: Version of the service
        state: Port state (open, closed, filtered)
        discovered_by_scan_id: Which scan discovered this port
        is_active: Whether this port is currently active
        notes: Additional notes about this port
    """
    __tablename__ = "ports"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Port record ID"
    )

    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Asset this port belongs to"
    )

    port_number = Column(
        Integer,
        nullable=False,
        index=True,
        comment="Port number (1-65535)"
    )

    protocol_id = Column(
        Integer,
        ForeignKey("protocols.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Protocol type (TCP, UDP, etc.)"
    )

    service_name = Column(
        String(100),
        nullable=True,
        comment="Service name (http, ssh, mysql, etc.)"
    )

    service_product = Column(
        String(100),
        nullable=True,
        comment="Product name (nginx, Apache, OpenSSH, etc.)"
    )

    service_version = Column(
        String(100),
        nullable=True,
        comment="Service version"
    )

    state = Column(
        String(20),
        default="open",
        comment="Port state: open, closed, filtered"
    )

    discovered_by_scan_id = Column(
        String(50),
        ForeignKey("discovery_scans.scan_id", ondelete="SET NULL"),
        nullable=True,
        comment="Scan that discovered this port"
    )

    is_active = Column(
        Boolean,
        default=True,
        comment="Whether this port is currently active"
    )

    notes = Column(
        Text,
        nullable=True,
        comment="Additional notes about this port"
    )

    # Timestamps
    discovered_at = Column(
        DateTime,
        default=datetime.utcnow,
        comment="When this port was first discovered"
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        comment="Last update timestamp"
    )

    # Relationships
    asset = relationship("Asset", back_populates="ports")
    protocol = relationship("Protocol", back_populates="ports")
    discovered_by_scan = relationship("DiscoveryScan", foreign_keys=[discovered_by_scan_id])

    def __repr__(self):
        return f"<Port(asset_id={self.asset_id}, port={self.port_number}, protocol={self.protocol.name if self.protocol else 'Unknown'})>"

    def to_dict(self):
        """Convert port to dictionary"""
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "port_number": self.port_number,
            "protocol": self.protocol.name if self.protocol else None,
            "service_name": self.service_name,
            "service_product": self.service_product,
            "service_version": self.service_version,
            "state": self.state,
            "is_active": self.is_active,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "notes": self.notes
        }


# Helper function to seed protocols
def seed_protocols(db):
    """Seed initial protocol data"""
    protocols = [
        {"name": "TCP", "description": "Transmission Control Protocol"},
        {"name": "UDP", "description": "User Datagram Protocol"},
        {"name": "SCTP", "description": "Stream Control Transmission Protocol"},
    ]

    for proto_data in protocols:
        existing = db.query(Protocol).filter(Protocol.name == proto_data["name"]).first()
        if not existing:
            protocol = Protocol(**proto_data)
            db.add(protocol)

    db.commit()
