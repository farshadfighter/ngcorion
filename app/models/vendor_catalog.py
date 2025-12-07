"""
Vendor Catalog Model

This table stores standardized vendor/manufacturer definitions.
This is a shared reference table (not per-user).

Example: Cisco, Fortinet, HP, Dell, Palo Alto Networks
"""

from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base


class VendorCatalog(Base):
    """
    Vendor/Manufacturer Catalog Reference Table
    
    Stores standardized vendor/manufacturer names.
    Shared across all users (reference data).
    
    Attributes:
        id: Unique identifier (auto-generated)
        vendor_name: Vendor/manufacturer name
        vendor_type: Type of vendor (e.g., Network, Security, Server)
        website: Vendor website URL (optional)
        description: Additional information
    
    Common vendors:
        - Cisco (Network)
        - Fortinet (Security)
        - Palo Alto Networks (Security)
        - HP/HPE (Server)
        - Dell (Server)
    """
    
    __tablename__ = "vendor_catalog"
    
    # ====================================
    # Columns
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier"
    )
    
    vendor_name = Column(
        String(200),
        unique=True,
        nullable=False,
        index=True,
        comment="Vendor or manufacturer name (e.g., Cisco, HP, Dell)"
    )
    
    vendor_type = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Type of vendor (e.g., Network, Security, Server, Storage)"
    )
    
    website = Column(
        String(255),
        nullable=True,
        comment="Vendor website URL"
    )
    
    description = Column(
        Text,
        nullable=True,
        comment="Additional information about the vendor"
    )
    
    
    # ====================================
    # Helper Methods
    # ====================================
    
    def __repr__(self):
        return f"<VendorCatalog(id={self.id}, name='{self.vendor_name}')>"
    
    def __str__(self):
        if self.vendor_type:
            return f"{self.vendor_name} ({self.vendor_type})"
        return self.vendor_name


