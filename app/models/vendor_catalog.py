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


# ====================================
# Detailed Explanation:
# ====================================
"""
1. Why vendor_type field?
   ======================
   Helps categorize and filter vendors:
   
   Categories:
   - Network: Cisco, Juniper, Arista
   - Security: Fortinet, Palo Alto, Check Point
   - Server: HP, Dell, Lenovo
   - Storage: NetApp, EMC, Pure Storage
   - Virtualization: VMware, Citrix
   - Software: Microsoft, Oracle, Red Hat


2. Why unique=True for vendor_name?
   =================================
   Prevents duplicates:
   ✅ One "Cisco" entry
   ❌ Cannot add another "Cisco"
   
   If you need variations:
   - Cisco Systems
   - Cisco (Legacy)
   - Cisco Meraki
   These are different names, so allowed


3. Default data to insert:
   =======================
   INSERT INTO vendor_catalog (vendor_name, vendor_type, website) VALUES
   ('Cisco', 'Network', 'https://www.cisco.com'),
   ('Fortinet', 'Security', 'https://www.fortinet.com'),
   ('Palo Alto Networks', 'Security', 'https://www.paloaltonetworks.com'),
   ('Juniper Networks', 'Network', 'https://www.juniper.net'),
   ('HP', 'Server', 'https://www.hp.com'),
   ('Dell', 'Server', 'https://www.dell.com'),
   ('VMware', 'Virtualization', 'https://www.vmware.com'),
   ('Microsoft', 'Software', 'https://www.microsoft.com'),
   ('Arista', 'Network', 'https://www.arista.com'),
   ('Check Point', 'Security', 'https://www.checkpoint.com');


4. Usage in asset_inventory:
   ==========================
   Two approaches:
   
   Approach A - Direct string (current):
   asset.manufacturer = "Cisco"
   
   Approach B - Foreign Key:
   asset.vendor_id = 1  # References vendor_catalog.id
   
   Current implementation uses direct string for flexibility


5. Practical examples:
   ===================
   # Get all network vendors
   network_vendors = db.query(VendorCatalog).filter(
       VendorCatalog.vendor_type == 'Network'
   ).all()
   
   for vendor in network_vendors:
       print(vendor.vendor_name)
   
   # Output:
   # Cisco
   # Juniper Networks
   # Arista
   
   
   # Search for specific vendor
   cisco = db.query(VendorCatalog).filter(
       VendorCatalog.vendor_name == 'Cisco'
   ).first()
   
   print(f"Name: {cisco.vendor_name}")
   print(f"Type: {cisco.vendor_type}")
   print(f"Website: {cisco.website}")
   
   # Output:
   # Name: Cisco
   # Type: Network
   # Website: https://www.cisco.com


6. Why this is shared (not per-user)?
   ===================================
   Vendor names are universal:
   - "Cisco" means the same to everyone
   - Standardization is important
   - Easier to generate reports across all users
   
   Example benefit:
   "How many Cisco devices do we have across all users?"
   → Easy to query if everyone uses same vendor name


7. Admin can manage this centrally:
   =================================
   - Add new vendors as needed
   - Update vendor information
   - Ensure consistency
   
   Users select from this list (dropdown)
   Rather than typing manually (prevents typos)
"""