"""
OS Catalog Model

This table stores standardized operating system definitions.
This is a shared reference table (not per-user).

Example: Windows Server 2019, Ubuntu 22.04, FortiOS 7.2
"""

from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base


class OSCatalog(Base):
    """
    Operating System Catalog Reference Table
    
    Stores standardized OS names and versions.
    Shared across all users (reference data).
    
    Attributes:
        id: Unique identifier (auto-generated)
        os_name: Operating system name
        os_version: Version information (optional)
        os_family: OS family/category (e.g., Windows, Linux, Network OS)
        description: Additional information
    
    Common OS entries:
        - Windows Server 2019
        - Ubuntu 22.04 LTS
        - FortiOS 7.2
        - Cisco IOS-XE 17.9
    """
    
    __tablename__ = "os_catalog"
    
    # ====================================
    # Columns
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier"
    )
    
    os_name = Column(
        String(100),
        nullable=False,
        index=True,
        comment="Operating system name (e.g., Windows Server, Ubuntu, FortiOS)"
    )
    
    os_version = Column(
        String(50),
        nullable=True,
        comment="Version information (e.g., 2019, 22.04, 7.2)"
    )
    
    os_family = Column(
        String(50),
        nullable=True,
        index=True,
        comment="OS family or category (e.g., Windows, Linux, Network OS)"
    )
    
    description = Column(
        Text,
        nullable=True,
        comment="Additional information about this OS"
    )
    
    
    # ====================================
    # Helper Methods
    # ====================================
    
    def __repr__(self):
        return f"<OSCatalog(id={self.id}, name='{self.os_name}', version='{self.os_version}')>"
    
    def __str__(self):
        if self.os_version:
            return f"{self.os_name} {self.os_version}"
        return self.os_name
    
    
    def get_full_name(self):
        """
        Returns complete OS name with version
        
        Returns:
            str: Full OS name
        
        Example:
            >>> os.get_full_name()
            "Windows Server 2019"
        """
        parts = [self.os_name]
        if self.os_version:
            parts.append(self.os_version)
        return " ".join(parts)


# ====================================
# Detailed Explanation:
# ====================================
"""
1. Why separate os_name and os_version?
   ====================================
   Allows flexible searching and grouping:
   
   Query examples:
   - All Windows versions: filter by os_name="Windows Server"
   - Specific version: filter by os_version="2019"
   - By family: filter by os_family="Windows"


2. OS Family categories:
   =====================
   - Windows: Windows Server, Windows 10
   - Linux: Ubuntu, CentOS, RHEL
   - Network OS: FortiOS, Cisco IOS, PAN-OS
   - Unix: FreeBSD, Solaris
   - Virtualization: VMware ESXi, Proxmox


3. Default data to insert:
   =======================
   INSERT INTO os_catalog (os_name, os_version, os_family) VALUES
   ('Windows Server', '2019', 'Windows'),
   ('Windows Server', '2022', 'Windows'),
   ('Ubuntu', '22.04 LTS', 'Linux'),
   ('Ubuntu', '20.04 LTS', 'Linux'),
   ('CentOS', '8', 'Linux'),
   ('FortiOS', '7.2', 'Network OS'),
   ('Cisco IOS-XE', '17.9', 'Network OS'),
   ('PAN-OS', '11.0', 'Network OS'),
   ('VMware ESXi', '7.0', 'Virtualization');


4. Usage in asset_inventory:
   ==========================
   Two approaches:
   
   Approach A - Direct strings (current):
   asset.os_name = "Windows Server"
   asset.os_version = "2019"
   
   Approach B - Foreign Key (more structured):
   asset.os_id = 1  # References os_catalog.id
   
   Current implementation uses direct strings for flexibility


5. Practical example:
   ==================
   # Get all Linux OS
   linux_os = db.query(OSCatalog).filter(
       OSCatalog.os_family == 'Linux'
   ).all()
   
   for os in linux_os:
       print(os.get_full_name())
   
   # Output:
   # Ubuntu 22.04 LTS
   # Ubuntu 20.04 LTS
   # CentOS 8
   
   
   # Search for specific version
   win2019 = db.query(OSCatalog).filter(
       OSCatalog.os_name == 'Windows Server',
       OSCatalog.os_version == '2019'
   ).first()
   
   print(win2019)  # Windows Server 2019
"""