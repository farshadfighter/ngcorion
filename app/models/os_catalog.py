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
