"""
Asset Security Status Model

This table stores security-related information for assets.
Tracks antivirus, firewall, patches, backups, vulnerabilities, and compliance.

Example:
    security_status = AssetSecurityStatus(
        asset_id=5,
        antivirus_installed=True,
        antivirus_status="Active",
        firewall_enabled=True,
        last_patch_date="2025-01-15",
        backup_enabled=True,
        vulnerability_score=7.5,
        compliance_status="Compliant"
    )
"""

from sqlalchemy import Column, Integer, ForeignKey, Boolean, String, Date, Float, Text
from sqlalchemy.orm import relationship, backref
from datetime import date
from app.core.database import Base


class AssetSecurityStatus(Base):
    """
    Asset Security Status Table
    
    Stores security and compliance information for assets.
    One-to-one relationship with asset_inventory.
    
    Relationships:
        asset: The asset this security status belongs to
    """
    
    __tablename__ = "asset_security_status"
    

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier for security status record"
    )
    

    
    asset_id = Column(
        Integer,
        ForeignKey('asset_inventory.id', ondelete='CASCADE'),
        unique=True,  # One-to-one relationship
        nullable=False,
        index=True,
        comment="Reference to asset_inventory (one-to-one relationship)"
    )
    

    
    antivirus_installed = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether antivirus software is installed"
    )
    
    antivirus_status = Column(
        String(50),
        nullable=True,
        comment="Status of antivirus (e.g., Active, Outdated, Disabled, Not Applicable)"
    )

    firewall_enabled = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether firewall is enabled"
    )
    

    
    last_patch_date = Column(
        Date,
        nullable=True,
        comment="Date of last security patch or update"
    )

    
    backup_enabled = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether backup is configured and enabled"
    )
    

    
    vulnerability_score = Column(
        Float,
        nullable=True,
        comment="Vulnerability score (0-10, CVSS or custom scale)"
    )
    

    compliance_status = Column(
        String(50),
        nullable=True,
        index=True,
        comment="Compliance state (e.g., Compliant, Non-Compliant, Partially Compliant, Under Review)"
    )
    

    notes = Column(
        Text,
        nullable=True,
        comment="Additional security notes or observations"
    )
    

    
    asset = relationship(
        "Asset",
        backref=backref("security_status", passive_deletes=True, uselist=False)
    )
    

    
    def __repr__(self):
        return f"<AssetSecurityStatus(id={self.id}, asset_id={self.asset_id}, compliance='{self.compliance_status}')>"
    
    def __str__(self):
        asset_name = self.asset.asset_name if self.asset else f"Asset {self.asset_id}"
        return f"Security Status for {asset_name}: {self.compliance_status or 'Unknown'}"
    
    
    def is_patch_current(self, days_threshold=30):
        """
        Check if patches are current (within threshold)
        
        Args:
            days_threshold: Maximum days since last patch (default 30)
        
        Returns:
            bool: True if patches are current, False otherwise
        
        Example:
            >>> status.is_patch_current(30)
            False  # Last patch was 45 days ago
        """
        if not self.last_patch_date:
            return False
        
        days_since_patch = (date.today() - self.last_patch_date).days
        return days_since_patch <= days_threshold
    
    
    def get_security_summary(self):
        """
        Returns a summary of security status
        
        Returns:
            dict: Security status summary
        
        Example:
            >>> status.get_security_summary()
            {
                'antivirus': 'Installed and Active',
                'firewall': 'Enabled',
                'backup': 'Enabled',
                'patch_status': 'Current',
                'vulnerability': 'Medium (7.5)',
                'compliance': 'Compliant'
            }
        """
        # Antivirus status
        if self.antivirus_installed:
            av_status = f"Installed ({self.antivirus_status or 'Unknown status'})"
        else:
            av_status = "Not Installed"
        
        # Firewall status
        fw_status = "Enabled" if self.firewall_enabled else "Disabled"
        
        # Backup status
        backup_status = "Enabled" if self.backup_enabled else "Disabled"
        
        # Patch status
        if self.is_patch_current():
            patch_status = "Current"
        elif self.last_patch_date:
            patch_status = "Outdated"
        else:
            patch_status = "Unknown"
        
        # Vulnerability
        if self.vulnerability_score is not None:
            if self.vulnerability_score < 4:
                vuln_level = "Low"
            elif self.vulnerability_score < 7:
                vuln_level = "Medium"
            else:
                vuln_level = "High"
            vuln_status = f"{vuln_level} ({self.vulnerability_score})"
        else:
            vuln_status = "Not Assessed"
        
        return {
            'antivirus': av_status,
            'firewall': fw_status,
            'backup': backup_status,
            'patch_status': patch_status,
            'vulnerability': vuln_status,
            'compliance': self.compliance_status or "Unknown"
        }



