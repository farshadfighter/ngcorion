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
from sqlalchemy.orm import relationship
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
    
    # ====================================
    # Primary Key
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier for security status record"
    )
    
    # ====================================
    # Foreign Key - Asset Reference
    # ====================================
    
    asset_id = Column(
        Integer,
        ForeignKey('asset_inventory.id', ondelete='CASCADE'),
        unique=True,  # One-to-one relationship
        nullable=False,
        index=True,
        comment="Reference to asset_inventory (one-to-one relationship)"
    )
    
    # ====================================
    # Antivirus Information
    # ====================================
    
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
    
    # ====================================
    # Firewall Information
    # ====================================
    
    firewall_enabled = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether firewall is enabled"
    )
    
    # ====================================
    # Patch Management
    # ====================================
    
    last_patch_date = Column(
        Date,
        nullable=True,
        comment="Date of last security patch or update"
    )
    
    # ====================================
    # Backup Information
    # ====================================
    
    backup_enabled = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether backup is configured and enabled"
    )
    
    # ====================================
    # Vulnerability Assessment
    # ====================================
    
    vulnerability_score = Column(
        Float,
        nullable=True,
        comment="Vulnerability score (0-10, CVSS or custom scale)"
    )
    
    # ====================================
    # Compliance Status
    # ====================================
    
    compliance_status = Column(
        String(50),
        nullable=True,
        index=True,
        comment="Compliance state (e.g., Compliant, Non-Compliant, Partially Compliant, Under Review)"
    )
    
    # ====================================
    # Additional Notes
    # ====================================
    
    notes = Column(
        Text,
        nullable=True,
        comment="Additional security notes or observations"
    )
    
    # ====================================
    # Relationships
    # ====================================
    
    asset = relationship(
        "Asset",
        backref="security_status",
        uselist=False  # One-to-one relationship
    )
    
    
    # ====================================
    # Helper Methods
    # ====================================
    
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


# ====================================
# Detailed Explanation:
# ====================================
"""
1. One-to-One Relationship with Asset:
   ===================================
   Each asset has exactly ONE security status record:
   
   asset_id is unique=True:
   - Asset 1 → Security Status 1
   - Asset 2 → Security Status 2
   - Asset 1 cannot have Security Status 3 (unique constraint)
   
   In relationship:
   uselist=False means:
   - asset.security_status (singular, not a list)
   - Returns one object, not a list


2. Why CASCADE delete?
   ===================
   If an asset is deleted:
   - Its security status should be deleted too
   - No orphaned security records


3. Boolean Fields with default=False:
   ==================================
   antivirus_installed, firewall_enabled, backup_enabled
   
   Default False means:
   - Assume insecure by default
   - Must explicitly mark as True
   - Better for security posture (fail-secure)


4. Vulnerability Score (0-10):
   ===========================
   Based on CVSS (Common Vulnerability Scoring System):
   - 0.0: No vulnerability
   - 0.1-3.9: Low
   - 4.0-6.9: Medium
   - 7.0-8.9: High
   - 9.0-10.0: Critical


5. Compliance Status Values:
   =========================
   Common values:
   - "Compliant": Meets all requirements
   - "Non-Compliant": Fails requirements
   - "Partially Compliant": Some requirements met
   - "Under Review": Being assessed
   - "Not Applicable": Compliance not required


6. Practical Usage Examples:
   ==========================
   # Create security status for an asset
   security = AssetSecurityStatus(
       asset_id=5,
       antivirus_installed=True,
       antivirus_status="Active",
       firewall_enabled=True,
       last_patch_date=date(2025, 1, 15),
       backup_enabled=True,
       vulnerability_score=3.5,
       compliance_status="Compliant",
       notes="All security controls in place"
   )
   db.add(security)
   db.commit()
   
   
   # Access security status from asset
   asset = db.query(Asset).filter(Asset.id == 5).first()
   print(f"Antivirus: {asset.security_status.antivirus_status}")
   print(f"Vulnerability: {asset.security_status.vulnerability_score}")
   
   
   # Check if patches are current
   if asset.security_status.is_patch_current(30):
       print("Patches are up to date")
   else:
       print("Patches are outdated")
   
   
   # Get security summary
   summary = asset.security_status.get_security_summary()
   for key, value in summary.items():
       print(f"{key}: {value}")
   
   # Output:
   # antivirus: Installed (Active)
   # firewall: Enabled
   # backup: Enabled
   # patch_status: Current
   # vulnerability: Low (3.5)
   # compliance: Compliant


7. Finding Non-Compliant Assets:
   ==============================
   # Find all non-compliant assets
   non_compliant = db.query(AssetSecurityStatus).filter(
       AssetSecurityStatus.compliance_status == 'Non-Compliant'
   ).all()
   
   for status in non_compliant:
       print(f"Asset: {status.asset.asset_name}")
       print(f"Issues: {status.notes}")
   
   
   # Find assets without antivirus
   no_av = db.query(AssetSecurityStatus).filter(
       AssetSecurityStatus.antivirus_installed == False
   ).all()
   
   
   # Find high vulnerability assets
   high_vuln = db.query(AssetSecurityStatus).filter(
       AssetSecurityStatus.vulnerability_score >= 7.0
   ).all()


8. Data Isolation:
   ===============
   Like asset_dependencies, this table doesn't have user_id:
   - Security status belongs to an asset
   - Asset already has user_id
   - So security status inherits user context from asset
   
   To get user's security statuses:
   user_assets = db.query(Asset).filter(Asset.user_id == 1).all()
   for asset in user_assets:
       if asset.security_status:
           print(f"{asset.asset_name}: {asset.security_status.compliance_status}")


9. Integration with Asset List Views:
   ==================================
   For "Security / Risk / Audit" view in Asset List:
   
   Query:
   SELECT 
       a.id,
       a.asset_name,
       s.confidentiality_level,  # from asset_inventory
       s.risk_level,              # from asset_inventory
       ss.last_patch_date,        # from asset_security_status
       a.last_audit_date,         # from asset_inventory
       a.asset_value,             # from asset_inventory
       a.description              # from asset_inventory
   FROM asset_inventory a
   LEFT JOIN asset_security_status ss ON a.id = ss.asset_id
   WHERE a.user_id = ?
"""