"""
Asset Owners Model

This table stores information about people who own/manage assets.
Each user has their own list of asset owners.

Example:
    owner = AssetOwner(
        full_name="Sina Bimesl",
        department="IT",
        role="Network Manager",
        email="fayatech@company.com",
        user_id=1  # Owner belongs to user with id=1
    )
"""

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class AssetOwner(Base):
    """
    Asset Owners Table
    
    Stores information about people responsible for assets.
    Each user maintains their own list of owners.
    
    Relationships:
        user: The user who created this owner record
        assets: List of assets owned by this person (reverse relationship)
    """
    
    __tablename__ = "asset_owners"
    
    # ====================================
    # Primary Key
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier for asset owner"
    )
    
    # ====================================
    # Owner Information
    # ====================================
    
    full_name = Column(
        String(200),
        nullable=False,
        index=True,
        comment="Full name of the asset owner"
    )
    
    department = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Department or team name (e.g., IT, Security, Network)"
    )
    
    role = Column(
        String(100),
        nullable=True,
        comment="Job role or position (e.g., Network Manager, Security Admin)"
    )
    
    email = Column(
        String(255),
        nullable=True,
        index=True,
        comment="Contact email address"
    )
    
    phone = Column(
        String(50),
        nullable=True,
        comment="Contact phone number"
    )
    
    responsibility_level = Column(
        String(50),
        nullable=True,
        comment="Level of responsibility (e.g., Primary, Secondary, Backup)"
    )
    
    # ====================================
    # Foreign Key - User Ownership
    # ====================================
    
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to users table - determines which user owns this owner record"
    )
    
    # ====================================
    # Timestamp
    # ====================================
    
    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        comment="Record creation timestamp"
    )
    
    # ====================================
    # Relationships
    # ====================================
    
    user = relationship(
        "User",
        backref="asset_owners"
    )
    
    # Note: Relationship with Asset will be defined in asset.py
    # assets = relationship("Asset", backref="owner")
    
    
    # ====================================
    # Helper Methods
    # ====================================
    
    def __repr__(self):
        return f"<AssetOwner(id={self.id}, name='{self.full_name}', dept='{self.department}')>"
    
    def __str__(self):
        return f"{self.full_name} ({self.department or 'No Department'})"


# ====================================
# Detailed Explanation:
# ====================================
"""
1. Why user_id with CASCADE?
   ==========================
   ondelete='CASCADE' means:
   - If a user is deleted
   - ALL their asset_owners records are automatically deleted too
   
   Example:
   User "sina" (id=1) has 3 asset owners:
   - Ali mansouri
   - Aylar Rezaei
   - Ahad zargar
   
   If user "sina" is deleted:
   → All 3 asset owners are automatically deleted
   
   Why CASCADE here?
   → Because asset_owners belong to the user
   → If user is gone, their owners list is meaningless


2. Data Isolation per User
   ========================
   Each user has their own list of owners:
   
   Database:
   id | full_name      | department | user_id
   1  | Aylar Rezaei     | IT         | 1 (sina)
   2  | Ali Mansouri | Security   | 1 (sina)
   3  | Ahad zargar  | Network    | 2 (ali)
   
   Query for user "sina":
   owners = db.query(AssetOwner).filter(AssetOwner.user_id == 1).all()
   → Returns: Aylar Rezaei, Ali Mansouri
   
   Query for user "ali":
   owners = db.query(AssetOwner).filter(AssetOwner.user_id == 2).all()
   → Returns: Ahad zargar


3. Why index=True on certain columns?
   ===================================
   Indexes speed up searches:
   
   full_name: Search by name
   department: Filter by department
   email: Search by email
   user_id: Filter by user (most common query!)
   
   Without index: 1000ms
   With index: 10ms


4. Why nullable=True for some fields?
   ===================================
   Not all information is always available:
   
   Required (nullable=False):
   - full_name: Must have a name
   - user_id: Must belong to a user
   
   Optional (nullable=True):
   - department: Might not know
   - phone: Might not have
   - email: Might not have


5. Practical Usage Example:
   =========================
   # User "sina" creates an owner
   owner = AssetOwner(
       full_name="Ali",
       department="Network",
       role="Senior Engineer",
       email="ali@company.com",
       phone="+98-914-1234567",
       responsibility_level="Primary",
       user_id=1  # sina's user_id
   )
   db.add(owner)
   db.commit()
   
   # Later, get all sina's owners
   sina_owners = db.query(AssetOwner).filter(
       AssetOwner.user_id == 1
   ).all()
   
   for owner in sina_owners:
       print(f"{owner.full_name} - {owner.department}")
   
   # Output:
   # Ali mansori - Network
   # Aylar rezaei - Security


6. Integration with Asset:
   ========================
   Later in asset.py, we'll add:
   
   class Asset(Base):
       owner_id = Column(Integer, ForeignKey('asset_owners.id'))
       owner = relationship("AssetOwner", backref="assets")
   
   Then we can do:
   - asset.owner.full_name
   - owner.assets (list of all assets this person owns)
"""