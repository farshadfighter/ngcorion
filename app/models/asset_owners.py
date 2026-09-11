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
    

    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier for asset owner"
    )
    

    
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
    

    
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to users table - determines which user owns this owner record"
    )

    
    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        comment="Record creation timestamp"
    )
    

    
    user = relationship(
        "User",
        backref="asset_owners"
    )
    
    # Note: Relationship with Asset will be defined in asset.py
    # assets = relationship("Asset", backref="owner")
    

    
    def __repr__(self):
        return f"<AssetOwner(id={self.id}, name='{self.full_name}', dept='{self.department}')>"
    
    def __str__(self):
        return f"{self.full_name} ({self.department or 'No Department'})"


