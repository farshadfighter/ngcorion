"""
Asset Types Model

This model defines different types of assets.
Examples: Firewall, Router, Switch, Server, etc.

This table is shared among all users.
"""

from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base


class AssetType(Base):
    """
    Asset Types Table

    This table maintains a list of device/software types.
    Examples: Firewall, Router, Switch, Server

    Attributes:
        id: Unique identifier (auto-generated)
        type_name: Asset type name (e.g., Firewall)
        category: Classification category (e.g., Security, Network, Infrastructure)
        description: Optional description

    Example:
        type = AssetType(
            type_name="Firewall",
            category="Security",
            description="Network security device"
        )
    """

    __tablename__ = "asset_types"

    # ====================================
    # Columns
    # ====================================

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier"
    )

    type_name = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Asset type name (e.g., Firewall)"
    )

    category = Column(
        String(50),
        nullable=False,
        index=True,  # For filtering by category
        comment="Category (Security, Network, Infrastructure, etc.)"
    )

    description = Column(
        Text,
        nullable=True,
        comment="Optional description"
    )


    # ====================================
    # Helper Methods for Display
    # ====================================

    def __repr__(self):
        """Readable representation for debugging"""
        return f"<AssetType(id={self.id}, name='{self.type_name}', category='{self.category}')>"


    def __str__(self):
        """Simple string representation"""
        return f"{self.type_name} ({self.category})"
