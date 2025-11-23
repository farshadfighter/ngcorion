"""
Asset Inventory Model (Simplified Version for Learning)

This is a simplified version to demonstrate Foreign Key relationships.
We'll create the complete version later.
"""

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base


class Asset(Base):
    """
    Main Asset Inventory Table (Simplified)
    
    This demonstrates how Foreign Keys connect tables together.
    
    Example:
        asset = Asset(
            asset_name="Core-Switch-01",
            asset_type_id=3  # References asset_types.id = 3 (Switch)
        )
    """
    
    __tablename__ = "asset_inventory"
    
    # ====================================
    # Basic Columns
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier"
    )
    
    asset_name = Column(
        String(200),
        nullable=False,
        index=True,
        comment="Name of the asset (e.g., Core-Switch-01)"
    )
    
    # ====================================
    # Foreign Key to asset_types
    # ====================================
    
    asset_type_id = Column(
        Integer,
        ForeignKey('asset_types.id', ondelete='RESTRICT'),
        nullable=False,
        comment="Reference to asset_types table"
    )
    
    # ====================================
    # Relationship (SQLAlchemy magic!)
    # ====================================
    
    asset_type = relationship(
        "AssetType",
        backref="assets"
    )
    
    
    def __repr__(self):
        return f"<Asset(id={self.id}, name='{self.asset_name}')>"
    
    def __str__(self):
        return f"{self.asset_name} (Type: {self.asset_type.type_name if self.asset_type else 'Unknown'})"


# ====================================
# Detailed Explanation:
# ====================================
"""
1. What is ForeignKey?
   =====================
   ForeignKey('asset_types.id') means:
   - This column stores an ID
   - That ID must exist in asset_types.id
   - Creates a link between two tables
   
   Example:
   asset_types:
   id | type_name
   1  | Firewall
   2  | Router
   3  | Switch
   
   asset_inventory:
   id | asset_name     | asset_type_id
   1  | FW-01          | 1  ← Links to "Firewall"
   2  | Core-Router    | 2  ← Links to "Router"
   3  | Switch-01      | 3  ← Links to "Switch"


2. What is ondelete='RESTRICT'?
   =============================
   Prevents deletion if referenced:
   
   ✅ Allowed:
   - Delete asset_type "Router" if NO assets use it
   
   ❌ Blocked:
   - Delete asset_type "Router" if 5 assets are using it
   - Database returns error: "Cannot delete, still in use"
   
   Other options:
   - CASCADE: Delete all related assets too (dangerous!)
   - SET NULL: Set asset_type_id to NULL (asset loses its type)


3. What is relationship()?
   ========================
   This is SQLAlchemy magic that lets you access related data easily!
   
   WITHOUT relationship:
   ---------------------
   asset = db.query(Asset).first()
   # To get asset type, you need another query:
   asset_type = db.query(AssetType).filter(AssetType.id == asset.asset_type_id).first()
   print(asset_type.type_name)
   
   WITH relationship:
   ------------------
   asset = db.query(Asset).first()
   # Direct access! No extra query needed:
   print(asset.asset_type.type_name)  ← Magic!


4. What is backref="assets"?
   ==========================
   Creates REVERSE relationship automatically!
   
   Forward direction (asset → type):
   ----------------------------------
   asset = db.query(Asset).first()
   print(asset.asset_type.type_name)  # "Firewall"
   
   Reverse direction (type → assets):
   -----------------------------------
   firewall_type = db.query(AssetType).filter(AssetType.type_name == "Firewall").first()
   print(firewall_type.assets)  # List of all Firewall assets
   
   Example output:
   [<Asset(id=1, name='FW-01')>, <Asset(id=5, name='FW-02')>, ...]


5. Practical Usage Example:
   =========================
   # Create an asset
   new_asset = Asset(
       asset_name="Core-Switch-01",
       asset_type_id=3  # Must exist in asset_types
   )
   db.add(new_asset)
   db.commit()
   
   # Access related data
   print(new_asset.asset_type.type_name)  # "Switch"
   print(new_asset.asset_type.category)   # "Network"
   
   # Find all switches
   switch_type = db.query(AssetType).filter(AssetType.type_name == "Switch").first()
   all_switches = switch_type.assets
   print(f"Total switches: {len(all_switches)}")
"""