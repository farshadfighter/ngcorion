"""
Asset Dependencies Model

This table stores relationships and dependencies between assets.
Shows how assets are connected (network links, dependencies, etc.)

Example:
    Router-01 depends on Core-Switch-01 (network_link)
    App-Server depends on DB-Server (app_dependency)
"""

from sqlalchemy import Column, Integer, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship, backref
from app.core.database import Base
from app.models.enums import RelationTypeEnum


class AssetDependency(Base):
    """
    Asset Dependencies Table
    
    Stores relationships between assets.
    Shows which asset depends on which other asset.
    
    Attributes:
        id: Unique identifier (auto-generated)
        asset_id: The asset that has a dependency
        depends_on_id: The asset it depends on
        relation_type: Type of relationship (network_link, app_dependency, etc.)
        description: Additional notes about this dependency
    
    Example relationships:
        asset_id=5 (Router) depends_on_id=3 (Switch) via network_link
        asset_id=10 (App) depends_on_id=12 (Database) via app_dependency
    
    Relationships:
        asset: The dependent asset (forward)
        depends_on: The asset being depended upon (forward)
    """
    
    __tablename__ = "asset_dependencies"
    
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier for dependency record"
    )
    
    asset_id = Column(
        Integer,
        ForeignKey('asset_inventory.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="The asset that has a dependency (dependent asset)"
    )
    
    depends_on_id = Column(
        Integer,
        ForeignKey('asset_inventory.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="The asset that is depended upon (dependency target)"
    )

    
    relation_type = Column(
        Enum(RelationTypeEnum),
        nullable=False,
        index=True,
        comment="Type of relationship (network_link, app_dependency, backup_link, power_source, logical_connection)"
    )

    description = Column(
        Text,
        nullable=True,
        comment="Additional notes or details about this dependency"
    )
    

    # Forward relationship: dependency -> asset
    asset = relationship(
        "Asset",
        foreign_keys=[asset_id],
        backref=backref("dependencies", passive_deletes=True)
    )
    
    # Forward relationship: dependency -> depends_on
    depends_on = relationship(
        "Asset",
        foreign_keys=[depends_on_id],
        backref=backref("dependents", passive_deletes=True)
    )
    

    def __repr__(self):
        return f"<AssetDependency(id={self.id}, asset={self.asset_id}, depends_on={self.depends_on_id}, type={self.relation_type.value})>"
    
    def __str__(self):
        return f"Asset {self.asset_id} depends on Asset {self.depends_on_id} ({self.relation_type.value})"
    
    
    def get_description(self):
        """
        Returns a human-readable description of the dependency
        
        Example:
            >>> dep.get_description()
            "Router-01 depends on Core-Switch-01 via network_link"
        """
        asset_name = self.asset.asset_name if self.asset else f"Asset {self.asset_id}"
        depends_name = self.depends_on.asset_name if self.depends_on else f"Asset {self.depends_on_id}"
        
        return f"{asset_name} depends on {depends_name} via {self.relation_type.value}"


"""
1. What is a dependency?
   =====================
   A dependency shows that one asset relies on another:
   
   Example 1 - Network dependency:
   Router-01 → connects to → Core-Switch-01
   (Router needs Switch to function)
   
   Example 2 - Application dependency:
   Web-Server → needs → Database-Server
   (Web app needs DB to work)
   
   Example 3 - Power dependency:
   Server-01 → powered by → UPS-01
   (Server relies on UPS for power)


2. Why CASCADE delete?
   ===================
   If an asset is deleted:
   - All its dependency records should be deleted too
   - Otherwise we'd have orphaned records pointing to non-existent assets
   
   Example:
   Router-01 (id=5) is deleted
   → All dependencies where asset_id=5 are deleted
   → All dependencies where depends_on_id=5 are deleted


3. Two Foreign Keys to same table:
   ================================
   Both asset_id and depends_on_id reference asset_inventory:
   
   asset_dependencies
   ├── asset_id → asset_inventory.id
   └── depends_on_id → asset_inventory.id
   
   This creates a self-referential relationship
   (table references itself)
   
4. Relation Types (from RelationTypeEnum):
   ========================================
   - network_link: Physical/logical network connection
   - app_dependency: Application-level dependency
   - backup_link: Redundant/backup connection
   - power_source: Power supply dependency
   - logical_connection: Other logical relationships

5. Relationships explanation:
   ==========================
   We have TWO relationships because we reference the same table twice:
   
   a) asset (forward):
      dependency.asset → Returns the dependent asset
      Example: dependency.asset.asset_name → "Router-01"
   
   b) depends_on (forward):
      dependency.depends_on → Returns what it depends on
      Example: dependency.depends_on.asset_name → "Switch-01"
   
   c) dependencies (backref from asset):
      asset.dependencies → All dependencies this asset has
      Example: router.dependencies → [depends on Switch, depends on UPS]
   
   d) dependents (backref from depends_on):
      asset.dependents → All assets that depend on this one
      Example: switch.dependents → [Router depends on me, Firewall depends on me]


6. Practical Usage Examples:
   ==========================
   # Create a dependency
   dep = AssetDependency(
       asset_id=2,  # Router-01
       depends_on_id=1,  # Core-Switch-01
       relation_type=RelationTypeEnum.NETWORK_LINK,
       description="Router uplink to core switch"
   )
   db.add(dep)
   db.commit()
   
   
   # Find what an asset depends on
   router = db.query(Asset).filter(Asset.id == 2).first()
   print("Router depends on:")
   for dep in router.dependencies:
       print(f"  - {dep.depends_on.asset_name} ({dep.relation_type.value})")
   
   # Output:
   # Router depends on:
   #   - Core-Switch-01 (network_link)
   #   - UPS-01 (power_source)
   
   
   # Find what depends on an asset
   switch = db.query(Asset).filter(Asset.id == 1).first()
   print("Assets that depend on Switch:")
   for dep in switch.dependents:
       print(f"  - {dep.asset.asset_name} ({dep.relation_type.value})")
   
   # Output:
   # Assets that depend on Switch:
   #   - Router-01 (network_link)
   #   - Firewall-01 (network_link)


7. Use Cases:
   ===========
   a) Network Topology:
      Show how network devices are connected
   
   b) Impact Analysis:
      "If Switch-01 fails, what else will be affected?"
      → Query all dependents
   
   c) Application Dependencies:
      "What does this app need to run?"
      → Query all dependencies
   
   d) Power Planning:
      "Which devices are on which UPS?"
      → Query by relation_type=power_source


8. Data Isolation:
   ===============
   This table doesn't have user_id because:
   - Dependencies are between assets
   - Assets already have user_id
   - So dependencies inherit user context from assets
   
   To get user's dependencies:
   user_assets = db.query(Asset).filter(Asset.user_id == 1).all()
   asset_ids = [a.id for a in user_assets]
   user_deps = db.query(AssetDependency).filter(
       AssetDependency.asset_id.in_(asset_ids)
   ).all()
"""