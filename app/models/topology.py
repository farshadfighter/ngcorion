"""
Topology Link Model

Physical/logical cabling between two assets. Nodes are Asset rows directly
(asset_inventory) - there is no separate topology-node table.
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class TopologyLink(Base):
    """A cable/link between two assets, with the specific ports it connects."""

    __tablename__ = "topology_links"

    id = Column(Integer, primary_key=True, index=True)
    source_asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    destination_asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_interface = Column(String(50), nullable=True)
    destination_interface = Column(String(50), nullable=True)
    link_type = Column(String(30), nullable=False, default="ethernet")  # ethernet | fiber | wireless | logical
    speed_mbps = Column(Integer, nullable=True)
    vlan = Column(String(20), nullable=True)
    subnet = Column(String(50), nullable=True)
    status = Column(String(20), nullable=False, default="active")  # active | planned | down
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    source_asset = relationship("Asset", foreign_keys=[source_asset_id])
    destination_asset = relationship("Asset", foreign_keys=[destination_asset_id])
    user = relationship("User", backref="topology_links")
