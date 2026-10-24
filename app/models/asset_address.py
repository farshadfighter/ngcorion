"""
Other addresses of an asset, besides its inventory IP address.

A device often sends syslog from another interface than the one it is managed on (a FortiGate's logging
interface, the two units of an HA cluster). Syslog from any of these addresses is the asset's
(app/modules/syslog/intake.py). An address belongs to one asset only, and is never another asset's
inventory address.
"""
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint

from app.core.database import Base


class AssetAddress(Base):
    __tablename__ = "asset_addresses"
    __table_args__ = (UniqueConstraint("address", name="uq_asset_addresses_address"),)

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    address = Column(String(45), nullable=False, comment="IPv4 or IPv6, normalised")
    note = Column(String(120), nullable=True, comment="What the address is, e.g. logging interface")
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
