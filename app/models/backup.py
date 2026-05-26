from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship, backref
from datetime import datetime
from app.core.database import Base


class DeviceBackup(Base):
    """Stores device configuration backups taken manually or during hardening."""

    __tablename__ = "device_backups"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_name = Column(String(255), nullable=True)
    device_ip = Column(String(50), nullable=True)
    device_type = Column(String(30), nullable=True)  # cisco / fortinet
    config_content = Column(Text, nullable=False)
    source = Column(String(20), nullable=False, default="manual")  # manual | hardening
    hardening_action_id = Column(
        Integer,
        ForeignKey("hardening_actions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    asset = relationship("Asset", backref=backref("device_backups", passive_deletes=True))
    user = relationship("User", backref="device_backups")
