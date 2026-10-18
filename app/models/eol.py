"""
End of life: which operating systems, firmware and server software of the assets are out of (or close to
the end of) their vendor's support (app/modules/eol).

The built-in catalog ships with the code (app/modules/eol/catalog.json, from endoflife.date). These tables
hold what an installation adds to it:

  EolProduct     a product of the catalog as last downloaded from endoflife.date or imported from a file
                 (replaces the built-in one with the same key), or the organisation's own product - a
                 firmware endoflife.date does not track - with the software names it is recognised by
  EolAssetEntry  the end of support of something on one asset that the inventory does not see (a
                 camera's firmware, an appliance), entered by hand
"""
from datetime import datetime

from sqlalchemy import JSON, Column, Date, DateTime, ForeignKey, Integer, String, Text

from app.core.database import Base

SOURCE_ONLINE = "online"
SOURCE_IMPORT = "import"
SOURCE_CUSTOM = "custom"


class EolProduct(Base):
    __tablename__ = "eol_products"

    id = Column(Integer, primary_key=True)
    key = Column(String(60), nullable=False, unique=True)          # "ubuntu", "custom-hikvision-ipc"
    name = Column(String(120), nullable=False)
    source = Column(String(10), nullable=False)                    # online | import | custom
    link = Column(String(300), nullable=True)
    match_names = Column(JSON, nullable=True)                      # custom: software names, case-insensitive
    cycles = Column(JSON, nullable=False, default=list)            # as in catalog.json
    updated_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class EolAssetEntry(Base):
    __tablename__ = "eol_asset_entries"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False)                     # "Hikvision DS-2CD2143 firmware"
    version = Column(String(80), nullable=True)
    support_until = Column(Date, nullable=False)                   # end of security support
    note = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
