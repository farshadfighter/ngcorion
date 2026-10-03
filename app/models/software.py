"""
Software inventory (app/modules/software): what is actually installed on
each asset, collected by audits (or on demand) - not entered by hand.

SoftwareItem        one installed package / program / update / service or
                    firmware version, as last collected. A collection
                    replaces the items of its own collector only, so a
                    Linux package list and an Apache audit's version live
                    side by side.
SoftwareCollection  one collection run: when, from which audit, how many
                    items, what changed.
SoftwareChange      added / removed / updated items between two collections
                    of an asset (kept a year).
SoftwareProductMap  an admin's answer for a name the catalog does not know:
                    this NVD vendor:product, or "internal, not in NVD".
                    Applies fleet-wide.
"""
from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.core.database import Base

# SoftwareItem.source
SRC_DISTRO = "distro"
SRC_THIRD_PARTY = "third_party"
SRC_MANUAL = "manual"
SRC_WINDOWS = "windows"
SRC_SERVICE = "service"
SRC_FIRMWARE = "firmware"
SOURCES = (SRC_DISTRO, SRC_THIRD_PARTY, SRC_MANUAL, SRC_WINDOWS, SRC_SERVICE, SRC_FIRMWARE)
# Sources matched against NVD in phase 1. Distribution packages wait for the
# distribution's own advisories (USN / OVAL), see app/modules/software/collect.py.
NVD_SOURCES = (SRC_THIRD_PARTY, SRC_MANUAL, SRC_WINDOWS, SRC_SERVICE, SRC_FIRMWARE)

# SoftwareItem.collector - which collection owns the item
COLLECTORS = ("linux", "windows", "apache", "mongodb", "mssql", "cisco", "fortinet")
# Collectors that describe everything installed (a full package list)
FULL_COLLECTORS = ("linux", "windows")

# SoftwareProductMap.status
MAP_CPE = "cpe"
MAP_INTERNAL = "internal"


class SoftwareItem(Base):
    __tablename__ = "software_items"
    __table_args__ = (Index("ix_software_items_asset_collector", "asset_id", "collector"),)

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    collector = Column(String(16), nullable=False)
    kind = Column(String(12), nullable=False, default="package")    # package | program | hotfix | os | service | firmware
    name = Column(String(300), nullable=False, index=True)
    version = Column(String(160), nullable=True)
    arch = Column(String(60), nullable=True)
    source = Column(String(16), nullable=False, index=True)
    origin = Column(String(200), nullable=True)                     # repository / PPA / Release origin
    publisher = Column(String(200), nullable=True)
    source_package = Column(String(200), nullable=True)
    source_version = Column(String(160), nullable=True)             # deb: the source's version, when it differs
    vkind = Column(String(4), nullable=True)                        # deb | rpm | win | svc | fw (version format)
    collection_id = Column(Integer, ForeignKey("software_collections.id", ondelete="SET NULL"), nullable=True)
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)


class SoftwareCollection(Base):
    __tablename__ = "software_collections"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    collector = Column(String(16), nullable=False)
    trigger = Column(String(10), nullable=False, default="audit")   # audit | manual
    audit_session_id = Column(Integer, ForeignKey("audit_sessions.id", ondelete="SET NULL"), nullable=True)
    collected_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    collected_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    status = Column(String(8), nullable=False, default="ok")        # ok | failed
    error = Column(Text, nullable=True)
    item_count = Column(Integer, nullable=False, default=0)
    added = Column(Integer, nullable=False, default=0)
    removed = Column(Integer, nullable=False, default=0)
    updated = Column(Integer, nullable=False, default=0)
    summary = Column(JSON, nullable=True)                           # {"by_source": {...}, "os": "..."}


class SoftwareChange(Base):
    __tablename__ = "software_changes"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    collection_id = Column(Integer, ForeignKey("software_collections.id", ondelete="CASCADE"), nullable=False,
                           index=True)
    change = Column(String(8), nullable=False)                      # added | removed | updated
    kind = Column(String(12), nullable=False, default="package")
    name = Column(String(300), nullable=False)
    old_version = Column(String(160), nullable=True)
    new_version = Column(String(160), nullable=True)
    source = Column(String(16), nullable=True)
    origin = Column(String(200), nullable=True)
    at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)


class SoftwareProductMap(Base):
    __tablename__ = "software_product_maps"

    id = Column(Integer, primary_key=True)
    match_key = Column(String(300), nullable=False, unique=True)
    status = Column(String(10), nullable=False, default=MAP_CPE)    # cpe | internal
    vendor = Column(String(120), nullable=True)
    product = Column(String(160), nullable=True)
    label = Column(String(200), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
