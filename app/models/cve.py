"""
Local CVE database.

A local copy of every published CVE (from NVD), enriched with the CISA
Known Exploited Vulnerabilities list and FIRST EPSS scores, so findings work
on networks without internet access. It is loaded once (from the snapshot
shipped with a release, a full download, or a signed package) and kept
current by online incremental updates or offline packages
(app/modules/cve/jobs.py).

Matching is by CPE: each CVE lists the vendor/product/version ranges it
affects (CveCpeMatch), and each asset is described by the products it runs
(inferred from its fields - app/modules/cve/cpe.py - plus AssetSoftware rows
added by hand). Findings are computed at read time.
"""
from datetime import datetime

from sqlalchemy import (
    JSON, BigInteger, Boolean, Column, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)

from app.core.database import Base


class CveEntry(Base):
    __tablename__ = "cve_entries"

    cve_id = Column(String(32), primary_key=True)
    published = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True, index=True)
    status = Column(String(32), nullable=True)          # NVD vulnStatus
    description = Column(Text, nullable=False, default="")
    cvss_score = Column(Float, nullable=True)
    cvss_version = Column(String(8), nullable=True)
    severity = Column(String(16), nullable=True, index=True)  # critical | high | medium | low | none
    cvss_vector = Column(String(200), nullable=True)
    cwe = Column(String(200), nullable=True)
    references = Column(JSON, nullable=True)            # a few URLs, advisories first

    # CISA Known Exploited Vulnerabilities
    kev = Column(Boolean, nullable=False, default=False, index=True)
    kev_added = Column(Date, nullable=True)
    kev_due = Column(Date, nullable=True)
    kev_ransomware = Column(String(16), nullable=True)
    kev_action = Column(Text, nullable=True)

    # FIRST EPSS
    epss = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)

    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CveCpeMatch(Base):
    """One vulnerable CPE criterion of a CVE: a product, and either an exact
    version or a version range."""

    __tablename__ = "cve_cpe_matches"
    __table_args__ = (Index("ix_cve_cpe_matches_vendor_product", "vendor", "product"),)

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    cve_id = Column(String(32), ForeignKey("cve_entries.cve_id", ondelete="CASCADE"), nullable=False, index=True)
    part = Column(String(1), nullable=True)             # a (application) | o (OS) | h (hardware)
    vendor = Column(String(120), nullable=False)
    product = Column(String(160), nullable=False)
    version = Column(String(80), nullable=True)         # exact version, or "*" / "-" for "see range"
    start_incl = Column(String(80), nullable=True)
    start_excl = Column(String(80), nullable=True)
    end_incl = Column(String(80), nullable=True)
    end_excl = Column(String(80), nullable=True)


class AssetSoftware(Base):
    """A product an asset runs, added by hand (e.g. Apache 2.4.52 on web-01)
    when it cannot be inferred from the asset's own fields."""

    __tablename__ = "asset_software"
    __table_args__ = (UniqueConstraint("asset_id", "vendor", "product", "version", name="uq_asset_software"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    vendor = Column(String(120), nullable=False)
    product = Column(String(160), nullable=False)
    version = Column(String(80), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


CVE_JOB_ACTIVE = ("queued", "running")
CVE_JOB_FINAL = ("succeeded", "failed", "cancelled")


class CveUpdateJob(Base):
    """One load/update/import/export of the CVE database."""

    __tablename__ = "cve_update_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    kind = Column(String(16), nullable=False)           # online | full | offline | bundle | export
    trigger = Column(String(16), nullable=False, default="manual")  # manual | automatic
    status = Column(String(16), nullable=False, default="queued", index=True)
    progress = Column(JSON, nullable=True)              # {"step", "done", "total", "message"}
    stats = Column(JSON, nullable=True)                 # {"new", "changed", "kev", "epss", ...}
    error = Column(Text, nullable=True)
    file_name = Column(String(255), nullable=True)
    requested_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    # Set by Cancel; the job checks it, whichever worker process runs it.
    cancel_requested = Column(Boolean, nullable=False, default=False, server_default="false")
    runner = Column(String(160), nullable=True)         # app/core/singleton.runner_tag()


class CveSetting(Base):
    """Key/value state: update watermark, auto-update schedule, NVD API key
    (encrypted), this instance's package-signing key (encrypted)."""

    __tablename__ = "cve_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CveTrustedKey(Base):
    """A public key whose update packages this instance accepts."""

    __tablename__ = "cve_trusted_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(120), nullable=False)
    public_key = Column(String(100), nullable=False)    # base64 raw Ed25519 public key
    fingerprint = Column(String(64), nullable=False, unique=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
