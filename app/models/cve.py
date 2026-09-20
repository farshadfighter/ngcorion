"""
CVE (vulnerability) tracking model.

A local table of known CVEs, matched against the real asset inventory's
`manufacturer`/`os_name`/`os_version` fields at read time (see
app/modules/cve/matcher.py) - there is deliberately no persisted "match"
table, since a match is only ever a function of (asset version, CVE record)
and recomputing it on every read keeps it always consistent with the latest
data in both tables, for an asset/CVE count this app operates at.

Populated two ways:
- A small, curated seed of well-documented, high-confidence CVEs for the
  vendors this app already has audit/hardening modules for (see
  app/modules/cve/seed_data.py) - so there is real, verifiable data with a
  fresh install and no internet access.
- An admin-triggered sync against the NVD REST API (app/modules/cve/
  nvd_sync.py), which upserts by cve_id - deliberately not an always-on
  background poller like NOC's, since a live NVD API call cannot be
  assumed to succeed from every deployment network.
"""
from sqlalchemy import Column, Integer, Float, String, Text, DateTime, UniqueConstraint
from datetime import datetime
from app.core.database import Base


class CveRecord(Base):
    """One row per (CVE, affected version branch) - a single CVE routinely
    affects several disjoint version branches (e.g. FortiOS 7.2.x AND 7.0.x
    AND 6.4.x for the same advisory), which a single min/max range can't
    represent, so cve_id is intentionally NOT unique on its own; the
    composite constraint below just stops an NVD re-sync from duplicating
    the same branch row."""

    __tablename__ = "cve_records"
    __table_args__ = (
        UniqueConstraint(
            "cve_id", "product_keyword", "affected_version_min", "affected_version_max",
            name="uq_cve_records_branch",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), nullable=False, index=True)  # e.g. "CVE-2022-42475"

    vendor = Column(String(100), nullable=False)   # display only, e.g. "Fortinet"
    product = Column(String(100), nullable=False)  # display only, e.g. "FortiOS"
    # Matched case-insensitively as a substring against Asset.os_name (falling
    # back to Asset.manufacturer) - same free-text keyword-match convention
    # already used for asset_type classification elsewhere in this app (see
    # front/src/components/shared/DeviceIcon.jsx, app/modules/design/suggestion.py).
    product_keyword = Column(String(100), nullable=False, index=True)

    # Inclusive version bounds. Either may be null (open-ended). Compared via
    # app/modules/cve/matcher.py's lenient version parser - real semver
    # (packaging.version) first, falling back to a leading-numeric-groups
    # comparison for vendor version strings that aren't strict semver.
    affected_version_min = Column(String(50), nullable=True)
    affected_version_max = Column(String(50), nullable=True)
    fixed_version = Column(String(50), nullable=True)

    severity = Column(String(20), nullable=False)  # critical | high | medium | low
    cvss_score = Column(Float, nullable=True)
    summary = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    reference_url = Column(String(500), nullable=True)
    published_date = Column(DateTime, nullable=True)

    source = Column(String(20), nullable=False, default="seed")  # seed | nvd_sync
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
