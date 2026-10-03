"""
Distribution security advisories (app/modules/advisories): which version of
a distribution package fixes which CVE, from the distribution itself
(Ubuntu USN and CVE tracker, Debian DSA/DLA and security tracker, Red Hat
RHSA, Rocky RLSA, AlmaLinux ALSA), as published in the OSV format.

DistroVuln  one affected range of one package in one release, from one
            record. kind "cve" rows (Ubuntu, Debian) describe one CVE and
            may have no fix yet; kind "advisory" rows are an announcement
            (USN-6859-1, RHSA-2024:0001) that fixes one or more CVEs.
            The package is the source package on Debian/Ubuntu, the binary
            package on the RPM distributions - as the distributions publish.
DistroFeed  what is loaded for a release, and when.

Only releases in use (or asked for) are loaded; a record replaces all its
rows when it changes.
"""
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Column, DateTime, Index, Integer, String, Text

from app.core.database import Base

KIND_CVE = "cve"
KIND_ADVISORY = "advisory"
AVAILABILITY_STANDARD = "standard"
AVAILABILITY_PRO = "pro"         # only through an Ubuntu Pro (ESM) subscription


class DistroVuln(Base):
    __tablename__ = "distro_vulns"
    __table_args__ = (
        Index("ix_distro_vulns_release_package", "release", "package"),
        Index("ix_distro_vulns_record", "record_id"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    release = Column(String(24), nullable=False)          # ubuntu:22.04 | debian:12 | rhel:9 | rocky:9 | alma:9
    stream = Column(String(80), nullable=False)           # the OSV ecosystem: "Ubuntu:Pro:22.04:LTS", ...
    package = Column(String(200), nullable=False)
    record_id = Column(String(80), nullable=False)        # UBUNTU-CVE-2024-6387, USN-6859-1, RHSA-2024:0001
    kind = Column(String(10), nullable=False)             # cve | advisory
    introduced = Column(String(160), nullable=True)       # None = every version before `fixed`
    fixed = Column(String(160), nullable=True)            # None = no fix yet
    last_affected = Column(String(160), nullable=True)
    cves = Column(JSON, nullable=False, default=list)
    severity = Column(String(12), nullable=True)          # critical | high | medium | low (the distribution's)
    availability = Column(String(10), nullable=False, default=AVAILABILITY_STANDARD)
    title = Column(String(300), nullable=True)
    published = Column(DateTime, nullable=True)
    modified = Column(DateTime, nullable=True)


class DistroFeed(Base):
    __tablename__ = "distro_feeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    release = Column(String(24), nullable=False, unique=True)
    rows = Column(Integer, nullable=False, default=0)
    records = Column(Integer, nullable=False, default=0)
    watermark = Column(DateTime, nullable=True)           # newest `modified` loaded
    loaded_at = Column(DateTime, nullable=True)           # last full load
    updated_at = Column(DateTime, nullable=True)          # last change of any kind
    source = Column(String(12), nullable=True)            # online | osv_zip | package
    last_changes = Column(Integer, nullable=True)         # records changed by the last update
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
