"""
NOC (Network Operations Center) - SNMP monitoring models.

One SNMP credential per asset (encrypted at rest - see
app/core/snmp_crypto.py), plus the last poll result split into two tables:
AssetSnmpStatus (one row per asset, upserted on every poll - device-level
sysDescr/sysName/sysUpTime/reachability) and AssetSnmpInterface (one row per
IF-MIB interface the device reports, upserted by if_index on every poll).
Kept separate from Asset itself since this is monitoring state, not
inventory data, and separate from each other since a device has exactly one
status but any number of interfaces.
"""
from sqlalchemy import Column, Integer, BigInteger, Float, String, Boolean, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class AssetSnmpCredential(Base):
    """SNMP credential for one asset. Unattended background polling (unlike
    every other device-I/O path in this app) needs the secret at rest, so
    the community string / SNMPv3 auth+priv keys are Fernet-encrypted
    (app/core/snmp_crypto.py) rather than entered fresh per request."""

    __tablename__ = "asset_snmp_credentials"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    version = Column(String(10), nullable=False, default="v2c")  # v2c | v3
    port = Column(Integer, nullable=False, default=161)

    # v2c
    community_encrypted = Column(Text, nullable=True)

    # v3
    username = Column(String(100), nullable=True)
    auth_protocol = Column(String(20), nullable=True)  # MD5 | SHA
    auth_key_encrypted = Column(Text, nullable=True)
    priv_protocol = Column(String(20), nullable=True)  # DES | AES
    priv_key_encrypted = Column(Text, nullable=True)

    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = relationship("Asset")


class AssetSnmpStatus(Base):
    """Last SNMP poll result for one asset (device-level fields only - see
    AssetSnmpInterface for per-interface data). Upserted on every poll."""

    __tablename__ = "asset_snmp_status"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    reachable = Column(Boolean, nullable=False, default=False)
    sys_descr = Column(Text, nullable=True)
    sys_name = Column(String(255), nullable=True)
    sys_contact = Column(String(255), nullable=True)
    sys_location = Column(String(255), nullable=True)
    sys_uptime_ticks = Column(BigInteger, nullable=True)  # hundredths of a second, per RFC1213
    error_message = Column(Text, nullable=True)
    last_polled_at = Column(DateTime, nullable=True, index=True)

    asset = relationship("Asset")


class AssetSnmpInterface(Base):
    """One IF-MIB interface reported by an asset's last successful poll.
    Upserted by (asset_id, if_index); interfaces the device no longer
    reports are left stale rather than deleted, so a flapping poll doesn't
    thrash the table - the frontend can use last_polled_at to notice."""

    __tablename__ = "asset_snmp_interfaces"
    __table_args__ = (UniqueConstraint("asset_id", "if_index", name="uq_snmp_interface_asset_ifindex"),)

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    if_index = Column(Integer, nullable=False)
    if_descr = Column(String(255), nullable=True)
    if_type = Column(Integer, nullable=True)
    if_speed = Column(BigInteger, nullable=True)  # bits/sec
    if_admin_status = Column(String(20), nullable=True)  # up | down | testing
    if_oper_status = Column(String(20), nullable=True)
    in_octets = Column(BigInteger, nullable=True)
    out_octets = Column(BigInteger, nullable=True)
    last_polled_at = Column(DateTime, nullable=True)

    asset = relationship("Asset")
