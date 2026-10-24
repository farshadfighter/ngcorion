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
from sqlalchemy import (Column, Integer, BigInteger, String, Boolean, Text, DateTime, Float, ForeignKey,
                        UniqueConstraint, JSON)
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
    # Where to reach the device over SNMP when that is not its inventory address (a FortiGate's
    # management interface, say); NULL = the asset's IP address.
    poll_address = Column(String(255), nullable=True)

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

    @property
    def target(self):
        """The address SNMP talks to: the SNMP address when set, else the asset's IP address."""
        return (self.poll_address or "").strip() or (self.asset.ip_address if self.asset else None)


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
    # Consecutive failed polls in a row (reset to 0 on any success). Drives
    # the auto ACTIVE/INACTIVE flip on Asset.status - see
    # app/modules/noc/service.py's NOC_INACTIVE_AFTER_FAILURES threshold.
    # Flap-dampening: one dropped packet must not flip status.
    consecutive_poll_failures = Column(Integer, nullable=False, default=0)

    # Device health from the last successful poll (app/modules/noc/health.py); null when the device
    # does not report it. disk_percent is the fullest file system, temperature_c the hottest sensor.
    device_uptime_ticks = Column(BigInteger, nullable=True)   # host uptime (hrSystemUptime), else sysUpTime
    cpu_percent = Column(Float, nullable=True)
    memory_percent = Column(Float, nullable=True)
    memory_total_bytes = Column(BigInteger, nullable=True)
    disk_percent = Column(Float, nullable=True)
    temperature_c = Column(Float, nullable=True)
    # {"source": "host-resources|cisco|fortigate|ucd", "filesystems": [{name, size, used, percent}],
    #  "sensors": [{name, celsius}]}
    health = Column(JSON, nullable=True)
    last_reboot_at = Column(DateTime, nullable=True)

    asset = relationship("Asset")


class DeviceReboot(Base):
    """A restart NOC noticed: the device's uptime went back between two polls. booted_at is when
    the device came up (detection time minus its new uptime)."""

    __tablename__ = "noc_device_reboots"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    detected_at = Column(DateTime, nullable=False, index=True)
    booted_at = Column(DateTime, nullable=False)
    previous_uptime_seconds = Column(BigInteger, nullable=True)

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
    # IF-MIB ifXTable (RFC 2863) - see snmp_client.py's IFX_TABLE_BASE comment
    # for why these are collected alongside if_descr rather than instead of it.
    if_name = Column(String(255), nullable=True)
    if_alias = Column(String(255), nullable=True)
    if_type = Column(Integer, nullable=True)
    if_speed = Column(BigInteger, nullable=True)  # bits/sec
    if_admin_status = Column(String(20), nullable=True)  # up | down | testing
    if_oper_status = Column(String(20), nullable=True)
    in_octets = Column(BigInteger, nullable=True)
    out_octets = Column(BigInteger, nullable=True)
    last_polled_at = Column(DateTime, nullable=True)

    asset = relationship("Asset")


class NetworkEndpoint(Base):
    """A device address NOC saw in the ARP or MAC table of a monitored router or switch
    (app/modules/noc/endpoints.py). One row per MAC; matched_asset_id is set when the address
    belongs to an asset (its MAC, its IP, or a monitored device's own interface), otherwise the
    device is unknown and listed on the Unknown devices page until someone adds it as an asset or
    ignores it."""

    __tablename__ = "noc_network_endpoints"

    id = Column(Integer, primary_key=True)
    mac = Column(String(17), nullable=False, unique=True)          # aa:bb:cc:dd:ee:ff
    ip = Column(String(45), nullable=True, index=True)              # the address seen last
    other_ips = Column(JSON, nullable=True)                         # more addresses on the same MAC
    vendor = Column(String(160), nullable=True)                     # from the OUI registry
    private_mac = Column(Boolean, nullable=False, default=False)    # locally administered address
    guess_kind = Column(String(20), nullable=True)                  # app/modules/noc/oui.py guess()
    guess_icon = Column(String(20), nullable=True)
    first_seen_at = Column(DateTime, nullable=False, index=True)
    last_seen_at = Column(DateTime, nullable=False, index=True)
    # Found in the first read of every device that reported it: present before NOC looked, so no
    # "new device" alert for it.
    baseline = Column(Boolean, nullable=False, default=False)
    # Where it was seen: the device and port with the fewest addresses (an access port rather than
    # an uplink), and how (arp, mac or both).
    seen_by_asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True)
    seen_if_index = Column(Integer, nullable=True)
    seen_port = Column(String(255), nullable=True)
    seen_vlan = Column(Integer, nullable=True)
    seen_via = Column(String(10), nullable=True)

    matched_asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True,
                              index=True)
    state = Column(String(10), nullable=False, default="open", index=True)   # open | ignored
    ignore_note = Column(String(255), nullable=True)
    ignored_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ignored_at = Column(DateTime, nullable=True)

    seen_by = relationship("Asset", foreign_keys=[seen_by_asset_id])
    matched_asset = relationship("Asset", foreign_keys=[matched_asset_id])


class NetworkDiscoverySource(Base):
    """A monitored device whose ARP / MAC tables NOC reads, and how the last read went."""

    __tablename__ = "noc_discovery_sources"

    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), primary_key=True)
    first_read_at = Column(DateTime, nullable=True)
    last_read_at = Column(DateTime, nullable=True)
    ok = Column(Boolean, nullable=False, default=False)
    error = Column(Text, nullable=True)
    arp_entries = Column(Integer, nullable=False, default=0)
    mac_entries = Column(Integer, nullable=False, default=0)

    asset = relationship("Asset")


class TopologyNeighbor(Base):
    """A neighbour a monitored device reports on one of its ports over LLDP or CDP
    (app/modules/noc/topology_discovery.py). matched_asset_id is the asset it is, when it is one;
    link_id the Topology link it makes (or confirms) between the two."""

    __tablename__ = "noc_topology_neighbors"
    __table_args__ = (UniqueConstraint("asset_id", "ident", name="uq_topology_neighbor_ident"),)

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False, index=True)
    ident = Column(String(40), nullable=False)          # sha1 of protocol, local port, chassis, remote port
    protocol = Column(String(4), nullable=False)        # lldp | cdp
    local_port = Column(String(255), nullable=False)
    local_if_index = Column(Integer, nullable=True)
    chassis_id = Column(String(255), nullable=True)
    chassis_kind = Column(String(4), nullable=True)     # mac | ip | name
    remote_name = Column(String(255), nullable=True)
    remote_port = Column(String(255), nullable=True)
    remote_port_desc = Column(String(255), nullable=True)
    remote_mgmt_ip = Column(String(45), nullable=True)
    remote_description = Column(String(255), nullable=True)
    capabilities = Column(JSON, nullable=True)          # router, bridge, wlan_ap, phone, station, ...
    first_seen_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=False, index=True)

    matched_asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True,
                              index=True)
    link_id = Column(Integer, ForeignKey("topology_links.id", ondelete="SET NULL"), nullable=True, index=True)
    # Someone removed the link this neighbour made from the map: do not draw it again.
    suppressed = Column(Boolean, nullable=False, default=False)

    asset = relationship("Asset", foreign_keys=[asset_id])
    matched_asset = relationship("Asset", foreign_keys=[matched_asset_id])


class TopologyDiscoverySource(Base):
    """A monitored device whose LLDP / CDP neighbour tables NOC reads, and how the last read went."""

    __tablename__ = "noc_topology_sources"

    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), primary_key=True)
    last_read_at = Column(DateTime, nullable=True)
    ok = Column(Boolean, nullable=False, default=False)
    error = Column(Text, nullable=True)
    lldp = Column(Boolean, nullable=False, default=False)      # answered the LLDP tables
    cdp = Column(Boolean, nullable=False, default=False)
    neighbors = Column(Integer, nullable=False, default=0)
    chassis_id = Column(String(255), nullable=True)            # its own LLDP chassis id

    asset = relationship("Asset")
