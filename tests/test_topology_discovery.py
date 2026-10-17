"""
Topology from LLDP / CDP (app/modules/noc/lldp.py, topology_discovery.py, topology_router.py): port and
name spellings, parsing the neighbour tables, matching neighbours with the inventory, one link per
cable from both devices' reports, confirming a hand-drawn link, a link going missing (and the alert),
removing a found link from the map, the API, and a real net-snmp agent serving LLDP-MIB through
"pass" (skipped without snmpd).

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
import asyncio
import importlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.noc import AssetSnmpInterface, TopologyDiscoverySource, TopologyNeighbor
from app.models.security_audit_log import AuditLog as SecurityAuditLog
from app.models.topology import TopologyLink
from app.modules.alerts import events as E
from app.modules.noc import lldp as L
from app.modules.noc import topology_discovery as TD
from app.modules.noc import topology_router as R


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


def _type(db, name="Switch"):
    t = AssetType(type_name=f"{name} {_n()}", category="network")
    db.add(t)
    db.flush()
    return t


def _asset(db, name=None, ip=None, mac=None, ports=()):
    a = Asset(asset_name=name or f"sw-{_n()}", asset_type_id=_type(db).id, ip_address=ip, mac_address=mac)
    db.add(a)
    db.flush()
    for i, port in enumerate(ports, start=1):
        db.add(AssetSnmpInterface(asset_id=a.id, if_index=i, if_name=port[0], if_descr=port[1],
                                  if_speed=1_000_000_000))
    db.flush()
    return a


def _user(db, role=UserRole.ADMIN):
    u = User(username=f"td_{_n()}", hashed_password="x", role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


def _req():
    return SimpleNamespace(client=SimpleNamespace(host="10.0.0.9"))


# ── spellings and parsing ───────────────────────────────────────────────────

def test_port_and_name_spellings():
    assert TD.port_key("GigabitEthernet1/0/24") == TD.port_key("Gi1/0/24") == TD.port_key("gi 1/0/24") == "gi1/0/24"
    assert TD.port_key("TenGigabitEthernet1/1/1") == TD.port_key("Te1/1/1")
    assert TD.port_key("Ethernet1/49") == TD.port_key("Eth1/49") == TD.port_key("Et1/49")
    assert TD.port_key("port1") == "port1" and TD.port_key(None) is None
    assert TD.name_key("CORE-SW-01.corp.local") == "core-sw-01"
    assert TD.name_key("SEP001122334455") == "sep001122334455"
    assert TD.name_key("Switch2(FOC1234X0AB)") == "switch2"


def test_identifier_and_capability_values():
    assert L.chassis_value(4, bytes.fromhex("0019e7a1b2c3")) == ("00:19:e7:a1:b2:c3", "mac")
    assert L.chassis_value(5, bytes([1, 10, 0, 0, 2])) == ("10.0.0.2", "ip")
    assert L.chassis_value(7, b"fw-hq") == ("fw-hq", "name")
    assert L.port_value(5, b"Gi1/0/1") == "Gi1/0/1" and L.port_value(3, bytes.fromhex("001122334455")) == \
        "00:11:22:33:44:55"
    assert L.lldp_caps(bytes([0x28, 0x00])) == ["bridge", "router"]
    assert L.lldp_caps(bytes([0x04, 0x00])) == ["phone"]
    assert L.cdp_caps(bytes([0, 0, 0, 0x29])) == ["router", "bridge"]
    assert L.cdp_caps(bytes([0, 0, 0x04, 0x90])) == ["station", "phone"]
    assert L._text(b"\x01\x02") == "01:02" and L._text(b"  core  sw \x00") == "core sw"


REM, MAN, LOC, CDP = L.LLDP_REM, L.LLDP_REM_MAN_ADDR, L.LLDP_LOC_PORT, L.CDP_CACHE


def _lldp_rows(port_num, rem_index, chassis, port, name, caps=b"\x28\x00", subtype=4, desc="Cisco IOS XE"):
    idx = f"0.{port_num}.{rem_index}"
    return [(f"{REM}.4.{idx}", subtype), (f"{REM}.5.{idx}", chassis), (f"{REM}.6.{idx}", 5),
            (f"{REM}.7.{idx}", port.encode()), (f"{REM}.8.{idx}", b"uplink"), (f"{REM}.9.{idx}", name.encode()),
            (f"{REM}.10.{idx}", desc.encode()), (f"{REM}.12.{idx}", caps)]


def test_parse_lldp_and_cdp():
    rem = _lldp_rows(24, 1, bytes.fromhex("0019e7a1b2c3"), "Gi1/0/1", "dist-sw-02.corp.local")
    man = [(f"{MAN}.3.0.24.1.1.4.10.20.0.2", 2)]
    local = {24: ("Gi1/0/24", "GigabitEthernet1/0/24")}
    [n] = L.parse_lldp(rem, man, local, {"gigabitethernet1/0/24": 24})
    assert (n.protocol, n.local_port, n.local_if_index) == ("lldp", "Gi1/0/24", 24)
    assert (n.chassis_id, n.chassis_kind, n.remote_port, n.remote_name) == \
        ("00:19:e7:a1:b2:c3", "mac", "Gi1/0/1", "dist-sw-02.corp.local")
    assert n.remote_mgmt_ip == "10.20.0.2" and n.capabilities == ["bridge", "router"]
    # No lldpLocPortTable: the port number is the ifIndex.
    [m] = L.parse_lldp(rem, [], {}, {}, {24: "Gi1/0/24"})
    assert (m.local_port, m.local_if_index) == ("Gi1/0/24", 24)

    cdp = [(f"{CDP}.3.10101.1", 1), (f"{CDP}.4.10101.1", bytes([10, 20, 0, 9])), (f"{CDP}.5.10101.1", b"15.2(7)E"),
           (f"{CDP}.6.10101.1", b"SEP001122334455"), (f"{CDP}.7.10101.1", b"Port 1"),
           (f"{CDP}.8.10101.1", b"Cisco IP Phone 8845"), (f"{CDP}.9.10101.1", bytes([0, 0, 4, 0x90]))]
    [c] = L.parse_cdp(cdp, {10101: "Gi1/0/1"})
    assert (c.protocol, c.local_port, c.local_if_index, c.remote_name, c.remote_port, c.remote_mgmt_ip) == \
        ("cdp", "Gi1/0/1", 10101, "SEP001122334455", "Port 1", "10.20.0.9")
    assert c.remote_description == "Cisco IP Phone 8845 - 15.2(7)E" and "phone" in c.capabilities


class FakeClient:
    """Answers walk() from a dict of base OID -> rows, like puresnmp's PyWrapper."""
    def __init__(self, tables):
        self.tables = tables

    async def walk(self, base):
        if base == CDP and "cdp-fails" in self.tables:
            raise TimeoutError()
        for oid, value in self.tables.get(base, []):
            yield SimpleNamespace(oid=oid, value=value)


def test_collect_reads_what_a_device_has():
    loc_base = L.LLDP_LOC_CHASSIS_SUBTYPE.rsplit(".", 1)[0]
    client = FakeClient({
        loc_base: [(f"{L.LLDP_LOC_CHASSIS_SUBTYPE}.0", 4), (f"{L.LLDP_LOC_CHASSIS_ID}.0", bytes.fromhex("0019e7000001")),
                   (f"{LOC}.2.24", 5), (f"{LOC}.3.24", b"Gi1/0/24"), (f"{LOC}.4.24", b"GigabitEthernet1/0/24")],
        REM: _lldp_rows(24, 1, bytes.fromhex("0019e7a1b2c3"), "Gi1/0/1", "dist-sw-02"),
        "cdp-fails": True,
    })
    rep = asyncio.run(L.collect(client, [(24, "Gi1/0/24", "GigabitEthernet1/0/24")]))
    assert rep.local_chassis_id == "00:19:e7:00:00:01" and rep.lldp and not rep.cdp
    assert [(n.local_port, n.local_if_index, n.remote_name) for n in rep.neighbors] == [("Gi1/0/24", 24, "dist-sw-02")]
    assert any("CDP" in e for e in rep.errors)


# ── recording sweeps ────────────────────────────────────────────────────────

def _nb(local, chassis, port, name=None, kind="mac", protocol="lldp", ip=None, caps=("bridge",), if_index=None):
    return L.Neighbor(protocol=protocol, local_port=local, local_if_index=if_index, chassis_id=chassis,
                      chassis_kind=kind, remote_port=port, remote_name=name, remote_mgmt_ip=ip,
                      capabilities=list(caps))


def _rep(*neighbors, chassis=None):
    return L.NeighborReport(neighbors=list(neighbors), local_chassis_id=chassis, lldp=True)


def _two_switches(db):
    a = _asset(db, "core-sw-01", "10.20.0.1", ports=[("Gi1/0/1", "GigabitEthernet1/0/1"),
                                                     ("Gi1/0/24", "GigabitEthernet1/0/24")])
    b = _asset(db, "dist-sw-02", "10.20.0.2", ports=[("Gi1/0/1", "GigabitEthernet1/0/1")])
    return a, b


def _sweep_both(db, a, b, now, extra=()):
    """a and b report each other on a's Gi1/0/24 <-> b's Gi1/0/1, the far port spelled long."""
    return TD.record(db, {
        a.id: _rep(_nb("Gi1/0/24", "00:19:e7:00:00:02", "GigabitEthernet1/0/1", "dist-sw-02"), *extra,
                   chassis="00:19:e7:00:00:01"),
        b.id: _rep(_nb("Gi1/0/1", "00:19:e7:00:00:01", "Gi1/0/24", "core-sw-01.corp.local"),
                   chassis="00:19:e7:00:00:02"),
    }, {}, now)


def _found(db, a, b):
    return [lk for lk in db.query(TopologyLink).filter(TopologyLink.source_asset_id.in_([a.id, b.id]),
                                                       TopologyLink.destination_asset_id.in_([a.id, b.id]))]


def test_both_sides_make_one_link(db):
    a, b = _two_switches(db)
    ap = _nb("Gi1/0/1", "a0:b1:c2:00:00:01", "eth0", "ap-lobby", caps=("wlan_ap",), ip="10.20.9.9")
    t0 = datetime.utcnow().replace(microsecond=0)
    r = _sweep_both(db, a, b, t0, extra=[ap])
    assert r["devices_read"] == 2 and r["neighbors"] == 3 and r["links_created"] == 1
    [link] = _found(db, a, b)
    assert link.origin == "lldp" and link.last_seen_at == t0 and link.missing_since is None
    ends = {(link.source_asset_id, link.source_interface), (link.destination_asset_id, link.destination_interface)}
    assert ends == {(a.id, "Gi1/0/24"), (b.id, "Gi1/0/1")}
    assert link.speed_mbps == 1000
    rows = db.query(TopologyNeighbor).filter(TopologyNeighbor.asset_id.in_([a.id, b.id])).all()
    assert {r.link_id for r in rows if r.matched_asset_id} == {link.id}
    unknown = next(r for r in rows if r.remote_name == "ap-lobby")
    assert unknown.matched_asset_id is None and R.guess_icon(unknown) == "wireless"
    src = db.get(TopologyDiscoverySource, a.id)
    assert src.ok and src.lldp and src.neighbors == 2 and src.chassis_id == "00:19:e7:00:00:01"
    # The same again: nothing new, the link confirmed.
    r2 = _sweep_both(db, a, b, t0 + timedelta(hours=1), extra=[ap])
    assert r2["links_created"] == 0 and r2["links_confirmed"] == 1 and len(_found(db, a, b)) == 1


def test_matching_by_mac_address_and_name(db):
    a = _asset(db, "edge-fw", "10.30.0.1", ports=[("port1", None)])
    by_mac = _asset(db, "srv-esx-01", None, mac="00-50-56-AA-BB-CC")
    by_ip = _asset(db, "anything", "10.30.0.7")
    by_name = _asset(db, "ACCESS-SW-9")
    TD.record(db, {a.id: _rep(_nb("port1", "00:50:56:aa:bb:cc", "vmnic0"),
                              _nb("port2", "x1", "Gi0/1", "foo", kind="name", ip="10.30.0.7"),
                              _nb("port3", "x2", "Gi0/2", "access-sw-9.corp.local", kind="name"),
                              _nb("port4", "x3", "Gi0/3", "edge-fw", kind="name"))}, {})
    got = {r.local_port: r.matched_asset_id for r in db.query(TopologyNeighbor).filter_by(asset_id=a.id)}
    assert got == {"port1": by_mac.id, "port2": by_ip.id, "port3": by_name.id, "port4": None}   # not itself


def test_a_hand_drawn_link_is_confirmed_not_doubled(db):
    a, b = _two_switches(db)
    c = _asset(db, "phone-sw", "10.20.0.3")
    manual_ab = TopologyLink(source_asset_id=b.id, destination_asset_id=a.id, source_interface="GigabitEthernet1/0/1",
                             destination_interface="Gi1/0/24", status="active")
    manual_ac = TopologyLink(source_asset_id=a.id, destination_asset_id=c.id, status="active")   # no ports
    db.add_all([manual_ab, manual_ac])
    db.flush()
    now = datetime.utcnow().replace(microsecond=0)
    cdp = _nb("Gi1/0/1", "phone-sw", "Gi0/48", "phone-sw", kind="name", protocol="cdp", if_index=1)
    r = _sweep_both(db, a, b, now, extra=[cdp])
    assert r["links_created"] == 0 and r["links_confirmed"] == 2
    db.refresh(manual_ab)
    db.refresh(manual_ac)
    assert manual_ab.origin == "manual" and manual_ab.last_seen_at == now
    assert manual_ac.last_seen_at == now and manual_ac.source_interface is None        # never changed
    # A hand-drawn link is never marked missing.
    _sweep_both(db, a, b, now + timedelta(hours=1))
    db.refresh(manual_ac)
    assert manual_ac.missing_since is None


def test_a_link_goes_missing_comes_back_and_expires(db):
    a, b = _two_switches(db)
    t0 = datetime.utcnow().replace(microsecond=0) - timedelta(days=40)
    _sweep_both(db, a, b, t0)
    [link] = _found(db, a, b)
    t1 = t0 + timedelta(hours=1)
    r = TD.record(db, {a.id: _rep(), b.id: _rep()}, {}, t1)                     # cable pulled
    assert r["links_missing"] == 1
    db.refresh(link)
    assert link.missing_since == t1
    problems = [p for p in E._link_lost(db, {}, datetime.utcnow(), t0) if p.key == f"link:{link.id}"]
    assert problems and problems[0].title == "Network link lost"
    assert problems[0].detail == "core-sw-01 port Gi1/0/24 to dist-sw-02 port Gi1/0/1 is no longer reported by LLDP/CDP"
    # A device that could not be read does not make a link missing.
    _sweep_both(db, a, b, t1 + timedelta(hours=1))
    db.refresh(link)
    assert link.missing_since is None
    TD.record(db, {}, {a.id: "TimeoutError", b.id: "TimeoutError"}, t1 + timedelta(hours=2))
    db.refresh(link)
    assert link.missing_since is None
    TD.record(db, {a.id: _rep(), b.id: _rep()}, {}, t1 + timedelta(hours=3))
    r = TD.record(db, {a.id: _rep()}, {}, t1 + timedelta(days=31))
    assert r["links_removed"] == 1 and not _found(db, a, b)


def test_removing_a_found_link_keeps_it_off_the_map(db):
    topo = importlib.import_module("app.modules.topology.router")
    admin = _user(db)
    a, b = _two_switches(db)
    now = datetime.utcnow().replace(microsecond=0)
    _sweep_both(db, a, b, now)
    [link] = _found(db, a, b)
    topo.delete_link(link.id, current_user=admin, db=db)
    rows = db.query(TopologyNeighbor).filter(TopologyNeighbor.asset_id.in_([a.id, b.id])).all()
    assert all(r.suppressed and r.link_id is None for r in rows)
    r = _sweep_both(db, a, b, now + timedelta(hours=1))
    assert r["links_created"] == 0 and not _found(db, a, b)
    page = R.list_neighbors(status="suppressed", q=None, asset_id=a.id, page=1, page_size=50,
                            current_user=admin, db=db)
    assert page.total == 2
    out = R.add_to_map(rows[0].id, current_user=admin, db=db)
    assert [lk.id for lk in _found(db, a, b)] == [out["link_id"]]
    assert not any(r.suppressed for r in db.query(TopologyNeighbor).filter(TopologyNeighbor.asset_id.in_([a.id, b.id])))
    r = _sweep_both(db, a, b, now + timedelta(hours=2))
    assert r["links_created"] == 0 and len(_found(db, a, b)) == 1


def test_without_automatic_links(db):
    admin = _user(db)
    TD.save_settings(db, {"auto_links": False}, admin.id)
    a, b = _two_switches(db)
    r = _sweep_both(db, a, b, datetime.utcnow().replace(microsecond=0))
    assert r["links_created"] == 0 and not _found(db, a, b)
    page = R.list_neighbors(status="unlinked", q=None, asset_id=a.id, page=1, page_size=50, current_user=admin, db=db)
    assert page.total == 2 and not page.auto_links
    R.add_to_map(page.items[0].id, current_user=admin, db=db)
    assert len(_found(db, a, b)) == 1


def test_list_and_add_as_asset(db):
    admin = _user(db)
    a, b = _two_switches(db)
    _sweep_both(db, a, b, datetime.utcnow().replace(microsecond=0),
                extra=[_nb("Gi1/0/1", "a0:b1:c2:00:00:01", "eth0", "ap-lobby", caps=("wlan_ap",), ip="10.20.9.9")])
    page = R.list_neighbors(status="unknown", q="lobby", asset_id=None, page=1, page_size=50, current_user=admin, db=db)
    [ap] = page.items
    assert ap.guess_icon == "wireless" and ap.device.id == a.id and ap.current and ap.asset is None
    assert page.counts.unknown >= 1 and page.counts.linked >= 2
    with pytest.raises(HTTPException) as not_asset:
        R.add_to_map(ap.id, current_user=admin, db=db)
    assert not_asset.value.status_code == 400
    t = _type(db, "Access point")
    out = R.add_as_asset(ap.id, R.AddAssetBody(asset_name="ap-lobby", asset_type_id=t.id), current_user=admin, db=db)
    asset = db.get(Asset, out["asset_id"])
    assert (asset.ip_address, asset.mac_address) == ("10.20.9.9", "a0:b1:c2:00:00:01")
    link = db.get(TopologyLink, out["link_id"])
    assert {link.source_asset_id, link.destination_asset_id} == {a.id, asset.id} and link.source_interface == "Gi1/0/1"
    with pytest.raises(HTTPException) as again:
        R.add_as_asset(ap.id, R.AddAssetBody(asset_name="x", asset_type_id=t.id), current_user=admin, db=db)
    assert again.value.status_code == 409


def test_add_as_asset_needs_asset_write(db):
    from app.models import UserPermission
    user = _user(db, UserRole.USER)
    db.add(UserPermission(user_id=user.id, module="topology", can_read=True, can_write=True))
    db.flush()
    a = _asset(db, ports=[("Gi1/0/1", None)])
    TD.record(db, {a.id: _rep(_nb("Gi1/0/1", "a0:b1:c2:00:00:09", "eth0", "printer-3"))}, {})
    row = db.query(TopologyNeighbor).filter_by(asset_id=a.id).one()
    with pytest.raises(HTTPException) as denied:
        R.add_as_asset(row.id, R.AddAssetBody(asset_name="x", asset_type_id=_type(db).id), current_user=user, db=db)
    assert denied.value.status_code == 403


def test_settings_and_audit(db):
    admin = _user(db)
    saved = R.save_discovery_settings(R.DiscoverySettings(enabled=True, interval_minutes=30, auto_links=False),
                                      request=_req(), current_user=admin, db=db)
    assert saved == {"enabled": True, "interval_minutes": 30, "auto_links": False}
    R.save_discovery_settings(R.DiscoverySettings(enabled=False, interval_minutes=30), request=_req(),
                              current_user=admin, db=db)
    details = [r.detail for r in db.query(SecurityAuditLog).filter_by(user_id=admin.id,
                                                                     action="topology.discovery_settings")]
    assert "LLDP/CDP topology discovery turned on, every 30 minutes, links added by hand" in details
    assert "LLDP/CDP topology discovery turned off" in details
    assert TD.get_settings(db)["enabled"] is False


def test_graph_shows_where_a_link_came_from(db):
    topo = importlib.import_module("app.modules.topology.router")
    admin = _user(db)
    a, b = _two_switches(db)
    _sweep_both(db, a, b, datetime.utcnow().replace(microsecond=0))
    graph = topo.get_topology(current_user=admin, db=db)
    [link] = [lk for lk in graph.links if {lk.source_asset_id, lk.destination_asset_id} == {a.id, b.id}]
    assert link.origin == "lldp" and link.last_seen_at is not None and link.missing_since is None


def test_routes_are_guarded():
    assert len(R.router.routes) >= 6
    for route in R.router.routes:
        deps = [d.call for d in route.dependant.dependencies]
        assert any(getattr(c, "permission", None) or getattr(c, "__name__", "") == "require_admin" for c in deps), \
            route.path


# ── a real agent ────────────────────────────────────────────────────────────

PASS_SCRIPT = r'''
import sys
L = "1.0.8802.1.1.2.1"
ROWS = {
    L + ".3.1.0": ("integer", "4"), L + ".3.2.0": ("octet", "00 19 E7 00 00 01"),
    L + ".3.7.1.2.24": ("integer", "5"), L + ".3.7.1.3.24": ("string", "Gi1/0/24"),
    L + ".3.7.1.4.24": ("string", "GigabitEthernet1/0/24"),
    L + ".4.1.1.4.0.24.1": ("integer", "4"), L + ".4.1.1.5.0.24.1": ("octet", "00 19 E7 00 00 02"),
    L + ".4.1.1.6.0.24.1": ("integer", "5"), L + ".4.1.1.7.0.24.1": ("string", "Gi1/0/1"),
    L + ".4.1.1.9.0.24.1": ("string", "dist-sw-02"), L + ".4.1.1.12.0.24.1": ("octet", "28 00"),
    L + ".4.2.1.3.0.24.1.1.4.10.20.0.2": ("integer", "2"),
}
key = lambda oid: [int(p) for p in oid.split(".")]
mode, oid = sys.argv[1], sys.argv[2].lstrip(".")
order = sorted(ROWS, key=key)
if mode == "-g":
    hit = oid if oid in ROWS else None
else:
    hit = next((o for o in order if key(o) > key(oid)), None)
if hit:
    print("." + hit); print(ROWS[hit][0]); print(ROWS[hit][1])
'''


def _free_udp_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.skipif(not shutil.which("snmpd") or os.geteuid() != 0, reason="net-snmp agent not installed")
def test_real_net_snmp_agent():
    from puresnmp import Client, PyWrapper, V2C
    port = _free_udp_port()
    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "lldp.py")
        with open(script, "w") as f:
            f.write(PASS_SCRIPT)
        wrapper = os.path.join(tmp, "lldp.sh")
        with open(wrapper, "w") as f:
            f.write(f"#!/bin/sh\nexec {sys.executable} {script} \"$@\"\n")
        os.chmod(wrapper, os.stat(wrapper).st_mode | stat.S_IEXEC)
        conf = os.path.join(tmp, "snmpd.conf")
        with open(conf, "w") as f:
            f.write(f"agentAddress udp:127.0.0.1:{port}\nview all included .1\nrocommunity ngc-test default -V all\n"
                    f"pass .1.0.8802.1.1.2.1 {wrapper}\n")
        proc = subprocess.Popen(["snmpd", "-f", "-Lo", "-C", "-c", conf], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)
            rep = asyncio.run(L.collect(PyWrapper(Client("127.0.0.1", V2C("ngc-test"), port=port)),
                                        [(24, "Gi1/0/24", "GigabitEthernet1/0/24")], timeout=10))
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    assert rep.local_chassis_id == "00:19:e7:00:00:01" and rep.lldp and not rep.cdp
    [n] = rep.neighbors
    assert (n.local_port, n.local_if_index, n.chassis_id, n.remote_port, n.remote_name, n.remote_mgmt_ip) == \
        ("Gi1/0/24", 24, "00:19:e7:00:00:02", "Gi1/0/1", "dist-sw-02", "10.20.0.2")
    assert n.capabilities == ["bridge", "router"]
