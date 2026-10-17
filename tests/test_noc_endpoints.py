"""
Unknown devices (app/modules/noc/endpoints.py, neighbors.py, oui.py): MAC addresses and makers, the
ARP / MAC table parsing, merging several devices' tables (the access port wins over an uplink),
matching with the inventory, the baseline of a first read, forgetting, the "new device" alert,
the API (list, ignore, add as asset) and a real net-snmp agent - its real ARP table, and a switch
MAC table served through snmpd's "pass" (skipped without snmpd).

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
import asyncio
import os
import shutil
import socket
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
from app.models.noc import AssetSnmpInterface, NetworkDiscoverySource, NetworkEndpoint
from app.models.security_audit_log import AuditLog as SecurityAuditLog
from app.modules.alerts import events as E
from app.modules.noc import endpoints as EP
from app.modules.noc import endpoints_router as R
from app.modules.noc import neighbors as N
from app.modules.noc import oui


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


def _asset(db, ip=None, mac=None, name=None):
    a = Asset(asset_name=name or f"dev-{_n()}", asset_type_id=_type(db).id, ip_address=ip, mac_address=mac)
    db.add(a)
    db.flush()
    return a


def _user(db, role=UserRole.ADMIN):
    u = User(username=f"ep_{_n()}", hashed_password="x", role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


def _req():
    return SimpleNamespace(client=SimpleNamespace(host="10.0.0.9"))


# ── addresses and makers ────────────────────────────────────────────────────

def test_mac_forms():
    for form in ("AA:BB:CC:00:11:22", "aa-bb-cc-00-11-22", "aabb.cc00.1122", "AABBCC001122", bytes.fromhex("aabbcc001122")):
        assert oui.normalize_mac(form) == "aa:bb:cc:00:11:22"
    assert oui.normalize_mac("aa:bb:cc") is None and oui.normalize_mac(b"\x01\x02") is None
    assert oui.is_unicast("00:11:22:33:44:55")
    assert not oui.is_unicast("01:00:5e:00:00:01") and not oui.is_unicast("ff:ff:ff:ff:ff:ff")
    assert not oui.is_unicast("00:00:00:00:00:00")
    assert oui.is_private("da:a1:19:00:00:01") and not oui.is_private("00:11:22:33:44:55")


@pytest.mark.skipif(not os.path.exists(oui.PREFIX_FILES[0]), reason="nmap's OUI list not installed")
def test_makers_and_guesses():
    assert "Hikvision" in oui.vendor_of("44:19:b6:00:00:01")
    assert "Cisco" in oui.vendor_of("00:00:0c:00:00:01")
    assert oui.vendor_of("da:a1:19:00:00:01") is None                 # private: no maker
    assert oui.guess("44:19:b6:00:00:01", oui.vendor_of("44:19:b6:00:00:01")) == (None, "camera")
    assert oui.guess("00:50:56:00:00:01", oui.vendor_of("00:50:56:00:00:01")) == ("virtual_machine", "server")
    assert oui.guess("da:a1:19:00:00:01", None) == ("private", "laptop")
    assert oui.guess("00:15:65:00:00:01", "Xiamen Yealink Network Technology") == (None, "ip_phone")
    assert oui.guess("00:c0:b7:00:00:01", "American Power Conversion") == (None, "ups")
    assert oui.guess("00:00:bc:00:00:01", "Rockwell Automation") == (None, "plc")
    assert oui.guess("00:11:22:33:44:55", None) == (None, "other")


# ── the tables ──────────────────────────────────────────────────────────────

def test_arp_table():
    phys = [(f"{N.ARP_PHYS}.3.10.0.0.5", bytes.fromhex("001122334455")),
            (f"{N.ARP_PHYS}.3.10.0.0.6", bytes.fromhex("001122334466")),
            (f"{N.ARP_PHYS}.3.10.0.0.7", bytes.fromhex("01005e000001")),      # multicast
            (f"{N.ARP_PHYS}.3.10.0.0", bytes.fromhex("001122334477"))]        # malformed index
    types = [(f"{N.ARP_TYPE}.3.10.0.0.5", 3), (f"{N.ARP_TYPE}.3.10.0.0.6", 2)]  # .6 invalid
    out = N.parse_arp(phys, types)
    assert [(e.ip, e.mac, e.if_index) for e in out] == [("10.0.0.5", "00:11:22:33:44:55", 3)]


def test_newer_arp_table_ipv4_only():
    phys = [(f"{N.NET_PHYS}.2.1.4.10.1.1.9", bytes.fromhex("aabbcc000001")),
            (f"{N.NET_PHYS}.2.2.16." + ".".join(["0"] * 15) + ".1", bytes.fromhex("aabbcc000002")),
            (f"{N.NET_PHYS}.2.1.4.10.1.1.10", bytes.fromhex("aabbcc000003"))]
    types = [(f"{N.NET_TYPE}.2.1.4.10.1.1.10", 5)]                      # local: the router itself
    assert [(e.ip, e.mac) for e in N.parse_net_to_physical(phys, types)] == [("10.1.1.9", "aa:bb:cc:00:00:01")]


def test_mac_tables():
    ports = {1: 10101, 2: 10102}
    q = [(f"{N.QFDB_PORT}.20.0.17.34.51.68.85", 1), (f"{N.QFDB_PORT}.20.0.17.34.51.68.86", 2),
         (f"{N.QFDB_PORT}.20.0.17.34.51.68.87", 2)]
    st = [(f"{N.QFDB_STATUS}.20.0.17.34.51.68.86", 3), (f"{N.QFDB_STATUS}.20.0.17.34.51.68.87", 4)]  # .87 self
    out = N.parse_fdb(q, st, ports, qbridge=True)
    assert [(e.mac, e.if_index, e.vlan) for e in out] == [("00:11:22:33:44:55", 10101, 20),
                                                          ("00:11:22:33:44:56", 10102, 20)]
    d = [(f"{N.DFDB_PORT}.0.17.34.51.68.85", 2)]
    assert [(e.mac, e.if_index, e.vlan) for e in N.parse_fdb(d, [], ports, qbridge=False)] == \
        [("00:11:22:33:44:55", 10102, None)]
    assert N.parse_port_ifindex([(f"{N.BASE_PORT_IFINDEX}.7", 10107)]) == {7: 10107}
    assert N.valid_ipv4("10.0.0.5") and not N.valid_ipv4("224.0.0.1") and not N.valid_ipv4("10.0.0.255")


def test_the_access_port_wins_over_the_uplink():
    core = N.NeighborTables(fdb=[N.FdbEntry(f"00:00:00:00:01:{i:02x}", 48, 10) for i in range(30)])
    edge = N.NeighborTables(fdb=[N.FdbEntry("00:00:00:00:01:05", 7, 10)],
                            arp=[N.ArpEntry("10.0.0.5", "00:00:00:00:01:05", 2)])
    merged = EP.merge({1: core, 2: edge})
    s = merged["00:00:00:00:01:05"]
    assert s.ports[0] == (2, 7, 10) and s.ips == ["10.0.0.5"] and s.via == "both"
    assert merged["00:00:00:00:01:06"].ports[0] == (1, 48, 10)


class FakeClient:
    """Answers walk() from a dict of base OID -> rows, like puresnmp's PyWrapper."""
    def __init__(self, tables):
        self.tables = tables

    async def walk(self, base):
        if base == N.QFDB_PORT and "fail" in self.tables:
            raise TimeoutError()
        for oid, value in self.tables.get(base, []):
            yield SimpleNamespace(oid=oid, value=value)


def test_collect_reads_what_a_device_has():
    client = FakeClient({
        N.IF_PHYS: [(f"{N.IF_PHYS}.1", bytes.fromhex("0050560000aa")), (f"{N.IF_PHYS}.2", b"")],
        N.ARP_PHYS: [(f"{N.ARP_PHYS}.1.10.9.0.5", bytes.fromhex("001122334455"))],
        N.ARP_TYPE: [(f"{N.ARP_TYPE}.1.10.9.0.5", 3)],
        N.BASE_PORT_IFINDEX: [(f"{N.BASE_PORT_IFINDEX}.1", 1)],
        N.DFDB_PORT: [(f"{N.DFDB_PORT}.0.17.34.51.68.85", 1)],
        "fail": True,
    })
    t = asyncio.run(N.collect(client))
    assert t.own_macs == {"00:50:56:00:00:aa"} and t.arp[0].ip == "10.9.0.5"
    assert [(e.mac, e.if_index) for e in t.fdb] == [("00:11:22:33:44:55", 1)]   # Q-BRIDGE failed, BRIDGE used
    assert any("Q-BRIDGE" in e for e in t.errors)


# ── recording a sweep ───────────────────────────────────────────────────────

def _tables(*entries, own=()):
    """(mac, ip or None, port or None) tuples as one device's tables."""
    t = N.NeighborTables(own_macs=set(own))
    for mac, ip, port in entries:
        if ip:
            t.arp.append(N.ArpEntry(ip, mac, 1))
        if port:
            t.fdb.append(N.FdbEntry(mac, port, 30))
    return t


def test_first_read_is_baseline_then_new_devices_alert(db):
    sw = _asset(db, "10.80.0.1")
    db.add(AssetSnmpInterface(asset_id=sw.id, if_index=5, if_name="Gi1/0/5"))
    known = _asset(db, "10.80.0.20", "00:80:00:00:00:20")
    db.flush()
    t0 = datetime.utcnow() - timedelta(minutes=30)
    r = EP.record(db, {sw.id: _tables(("00:80:00:00:00:10", "10.80.0.10", 5),
                                      ("00:80:00:00:00:20", "10.80.0.20", 6),
                                      ("00:80:00:00:00:99", None, 5),
                                      own=["00:80:00:00:00:01"])}, {}, now=t0)
    assert r["devices_read"] == 1 and r["new"] == 4
    rows = {e.mac: e for e in db.query(NetworkEndpoint).filter(NetworkEndpoint.mac.like("00:80:%"))}
    assert all(e.baseline for e in rows.values())
    assert rows["00:80:00:00:00:20"].matched_asset_id == known.id                   # its MAC
    assert rows["00:80:00:00:00:01"].matched_asset_id == sw.id                      # the switch itself
    unknown = rows["00:80:00:00:00:10"]
    assert unknown.matched_asset_id is None and unknown.seen_port == "Gi1/0/5" and unknown.seen_vlan == 30
    assert unknown.ip == "10.80.0.10" and unknown.seen_via == "both"
    src = db.get(NetworkDiscoverySource, sw.id)
    assert src.ok and src.first_read_at == t0 and src.arp_entries == 2 and src.mac_entries == 3
    assert not E._unknown_device(db, {}, datetime.utcnow(), t0 - timedelta(minutes=1))   # baseline: quiet

    t1 = datetime.utcnow()
    EP.record(db, {sw.id: _tables(("00:80:00:00:00:10", "10.80.0.10", 5), ("00:80:00:00:00:30", "10.80.0.30", 5))},
              {}, now=t1)
    new = db.query(NetworkEndpoint).filter_by(mac="00:80:00:00:00:30").one()
    assert not new.baseline and new.first_seen_at == t1
    problems = E._unknown_device(db, {}, datetime.utcnow(), t1 - timedelta(seconds=1))
    assert [p.key for p in problems] == [f"endpoint:{new.id}"]
    detail = problems[0].detail                      # the maker comes from nmap's list when installed
    assert detail.startswith("MAC 00:80:00:00:00:30, maker ")
    assert detail.endswith(f", IP 10.80.0.30, seen by {sw.asset_name}, port Gi1/0/5")
    assert problems[0].detail.endswith(", port Gi1/0/5")
    assert problems[0].asset_id == sw.id
    assert db.query(NetworkEndpoint).filter_by(mac="00:80:00:00:00:10").one().last_seen_at == t1


def test_many_new_devices_make_one_alert(db):
    sw = _asset(db, "10.81.0.1")
    EP.record(db, {sw.id: _tables(("00:81:00:00:00:01", None, 3))}, {}, now=datetime.utcnow() - timedelta(hours=1))
    t1 = datetime.utcnow()
    EP.record(db, {sw.id: _tables(*[(f"00:81:00:00:01:{i:02x}", None, 3) for i in range(12)])}, {}, now=t1)
    problems = E._unknown_device(db, {}, datetime.utcnow(), t1 - timedelta(seconds=1))
    assert len(problems) == 1 and problems[0].detail == "12 addresses that are not assets appeared"


def test_an_ip_match_and_a_later_asset_make_it_known(db):
    sw = _asset(db, "10.82.0.1")
    _asset(db, "10.82.0.7")                                                   # no MAC on record
    EP.record(db, {sw.id: _tables(("00:82:00:00:00:07", "10.82.0.7", 2), ("00:82:00:00:00:08", "10.82.0.8", 3))}, {})
    rows = {e.mac: e for e in db.query(NetworkEndpoint).filter(NetworkEndpoint.mac.like("00:82:%"))}
    assert rows["00:82:00:00:00:07"].matched_asset_id is not None
    assert rows["00:82:00:00:00:08"].matched_asset_id is None
    later = _asset(db, mac="00-82-00-00-00-08")
    EP.rematch(db)
    db.refresh(rows["00:82:00:00:00:08"])
    assert rows["00:82:00:00:00:08"].matched_asset_id == later.id


def test_failed_device_is_recorded(db):
    sw = _asset(db, "10.83.0.1")
    EP.record(db, {}, {sw.id: "Timeout: no answer"})
    src = db.get(NetworkDiscoverySource, sw.id)
    assert not src.ok and src.error == "Timeout: no answer" and src.first_read_at is None


def test_old_addresses_are_forgotten(db):
    now = datetime.utcnow()

    def row(mac, days, **kw):
        e = NetworkEndpoint(mac=mac, first_seen_at=now - timedelta(days=days), last_seen_at=now - timedelta(days=days),
                            **kw)
        db.add(e)
        return e

    a = _asset(db)
    keep = [row("00:84:00:00:00:01", 10), row("00:84:00:00:00:02", 60, matched_asset_id=a.id),
            row("00:84:00:00:00:03", 200, state="ignored"), row("da:84:00:00:00:04", 3, private_mac=True)]
    drop = [row("00:84:00:00:00:11", 40), row("00:84:00:00:00:12", 100, matched_asset_id=a.id),
            row("00:84:00:00:00:13", 400, state="ignored"), row("da:84:00:00:00:14", 8, private_mac=True)]
    db.flush()
    assert EP.forget_old(db, now) >= len(drop)
    left = {m for (m,) in db.query(NetworkEndpoint.mac).filter(NetworkEndpoint.mac.like("%:84:%"))}
    assert left == {e.mac for e in keep}


def test_settings(db):
    assert EP.get_settings(db) == {"enabled": True, "interval_minutes": 15}
    assert EP.save_settings(db, {"interval_minutes": 2, "enabled": False}, None) == \
        {"enabled": False, "interval_minutes": 5}


# ── the API ─────────────────────────────────────────────────────────────────

def _some_endpoints(db):
    sw = _asset(db, "10.85.0.1", name="core-sw")
    EP.record(db, {sw.id: _tables(("00:85:00:00:00:01", "10.85.0.11", 4))}, {},
              now=datetime.utcnow() - timedelta(days=2))
    EP.record(db, {sw.id: _tables(("00:85:00:00:00:02", "10.85.0.12", 4), ("00:85:00:00:00:03", "10.85.0.13", 4))}, {})
    return sw


def test_list_ignore_and_unignore(db):
    admin = _user(db)
    _some_endpoints(db)
    page = R.list_endpoints(status="unknown", q="00:85", id=None, page=1, page_size=50, current_user=admin, db=db)
    assert page.total == 3 and page.counts.unknown >= 3 and page.items[0].seen_by.name == "core-sw"
    new = R.list_endpoints(status="new", q="00:85", id=None, page=1, page_size=50, current_user=admin, db=db)
    assert {i.mac for i in new.items} == {"00:85:00:00:00:02", "00:85:00:00:00:03"}
    assert all(i.is_new for i in new.items)
    target = new.items[0]
    R.ignore(R.IgnoreBody(ids=[target.id], note="lab"), _req(), current_user=admin, db=db)
    ignored = R.list_endpoints(status="ignored", q="00:85", id=None, page=1, page_size=50, current_user=admin, db=db)
    assert [i.id for i in ignored.items] == [target.id] and ignored.items[0].ignore_note == "lab"
    assert ignored.items[0].ignored_by == admin.username
    assert R.list_endpoints(status="unknown", q="00:85", id=None, page=1, page_size=50, current_user=admin, db=db).total == 2
    one = R.list_endpoints(status="unknown", q=None, id=target.id, page=1, page_size=50, current_user=admin, db=db)
    assert [i.id for i in one.items] == [target.id]                         # whatever its state
    R.unignore(target.id, _req(), current_user=admin, db=db)
    assert R.list_endpoints(status="unknown", q="00:85", id=None, page=1, page_size=50, current_user=admin, db=db).total == 3
    details = [d for (d,) in db.query(SecurityAuditLog.detail).filter(SecurityAuditLog.target_id == target.id,
                                                                      SecurityAuditLog.module == "noc")]
    assert f"Ignored the unknown device {target.mac}" in details
    assert f"No longer ignoring the device {target.mac}" in details
    with pytest.raises(HTTPException):
        R.ignore(R.IgnoreBody(ids=[], note=None), _req(), current_user=admin, db=db)


def test_add_as_asset(db):
    admin = _user(db)
    _some_endpoints(db)
    e = db.query(NetworkEndpoint).filter_by(mac="00:85:00:00:00:02").one()
    e.vendor = "Hangzhou Hikvision Digital Technology"
    db.flush()
    t = _type(db, "IP Camera")
    out = R.add_as_asset(e.id, R.AddAssetBody(asset_name="lobby-cam", asset_type_id=t.id), current_user=admin, db=db)
    a = db.get(Asset, out["asset_id"])
    assert (a.ip_address, a.mac_address, a.manufacturer) == ("10.85.0.12", "00:85:00:00:00:02",
                                                             "Hangzhou Hikvision Digital Technology")
    assert a.resolved_icon == "camera"
    db.refresh(e)
    assert e.matched_asset_id == a.id
    with pytest.raises(HTTPException) as again:
        R.add_as_asset(e.id, R.AddAssetBody(asset_name="x", asset_type_id=t.id), current_user=admin, db=db)
    assert again.value.status_code == 409
    other = db.query(NetworkEndpoint).filter_by(mac="00:85:00:00:00:03").one()
    with pytest.raises(HTTPException) as bad_type:
        R.add_as_asset(other.id, R.AddAssetBody(asset_name="x", asset_type_id=-1), current_user=admin, db=db)
    assert bad_type.value.status_code == 400


def test_add_as_asset_needs_asset_write(db):
    from app.models import UserPermission
    user = _user(db, UserRole.USER)
    db.add(UserPermission(user_id=user.id, module="noc", can_read=True, can_write=True))
    db.flush()
    _some_endpoints(db)
    e = db.query(NetworkEndpoint).filter_by(mac="00:85:00:00:00:03").one()
    with pytest.raises(HTTPException) as denied:
        R.add_as_asset(e.id, R.AddAssetBody(asset_name="x", asset_type_id=_type(db).id), current_user=user, db=db)
    assert denied.value.status_code == 403


def test_routes_are_guarded():
    from app.main import app
    for route in app.routes:
        if getattr(route, "path", "").startswith("/api/noc/endpoints"):
            deps = [d.call for d in route.dependant.dependencies]
            assert any(getattr(c, "permission", None) or getattr(c, "__name__", "") == "require_admin" for c in deps), \
                route.path


# ── a real agent ────────────────────────────────────────────────────────────

PASS_SCRIPT = r'''
import sys
BASE = "1.3.6.1.2.1.17"
ROWS = {
    BASE + ".1.4.1.2.1": 1, BASE + ".1.4.1.2.2": 2,                      # bridge port -> ifIndex
    BASE + ".4.3.1.2.0.17.34.51.68.85": 1, BASE + ".4.3.1.3.0.17.34.51.68.85": 3,
    BASE + ".4.3.1.2.0.17.34.51.68.86": 2, BASE + ".4.3.1.3.0.17.34.51.68.86": 3,
}
key = lambda oid: [int(p) for p in oid.split(".")]
mode, oid = sys.argv[1], sys.argv[2].lstrip(".")
order = sorted(ROWS, key=key)
if mode == "-g":
    hit = oid if oid in ROWS else None
else:
    hit = next((o for o in order if key(o) > key(oid)), None)
if hit:
    print("." + hit); print("integer"); print(ROWS[hit])
'''


def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.skipif(not shutil.which("snmpd") or os.geteuid() != 0, reason="net-snmp agent not installed")
def test_real_net_snmp_agent():
    from puresnmp import Client, PyWrapper, V2C
    with open("/proc/net/arp") as f:
        arp = [line.split() for line in f.read().splitlines()[1:] if line.split()]
    port = _free_udp_port()
    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "bridge.py")
        with open(script, "w") as f:
            f.write(PASS_SCRIPT)
        wrapper = os.path.join(tmp, "bridge.sh")
        with open(wrapper, "w") as f:
            f.write(f"#!/bin/sh\nexec {sys.executable} {script} \"$@\"\n")
        os.chmod(wrapper, os.stat(wrapper).st_mode | stat.S_IEXEC)
        conf = os.path.join(tmp, "snmpd.conf")
        with open(conf, "w") as f:
            f.write(f"agentAddress udp:127.0.0.1:{port}\nview all included .1\nrocommunity ngc-test default -V all\n"
                    f"pass .1.3.6.1.2.1.17 {wrapper}\n")
        proc = subprocess.Popen(["snmpd", "-f", "-Lo", "-C", "-c", conf], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)
            t = asyncio.run(N.collect(PyWrapper(Client("127.0.0.1", V2C("ngc-test"), port=port)), timeout=10))
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    assert {(e.mac, e.if_index) for e in t.fdb} == {("00:11:22:33:44:55", 1), ("00:11:22:33:44:56", 2)}
    assert t.own_macs                                      # this host's own interfaces
    for ip, _hw, flags, mac, *_ in arp:
        if flags != "0x0" and oui.is_unicast(oui.normalize_mac(mac)):
            assert (ip, oui.normalize_mac(mac)) in {(e.ip, e.mac) for e in t.arp}
