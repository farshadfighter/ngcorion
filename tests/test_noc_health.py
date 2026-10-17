"""
Device health over SNMP (app/modules/noc/health.py, NocService._apply_health): CPU, memory, disk and
temperature from Linux (HOST-RESOURCES / UCD), Cisco and FortiGate MIBs, history samples, restarts
noticed from the uptime (and the 497-day counter wrap that is not one), the alerts, the API and the
asset 360 page. A real net-snmp agent is used when snmpd is installed (skipped otherwise).

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
import asyncio
import os
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.core.snmp_crypto import encrypt_secret
from app.models import Asset, AssetType, User, UserRole
from app.models.noc import AssetSnmpStatus, DeviceReboot
from app.models.noc_metrics import AssetMetricSample
from app.modules.alerts import events as E
from app.modules.assets import overview360
from app.modules.noc import health as H
from app.modules.noc import router as NR
from app.modules.noc.service import NocService
from app.modules.noc.snmp_client import DevicePollResult

RAM, DISK, OTHER = H.HR_STORAGE_RAM, H.HR_STORAGE_FIXED_DISK, "1.3.6.1.2.1.25.2.1.1"


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


def _asset(db, ip="10.70.0.1"):
    t = AssetType(type_name=f"Server {_n()}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"h-{_n()}", asset_type_id=t.id, ip_address=ip)
    db.add(a)
    db.flush()
    return a


def _storage(rows):
    out = {}
    for idx, (kind, name, units, size, used) in rows.items():
        out.update({f"{H.HR_STORAGE}.2.{idx}": kind, f"{H.HR_STORAGE}.3.{idx}": name.encode(),
                    f"{H.HR_STORAGE}.4.{idx}": units, f"{H.HR_STORAGE}.5.{idx}": size,
                    f"{H.HR_STORAGE}.6.{idx}": used})
    return out


# ── reading the MIBs ────────────────────────────────────────────────────────

def test_linux_host_resources_and_ucd():
    values = {
        f"{H.HR_SYSTEM_UPTIME}.0": timedelta(days=3, hours=2),
        f"{H.HR_PROCESSOR_LOAD}.196608": 30, f"{H.HR_PROCESSOR_LOAD}.196609": 50,
        f"{H.UCD_MEMORY}.5.0": 8_000_000, f"{H.UCD_MEMORY}.6.0": 1_000_000, f"{H.UCD_MEMORY}.27.0": 2_000_000,
        f"{H.UCD_CPU_IDLE}.0": 10,
        f"{H.UCD_LM_TEMP}.2.1": b"Package id 0", f"{H.UCD_LM_TEMP}.3.1": 61500,
        f"{H.UCD_LM_TEMP}.2.2": b"Core 0", f"{H.UCD_LM_TEMP}.3.2": 58000,
        **_storage({1: (RAM, "Physical memory", 1024, 8_000_000, 7_900_000),
                    31: (DISK, "/", 4096, 1_000_000, 920_000),
                    32: (DISK, "/var", 4096, 1_000_000, 500_000),
                    33: (DISK, "/run", 4096, 1000, 999),          # left out
                    34: (DISK, "/snap/core/1", 4096, 100, 100),   # left out
                    35: (OTHER, "Virtual memory", 1024, 9, 9)}),
    }
    h = H.summarize(values)
    assert h.cpu_percent == 40.0 and h.source == "host-resources"     # cores averaged, not ssCpuIdle
    assert h.memory_percent == 75.0 and h.memory_total_bytes == 8_000_000 * 1024   # total - available
    assert h.disk_percent == 92.0 and [f["name"] for f in h.filesystems] == ["/", "/var"]
    assert h.filesystems[0]["size"] == 4_096_000_000
    assert h.temperature_c == 61.5 and h.sensors[0]["name"] == "Package id 0"
    assert h.uptime_ticks == int(timedelta(days=3, hours=2).total_seconds() * 100)


def test_fallbacks_when_a_mib_is_missing():
    # older net-snmp: no memSysAvail -> total - free - buffers - cache; no hrProcessorLoad -> 100 - ssCpuIdle
    h = H.summarize({f"{H.UCD_MEMORY}.5.0": 1000, f"{H.UCD_MEMORY}.6.0": 300, f"{H.UCD_MEMORY}.14.0": 100,
                     f"{H.UCD_MEMORY}.15.0": 200, f"{H.UCD_CPU_IDLE}.0": 85})
    assert (h.cpu_percent, h.memory_percent, h.source) == (15.0, 40.0, "ucd")
    # Windows: HOST-RESOURCES only
    h = H.summarize(_storage({1: (RAM, "Physical Memory", 65536, 1000, 250),
                              2: (DISK, "C:\\ Label:  Serial Number 1", 4096, 100, 81)}))
    assert (h.memory_percent, h.disk_percent, h.cpu_percent) == (25.0, 81.0, None)
    # nothing at all
    h = H.summarize({})
    assert h.detail() is None and h.cpu_percent is None and h.uptime_ticks is None


def test_cisco():
    values = {
        f"{H.CISCO_CPU_1MIN}.1": 12, f"{H.CISCO_CPU_1MIN}.2": 20,
        f"{H.CISCO_MEMPOOL}.2.1": b"Processor", f"{H.CISCO_MEMPOOL}.5.1": 300, f"{H.CISCO_MEMPOOL}.6.1": 700,
        f"{H.CISCO_MEMPOOL}.2.2": b"I/O", f"{H.CISCO_MEMPOOL}.5.2": 90, f"{H.CISCO_MEMPOOL}.6.2": 10,
        f"{H.CISCO_TEMPERATURE}.2.1": b"Inlet Temp Sensor", f"{H.CISCO_TEMPERATURE}.3.1": 34,
        # ENTITY-SENSOR: 452 in tenths (precision 1) of units (scale 9), celsius (8); a fan (type 10) ignored
        f"{H.ENT_SENSOR}.1.1010": 8, f"{H.ENT_SENSOR}.2.1010": 9, f"{H.ENT_SENSOR}.3.1010": 1,
        f"{H.ENT_SENSOR}.4.1010": 452, f"{H.ENT_PHYSICAL_NAME}.1010": b"CPU die",
        f"{H.ENT_SENSOR}.1.1011": 10, f"{H.ENT_SENSOR}.4.1011": 5000,
    }
    h = H.summarize(values)
    assert (h.cpu_percent, h.memory_percent, h.memory_total_bytes, h.source) == (16.0, 30.0, 1000, "cisco")
    assert h.temperature_c == 45.2 and [s["name"] for s in h.sensors] == ["CPU die", "Inlet Temp Sensor"]
    # no memory pool: cpmCPUMemoryUsed/Free (kB)
    h = H.summarize({f"{H.CISCO_CPU_MEM_USED}.1": 600, f"{H.CISCO_CPU_MEM_FREE}.1": 400})
    assert (h.memory_percent, h.memory_total_bytes) == (60.0, 1000 * 1024)


def test_fortigate():
    values = {
        f"{H.FORTI_SYSTEM}.3.0": 7, f"{H.FORTI_SYSTEM}.4.0": 63, f"{H.FORTI_SYSTEM}.5.0": 4_000_000,
        f"{H.FORTI_SYSTEM}.6.0": 1500, f"{H.FORTI_SYSTEM}.7.0": 2000,
        f"{H.FORTI_SENSOR}.2.1": b"DTS CPU0", f"{H.FORTI_SENSOR}.3.1": b"55",
        f"{H.FORTI_SENSOR}.2.2": b"PS1 Temp", f"{H.FORTI_SENSOR}.3.2": b"41",
        f"{H.FORTI_SENSOR}.2.3": b"FAN1", f"{H.FORTI_SENSOR}.3.3": b"4200",       # not a temperature
        f"{H.FORTI_SENSOR}.2.4": b"PS2 Temp", f"{H.FORTI_SENSOR}.3.4": b"0",      # absent sensor reads 0
    }
    h = H.summarize(values)
    assert (h.cpu_percent, h.memory_percent, h.memory_total_bytes, h.source) == (7.0, 63.0, 4_096_000_000,
                                                                                 "fortigate")
    assert h.disk_percent == 75.0 and h.temperature_c == 55.0
    assert [s["name"] for s in h.sensors] == ["DTS CPU0", "PS1 Temp"]


def test_vendor_mibs_are_asked_only_of_their_vendor():
    asked = []

    class Client:
        def multiwalk(self, roots):
            asked.append(tuple(roots))

            async def gen():
                if False:
                    yield None
            return gen()

    asyncio.run(H.collect(Client(), "Linux web01 6.8.0 #1 SMP x86_64", 1))
    assert tuple(H.CISCO) not in asked and tuple(H.FORTI) not in asked and tuple(H.GENERIC) in asked
    asked.clear()
    asyncio.run(H.collect(Client(), "Cisco IOS Software, C2960X Software", 1))
    assert tuple(H.CISCO) in asked and tuple(H.FORTI) not in asked


# ── storing a poll, history, restarts ───────────────────────────────────────

def _poll(uptime_s, cpu=10.0, mem=20.0, disk=30.0, temp=40.0, sys_uptime_s=None):
    h = H.Health(cpu_percent=cpu, memory_percent=mem, memory_total_bytes=10, disk_percent=disk, temperature_c=temp,
                 uptime_ticks=uptime_s * 100 if uptime_s is not None else None, source="host-resources",
                 filesystems=[{"name": "/", "size": 10, "used": 3, "percent": disk}],
                 sensors=[{"name": "cpu", "celsius": temp}] if temp is not None else [])
    return DevicePollResult(reachable=True, sys_descr="Linux", sys_uptime_ticks=(sys_uptime_s or 5) * 100, health=h)


def test_poll_stores_health_history_and_notices_restarts(db, monkeypatch):
    a = _asset(db)
    clock = {"now": datetime(2026, 10, 17, 8, 0, 0)}

    class _Clock(datetime):
        @classmethod
        def utcnow(cls):
            return clock["now"]
    monkeypatch.setattr("app.modules.noc.service.datetime", _Clock)

    st = NocService._persist_poll_result(db, a.id, _poll(10 * 86400))
    assert (st.cpu_percent, st.memory_percent, st.disk_percent, st.temperature_c) == (10.0, 20.0, 30.0, 40.0)
    assert st.device_uptime_ticks == 10 * 86400 * 100 and st.health["filesystems"][0]["name"] == "/"
    assert st.last_reboot_at == clock["now"] - timedelta(days=10)
    kinds = {m for (m,) in db.query(AssetMetricSample.metric_type).filter(AssetMetricSample.asset_id == a.id)}
    assert {"cpu_percent", "memory_percent", "disk_percent", "temperature_c", "reachable"} <= kinds

    # a minute later, one minute more uptime: no restart (the agent's own sysUpTime is not used)
    clock["now"] += timedelta(seconds=60)
    NocService._persist_poll_result(db, a.id, _poll(10 * 86400 + 61, sys_uptime_s=3))
    assert db.query(DeviceReboot).filter(DeviceReboot.asset_id == a.id).count() == 0

    # unreachable for a while: health kept as last known, no samples of it
    clock["now"] += timedelta(seconds=60)
    st = NocService._persist_poll_result(db, a.id, DevicePollResult(reachable=False, error_message="timed out"))
    assert st.cpu_percent == 10.0

    # back, with 5 minutes of uptime: restarted
    clock["now"] += timedelta(minutes=10)
    NocService._persist_poll_result(db, a.id, _poll(300))
    r = db.query(DeviceReboot).filter(DeviceReboot.asset_id == a.id).one()
    assert r.booted_at == clock["now"] - timedelta(seconds=300) and r.previous_uptime_seconds > 10 * 86400

    # the 32-bit TimeTicks wrap after ~497 days is not a restart
    clock["now"] += timedelta(minutes=1)
    st = db.query(AssetSnmpStatus).filter(AssetSnmpStatus.asset_id == a.id).one()
    st.last_reboot_at = clock["now"] - timedelta(seconds=2 ** 32 / 100 + 30)
    db.flush()
    NocService._persist_poll_result(db, a.id, _poll(30))
    assert db.query(DeviceReboot).filter(DeviceReboot.asset_id == a.id).count() == 1


def test_device_without_host_resources_uses_sysuptime(db):
    a = _asset(db)
    res = DevicePollResult(reachable=True, sys_descr="Cisco IOS", sys_uptime_ticks=123400, health=H.Health())
    st = NocService._persist_poll_result(db, a.id, res)
    assert st.device_uptime_ticks == 123400 and st.health is None


# ── alerts ──────────────────────────────────────────────────────────────────

def _samples(db, a, metric, values, end):
    for i, v in enumerate(values):
        db.add(AssetMetricSample(asset_id=a.id, metric_type=metric, value=v,
                                 sampled_at=end - timedelta(minutes=len(values) - 1 - i)))
    db.flush()


def test_cpu_and_memory_alert_only_when_sustained(db):
    now = datetime.utcnow()
    busy, spike, short = _asset(db, "10.70.1.1"), _asset(db, "10.70.1.2"), _asset(db, "10.70.1.3")
    _samples(db, busy, "cpu_percent", [95, 97, 99, 96, 94, 98, 99, 97, 95, 96, 97], now)
    _samples(db, spike, "cpu_percent", [20, 25, 99, 30, 22, 21, 23, 20, 24, 22, 21], now)
    _samples(db, short, "cpu_percent", [99, 99], now)                       # only 1 minute of a 10-minute window
    probs = E._cpu_high(db, {"percent": 90, "minutes": 10}, now, now)
    assert {p.asset_id for p in probs} >= {busy.id} and not {spike.id, short.id} & {p.asset_id for p in probs}
    p = next(p for p in probs if p.asset_id == busy.id)
    assert p.detail == "CPU at 97%, at or above 90% for 10 min" and p.link == f"/noc/hosts/{busy.id}"
    # the shortest window: two polls a minute apart cover 2 minutes
    _samples(db, short, "memory_percent", [95, 96], now)
    assert short.id in {p.asset_id for p in E._memory_high(db, {"percent": 90, "minutes": 2}, now, now)}
    _samples(db, spike, "memory_percent", [93] * 16, now)
    assert spike.id in {p.asset_id for p in E._memory_high(db, {"percent": 90, "minutes": 15}, now, now)}


def test_disk_temperature_and_restart_alerts(db):
    now = datetime.utcnow()
    a = _asset(db, "10.70.2.1")
    db.add(AssetSnmpStatus(asset_id=a.id, reachable=True, disk_percent=95.0, temperature_c=78.0,
                           health={"filesystems": [{"name": "/var", "percent": 95.0}, {"name": "/", "percent": 91.0},
                                                   {"name": "/boot", "percent": 40.0}],
                                   "sensors": [{"name": "Package id 0", "celsius": 78.0}]}))
    db.add(DeviceReboot(asset_id=a.id, detected_at=now, booted_at=datetime(2026, 10, 17, 7, 58),
                        previous_uptime_seconds=40 * 86400))
    db.flush()
    disk = next(p for p in E._disk_full(db, {"percent": 90}, now, now) if p.asset_id == a.id)
    assert disk.detail == "/var 95% full (and 1 more)"
    temp = next(p for p in E._temperature_high(db, {"celsius": 70}, now, now) if p.asset_id == a.id)
    assert temp.detail == "Package id 0 at 78 °C"
    assert not [p for p in E._temperature_high(db, {"celsius": 80}, now, now) if p.asset_id == a.id]
    boot = next(p for p in E._device_rebooted(db, {}, now, now - timedelta(minutes=1)) if p.asset_id == a.id)
    assert boot.detail == "Restarted after 40 days of uptime"
    for code in ("noc.cpu_high", "noc.memory_high", "noc.disk_full", "noc.temperature_high", "noc.device_rebooted"):
        assert code in E.EVENTS


# ── API and the asset page ──────────────────────────────────────────────────

def test_host_api_and_asset_360(db):
    admin = User(username=f"nh_{_n()}", hashed_password="x", role=UserRole.ADMIN, is_active=True)
    db.add(admin)
    a = _asset(db, "10.70.3.1")
    db.flush()
    NocService._persist_poll_result(db, a.id, _poll(3600))
    db.add(DeviceReboot(asset_id=a.id, detected_at=datetime.utcnow(), booted_at=datetime.utcnow() - timedelta(hours=1),
                        previous_uptime_seconds=86400))
    db.flush()
    d = NR.get_host_detail(a.id, current_user=admin, db=db)
    assert d.health.cpu_percent == 10.0 and d.uptime_seconds == 3600 and d.health_source == "host-resources"
    assert d.filesystems[0].name == "/" and d.sensors[0].celsius == 40.0 and len(d.reboots) == 1
    row = next(h for h in NR.list_hosts(current_user=admin, db=db) if h.asset_id == a.id)
    assert row.health.memory_percent == 20.0
    now = datetime.utcnow()
    series = NR.get_host_metrics(a.id, metric="cpu_percent", interface_id=None, start=now - timedelta(hours=1),
                                 end=now + timedelta(minutes=1), current_user=admin, db=db)
    assert series.points and series.points[-1].avg == 10.0
    m = overview360.build(db, a, admin)
    assert m["monitoring"]["snmp"]["cpu_percent"] == 10.0 and m["monitoring"]["snmp"]["uptime_seconds"] == 3600
    assert any(e["kind"] == "reboot" for e in m["timeline"])


# ── a real agent ────────────────────────────────────────────────────────────

def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.skipif(not shutil.which("snmpd") or os.geteuid() != 0, reason="net-snmp agent not installed")
def test_real_net_snmp_agent():
    from app.modules.noc.snmp_client import poll_asset
    port = _free_udp_port()
    with tempfile.TemporaryDirectory() as tmp:
        conf = os.path.join(tmp, "snmpd.conf")
        with open(conf, "w") as f:
            f.write(f"agentAddress udp:127.0.0.1:{port}\nview all included .1\nrocommunity ngc-test default -V all\n")
        proc = subprocess.Popen(["snmpd", "-f", "-Lo", "-C", "-c", conf], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)
            cred = SimpleNamespace(version="v2c", port=port, community_encrypted=encrypt_secret("ngc-test"))
            r = asyncio.run(poll_asset("127.0.0.1", cred))
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    assert r.reachable and r.health is not None
    assert r.health.memory_percent is not None and 0 < r.health.memory_percent < 100
    assert r.health.memory_total_bytes > 0 and r.health.filesystems
    assert r.health.uptime_ticks and r.health.uptime_ticks >= r.sys_uptime_ticks    # the host's, not the agent's


def test_old_restarts_are_forgotten(db):
    from app.modules.noc.metrics_retention import forget_old_reboots
    a = _asset(db, "10.70.4.1")
    now = datetime.utcnow()
    old = DeviceReboot(asset_id=a.id, detected_at=now - timedelta(days=800), booted_at=now - timedelta(days=800))
    new = DeviceReboot(asset_id=a.id, detected_at=now - timedelta(days=10), booted_at=now - timedelta(days=10))
    db.add_all([old, new])
    db.flush()
    old_id, new_id = old.id, new.id
    assert forget_old_reboots(db, now) >= 1
    assert db.get(DeviceReboot, old_id) is None and db.get(DeviceReboot, new_id) is not None
