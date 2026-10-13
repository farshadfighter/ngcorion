"""
The asset 360 page (GET /api/assets/{asset_id}/360, app/modules/assets/overview360.py): every
section filled for an administrator, sections of modules a user cannot read left out, audit
sessions and hardening actions limited to the user's own, groups (static and by rule), timeline.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserPermission, UserRole
from app.models.asset_groups import AssetGroup, AssetGroupMember, AssetTag
from app.models.asset_log import AssetLog
from app.models.audit import AuditSession, DeviceType
from app.models.backup import DeviceBackup
from app.models.noc import AssetSnmpStatus
from app.models.notification import Alert
from app.models.remediation import RemediationItem
from app.models.syslog import SyslogMessage
from app.models.topology import TopologyLink
from app.models.user_permission import ModuleEnum
from app.modules.assets import overview360
from app.modules.assets.router_with_auth import get_asset_360


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


def _user(db, role=UserRole.ADMIN, perms=()):
    u = User(username=f"a360_{_n()}", hashed_password="x", role=role, is_active=True)
    db.add(u)
    db.flush()
    for m in perms:
        db.add(UserPermission(user_id=u.id, module=m, can_read=True, can_write=False, can_delete=False))
    db.flush()
    return u


@pytest.fixture
def world(db):
    """One asset with something in every section."""
    admin = _user(db)
    t = AssetType(type_name=f"Linux Server {_n()}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"web-{_n()}", asset_type_id=t.id, ip_address="10.88.0.1", os_name="Ubuntu")
    other = Asset(asset_name=f"sw-{_n()}", asset_type_id=t.id, ip_address="10.88.0.2")
    db.add_all([a, other])
    db.flush()
    db.add(AssetTag(asset_id=a.id, tag="pci"))
    static = AssetGroup(name=f"static-{_n()}", kind="static", rules=[])
    by_tag = AssetGroup(name=f"pci-{_n()}", kind="dynamic", rules=[{"field": "tag", "op": "has", "value": "pci"}])
    not_mine = AssetGroup(name=f"none-{_n()}", kind="dynamic", rules=[{"field": "tag", "op": "has", "value": "zzz"}])
    db.add_all([static, by_tag, not_mine])
    db.flush()
    db.add(AssetGroupMember(group_id=static.id, asset_id=a.id))
    now = datetime.utcnow()
    db.add(AuditSession(user_id=admin.id, asset_id=a.id, target_ip=a.ip_address, device_type=DeviceType.LINUX,
                        status="completed", started_at=now - timedelta(days=2), completed_at=now - timedelta(days=2),
                        compliance_pct=70, weighted_compliance_pct=65, total_checks=100, passed_checks=65,
                        failed_checks=35))
    db.add(DeviceBackup(asset_id=a.id, asset_name=a.asset_name, device_ip=a.ip_address, device_type="linux",
                        config_content="x", source="scheduled", created_at=now - timedelta(days=1),
                        change_origin="external", changed=True, added_lines=2, removed_lines=1))
    db.add(RemediationItem(key=f"k-{_n()}", source="audit", ref="5.1", asset_id=a.id, title="SSH root login",
                           severity="high", status="open", due_at=now - timedelta(days=1)))
    db.add(Alert(event_type="noc.syslog_severe", module="noc", severity="warning", fingerprint=f"f-{_n()}",
                 title="Severe syslog message", asset_id=a.id, status="active", first_seen_at=now))
    db.add(Alert(event_type="system.x", module="system", severity="critical", fingerprint=f"f-{_n()}",
                 title="System thing", asset_id=a.id, status="active", first_seen_at=now))
    db.add(SyslogMessage(asset_id=a.id, received_at=now, source_ip=a.ip_address, protocol="udp", severity=2,
                         app_name="kernel", message="disk failed"))
    db.add(AssetSnmpStatus(asset_id=a.id, reachable=True, last_polled_at=now, sys_uptime_ticks=360000))
    db.add(TopologyLink(source_asset_id=a.id, destination_asset_id=other.id, source_interface="eth0",
                        destination_interface="Gi1/0/1", link_type="ethernet", status="active"))
    db.add(AssetLog(user_id=admin.id, action="update", asset_id=a.id, asset_name=a.asset_name,
                    timestamp=now - timedelta(hours=1), status="success"))
    db.flush()
    return {"admin": admin, "asset": a, "other": other, "static": static, "by_tag": by_tag, "not_mine": not_mine}


def test_administrator_sees_every_section(db, world):
    a = world["asset"]
    d = get_asset_360(a.id, current_user=world["admin"], db=db)
    assert d["asset"]["name"] == a.asset_name and d["asset"]["tags"] == ["pci"]
    groups = {g["id"] for g in d["asset"]["groups"]}
    assert {world["static"].id, world["by_tag"].id} <= groups and world["not_mine"].id not in groups
    assert d["audits"]["total"] == 1 and d["audits"]["latest"][0]["compliance"] == 65.0
    assert d["backups"]["total"] == 1 and d["backups"]["last_change_origin"] == "external"
    assert d["backups"]["external_changes_30d"] == 1
    assert d["remediation"]["open"] == 1 and d["remediation"]["overdue"] == 1
    assert d["monitoring"]["snmp"]["reachable"] is True and d["monitoring"]["snmp"]["uptime_seconds"] == 3600
    assert d["monitoring"]["syslog"]["severe_24h"] == 1
    assert {x["title"] for x in d["alerts"]} == {"Severe syslog message", "System thing"}
    assert d["topology"][0]["name"] == world["other"].asset_name
    assert d["topology"][0]["local_interface"] == "eth0" and d["topology"][0]["remote_interface"] == "Gi1/0/1"
    assert d["cve"] is not None and d["risk"] is not None and d["hardening"] is not None
    kinds = [e["kind"] for e in d["timeline"]]
    assert {"asset", "audit", "backup", "alert"} <= set(kinds)
    assert [e["at"] for e in d["timeline"]] == sorted((e["at"] for e in d["timeline"]), reverse=True)


def test_sections_follow_the_users_permissions(db, world):
    a = world["asset"]
    viewer = _user(db, UserRole.USER,
                   perms=[ModuleEnum.ASSET_LIST, ModuleEnum.NOC])
    d = overview360.build(db, a, viewer)
    for section in ("risk", "audits", "hardening", "cve", "remediation", "backups", "topology"):
        assert d[section] is None, section
    assert d["monitoring"] is not None
    # only the NOC alert, not the system one
    assert [x["title"] for x in d["alerts"]] == ["Severe syslog message"]
    assert {e["kind"] for e in d["timeline"]} <= {"asset", "alert"}


def test_audit_sessions_are_the_users_own(db, world):
    a = world["asset"]
    auditor = _user(db, UserRole.USER,
                    perms=[ModuleEnum.ASSET_LIST, ModuleEnum.AUDITING])
    d = overview360.build(db, a, auditor)
    assert d["audits"]["total"] == 0 and d["audits"]["latest"] == []
    db.add(AuditSession(user_id=auditor.id, asset_id=a.id, target_ip=a.ip_address, device_type=DeviceType.LINUX,
                        status="completed", completed_at=datetime.utcnow(), compliance_pct=90))
    db.flush()
    d = overview360.build(db, a, auditor)
    assert d["audits"]["total"] == 1 and d["audits"]["latest"][0]["compliance"] == 90.0


def test_unknown_asset(db, world):
    with pytest.raises(HTTPException) as e:
        get_asset_360(10 ** 9, current_user=world["admin"], db=db)
    assert e.value.status_code == 404
