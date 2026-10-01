"""
Backup & Restore overview and restore history: which devices count as
supported, fresh / stale / never, per-family coverage, the 30-day activity,
and the Restore History filters.

The overview covers every asset in the database, so assertions compare
against a baseline taken before the test adds its own rows.
"""
import importlib
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, DeviceBackup, User, UserRole
from app.models.asset_types import AssetType
from app.models.backup_restore import BackupRestore
from app.modules.backup.overview import compute_overview, restore_history

backup_router = importlib.import_module("app.modules.backup.router")


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


@pytest.fixture
def user(db):
    u = User(username=f"bk_overview_{_n()}", hashed_password="x", role=UserRole.ADMIN)
    db.add(u)
    db.flush()
    return u


def _asset(db, name, type_name, os_name=None, manufacturer=None):
    t = AssetType(type_name=f"{type_name} {_n()}", category="network")
    db.add(t)
    db.flush()
    a = Asset(asset_name=name, asset_type_id=t.id, os_name=os_name, manufacturer=manufacturer,
              ip_address=f"10.77.{_n() % 250}.{_n() % 250}")
    db.add(a)
    db.flush()
    return a


def _backup(db, asset, device_type, age_days, source="manual"):
    b = DeviceBackup(asset_id=asset.id, asset_name=asset.asset_name, device_ip=asset.ip_address,
                     device_type=device_type, config_content="x", source=source,
                     created_at=datetime.utcnow() - timedelta(days=age_days))
    db.add(b)
    db.flush()
    return b


def _restore(db, asset, user, status, reason="Roll back change CR-1", age_days=1):
    j = BackupRestore(asset_id=asset.id, asset_name=asset.asset_name, device_ip=asset.ip_address,
                      device_type="fortinet", status=status, reason=reason, revert_minutes=10, events=[],
                      requested_by=user.id, created_at=datetime.utcnow() - timedelta(days=age_days))
    db.add(j)
    db.flush()
    return j


class TestOverview:
    def test_states_families_and_unsupported_devices(self, db):
        base = compute_overview(db)
        fresh = _asset(db, "bk-fgt-fresh", "Firewall", os_name="FortiOS")
        stale = _asset(db, "bk-cisco-stale", "Router", manufacturer="Cisco")
        never = _asset(db, "bk-linux-never", "Server", os_name="Ubuntu 22.04")
        windows = _asset(db, "bk-win", "Server", os_name="Windows Server 2022")
        by_backup = _asset(db, "bk-web-unknown", "Appliance")        # nothing to infer from
        _backup(db, fresh, "fortinet", 2)
        _backup(db, fresh, "fortinet", 90)
        _backup(db, stale, "cisco", 40)
        _backup(db, by_backup, "apache", 5)

        o = compute_overview(db)
        assert o["supported"] - base["supported"] == 4               # Windows has no backup driver
        assert o["fresh"] - base["fresh"] == 2                        # newest backup decides
        assert o["stale"] - base["stale"] == 1
        assert o["never"] - base["never"] == 1

        ids = {d["asset_id"]: d for d in o["attention"]}
        assert ids[never.id]["state"] == "never" and ids[never.id]["family"] == "linux"
        assert ids[stale.id]["state"] == "stale"
        assert fresh.id not in ids and windows.id not in ids and by_backup.id not in ids
        # Never-backed-up devices come first.
        states = [d["state"] for d in o["attention"]]
        assert states == sorted(states, key=lambda s: s != "never")

        fam = {f["family"]: f for f in o["by_family"]}
        base_fam = {f["family"]: f for f in base["by_family"]}
        delta = lambda k, f: fam[f][k] - base_fam.get(f, {"total": 0, "fresh": 0})[k]  # noqa: E731
        assert (delta("total", "fortinet"), delta("fresh", "fortinet")) == (1, 1)
        assert (delta("total", "apache"), delta("fresh", "apache")) == (1, 1)
        assert (delta("total", "cisco"), delta("fresh", "cisco")) == (1, 0)

    def test_activity_last_30_days(self, db, user):
        base = compute_overview(db)
        a = _asset(db, "bk-fgt-activity", "Firewall", os_name="FortiOS")
        _backup(db, a, "fortinet", 0, "manual")
        _backup(db, a, "fortinet", 0, "hardening")
        _backup(db, a, "fortinet", 3, "pre_restore")
        _backup(db, a, "fortinet", 45, "manual")                     # outside the window
        _restore(db, a, user, "succeeded")
        _restore(db, a, user, "reverted")
        _restore(db, a, user, "failed", age_days=40)                  # outside the window

        o = compute_overview(db)
        b, b0 = o["backups_30d"], base["backups_30d"]
        assert (b["manual"] - b0["manual"], b["hardening"] - b0["hardening"],
                b["pre_restore"] - b0["pre_restore"]) == (1, 1, 1)
        assert len(o["daily"]) == 30 and o["daily"][-1]["date"] == datetime.utcnow().date().isoformat()
        assert o["daily"][-1]["manual"] - base["daily"][-1]["manual"] == 1
        assert o["daily"][-1]["automatic"] - base["daily"][-1]["automatic"] == 1
        r, r0 = o["restores_30d"], base["restores_30d"]
        assert (r["succeeded"] - r0["succeeded"], r["reverted"] - r0["reverted"], r["failed"] - r0["failed"]) == (1, 1, 0)

    def test_endpoint_adds_recent_restores(self, db, user):
        a = _asset(db, "bk-fgt-recent", "Firewall", os_name="FortiOS")
        j = _restore(db, a, user, "succeeded", age_days=0)
        out = backup_router.backup_overview(current_user=user, db=db)
        assert out["recent_restores"][0].id == j.id
        assert backup_router.BackupOverview(**out)


class TestRestoreHistory:
    def test_groups_search_and_counts(self, db, user):
        a = _asset(db, "bk-hist-fw", "Firewall", os_name="FortiOS")
        b = _asset(db, "bk-hist-rtr", "Router", manufacturer="Cisco")
        _restore(db, a, user, "succeeded", reason="Undo temporary rule INC-9001")
        _restore(db, a, user, "reverted", reason="Roll back ACL INC-9001")
        _restore(db, b, user, "failed", reason="Back out VLAN INC-9001")
        _restore(db, b, user, "applying", reason="Restore NTP INC-9001")
        _restore(db, b, user, "succeeded", reason="Old one INC-9001", age_days=200)

        jobs, total, counts = restore_history(db, search="INC-9001", days=90)
        assert total == 4 and counts == {"all": 4, "active": 1, "succeeded": 1, "reverted": 1, "failed": 1}
        jobs, total, counts = restore_history(db, group="reverted", search="inc-9001", days=90)
        assert [j.reason for j in jobs] == ["Roll back ACL INC-9001"] and counts["all"] == 4
        jobs, total, _ = restore_history(db, search="bk-hist-rtr", days=None)
        assert total == 3
        jobs, total, _ = restore_history(db, search=user.username, days=90, limit=2)
        assert total >= 4 and len(jobs) == 2

    def test_history_route_is_not_parsed_as_a_job_id(self):
        paths = [r.path for r in backup_router.router.routes]
        assert paths.index("/api/backups/restores/history") < paths.index("/api/backups/restores/{job_id}")
        assert paths.index("/api/backups/overview") < paths.index("/api/backups/{backup_id}")
