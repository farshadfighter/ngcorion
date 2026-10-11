"""
Audit storage (FAU_STG): the guard that pauses changes when the disk is nearly full
(app/core/storage_guard.py) and the archive-then-purge tool for old audit records
(app/modules/audit_archive/). The archive tests need a migrated PostgreSQL database.
"""
import json
import zipfile
from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from app.core import storage_guard
from app.core.database import SessionLocal
from app.models import LoginLog
from app.models.security_audit_log import AuditLog
from app.modules.audit_archive import archive as audit_archive

# Far in the past, so no other test's rows are older than the cut-off.
OLD = datetime(2001, 3, 4, 12, 0, tzinfo=timezone.utc)
BEFORE = date(2001, 6, 1)


# ── storage guard ───────────────────────────────────────────────────────────

def _request(method, path="/api/assets/"):
    return SimpleNamespace(method=method, url=SimpleNamespace(path=path))


def _user(role):
    return SimpleNamespace(role=SimpleNamespace(value=role))


@pytest.fixture
def critical(monkeypatch):
    monkeypatch.setattr(storage_guard, "storage_critical", lambda: True)


def test_changes_refused_to_everyone_but_administrators_when_critical(critical):
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(HTTPException) as err:
            storage_guard.check_request(_request(method), _user("manager"))
        assert err.value.status_code == 507
    storage_guard.check_request(_request("POST"), _user("admin"))       # frees the space
    storage_guard.check_request(_request("GET"), _user("user"))         # reading goes on
    storage_guard.check_request(_request("POST", "/auth/logout"), _user("user"))


def test_nothing_refused_with_room(monkeypatch):
    monkeypatch.setattr(storage_guard, "storage_critical", lambda: False)
    storage_guard.check_request(_request("DELETE"), _user("user"))


def test_state_change_is_recorded_once(monkeypatch):
    free = {"bytes": 100 * 1024 ** 2}
    monkeypatch.setattr(storage_guard, "_lowest_free", lambda: (free["bytes"], "/data"))
    monkeypatch.setattr(storage_guard.settings, "STORAGE_CRITICAL_MB", 500)
    monkeypatch.setitem(storage_guard._state, "critical", False)
    recorded = []
    monkeypatch.setattr(storage_guard, "_record", lambda crit, f, p: recorded.append(crit))
    assert storage_guard.storage_state(force=True)["critical"] is True
    assert storage_guard.storage_state(force=True)["critical"] is True
    free["bytes"] = 5 * 1024 ** 3
    assert storage_guard.storage_state(force=True)["critical"] is False
    assert recorded == [True, False]


def test_guard_can_be_turned_off(monkeypatch):
    monkeypatch.setattr(storage_guard, "_lowest_free", lambda: (1, "/data"))
    monkeypatch.setattr(storage_guard.settings, "STORAGE_CRITICAL_MB", 0)
    monkeypatch.setattr(storage_guard, "_record", lambda *a: None)
    assert storage_guard.storage_state(force=True)["critical"] is False


# ── archive and purge ───────────────────────────────────────────────────────

@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def old_rows(db):
    """Three audit events and two sign-ins from 2001, plus one of each from today."""
    db.add_all([AuditLog(username="arch-a", action="user.create", module="user_management", result="success",
                         detail=f"old event {i}\nwith a second line, \"quotes\", commas", timestamp=OLD)
                for i in range(3)])
    db.add_all([LoginLog(username="arch-a", success=i == 0, ip_address="192.0.2.8", timestamp=OLD)
                for i in range(2)])
    db.add(AuditLog(username="arch-a", action="user.create", module="user_management", result="success",
                    detail="new event"))
    db.add(LoginLog(username="arch-a", success=True, ip_address="192.0.2.8", timestamp=datetime.now(timezone.utc)))
    db.commit()
    yield
    # Whatever a failed test left behind in 2001 goes, so the next run starts clean.
    db.rollback()
    db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_change"))
    db.execute(text("DELETE FROM audit_logs WHERE timestamp < :c"), {"c": OLD.replace(year=2002)})
    db.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_change"))
    db.execute(text("DELETE FROM login_logs WHERE timestamp < :c"), {"c": OLD.replace(year=2002)})
    db.commit()


def _utc(_db):
    return None


@patch("app.modules.alerts.channels.local_timezone", _utc)
def test_export_verify_purge(db, old_rows, tmp_path):
    path, manifest = audit_archive.export(db, BEFORE, tmp_path)
    assert manifest["tables"]["audit_logs"]["rows"] == 3 and manifest["tables"]["login_logs"]["rows"] == 2
    assert audit_archive.verify(path)["cutoff"] == "2001-06-01T00:00:00+00:00"
    with zipfile.ZipFile(path) as zf:
        assert b"with a second line" in zf.read("audit_logs.csv")

    done = audit_archive.purge(db, path)
    assert (done["events"], done["logins"]) == (3, 2)
    cutoff = datetime(2001, 6, 1, tzinfo=timezone.utc)
    assert db.query(AuditLog).filter(AuditLog.timestamp < cutoff).count() == 0
    assert db.query(LoginLog).filter(LoginLog.timestamp < cutoff).count() == 0
    assert db.query(AuditLog).filter(AuditLog.detail == "new event").count() >= 1
    record = db.query(AuditLog).filter(AuditLog.action == "audit.archive_purge").order_by(AuditLog.id.desc()).first()
    assert done["archive_sha256"] in record.detail and "Removed 3 audit events and 2 sign-ins" in record.detail
    # Append-only again straight after.
    with pytest.raises(Exception, match="append-only"):
        db.execute(text("UPDATE audit_logs SET detail = 'x' WHERE id = :i"), {"i": record.id})
    db.rollback()


@patch("app.modules.alerts.channels.local_timezone", _utc)
def test_purge_refuses_when_the_database_holds_more_than_the_archive(db, old_rows, tmp_path):
    path, _ = audit_archive.export(db, BEFORE, tmp_path)
    db.add(AuditLog(username="arch-late", action="user.create", module="user_management", result="success",
                    timestamp=OLD))
    db.commit()
    with pytest.raises(audit_archive.ArchiveError, match="nothing was removed"):
        audit_archive.purge(db, path)
    assert db.query(AuditLog).filter(AuditLog.timestamp < OLD.replace(year=2002)).count() == 4


@patch("app.modules.alerts.channels.local_timezone", _utc)
def test_tampered_archive_is_refused(db, old_rows, tmp_path):
    path, _ = audit_archive.export(db, BEFORE, tmp_path)
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(path) as src, zipfile.ZipFile(tampered, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            dst.writestr(name, data.replace(b"old event 1", b"old event 9") if name == "audit_logs.csv" else data)
    with pytest.raises(audit_archive.ArchiveError, match="does not match"):
        audit_archive.verify(tampered)
    with pytest.raises(audit_archive.ArchiveError):
        audit_archive.purge(db, tampered)


def test_cutoff_is_the_start_of_the_day_in_the_configured_time_zone(db):
    with patch("app.modules.alerts.channels.local_timezone", lambda _db: ZoneInfo("Asia/Tehran")):
        cutoff = audit_archive.cutoff_for(db, date(2026, 1, 1))
    assert cutoff.astimezone(timezone.utc) == datetime(2025, 12, 31, 20, 30, tzinfo=timezone.utc)


def test_manifest_records_the_format(db, old_rows, tmp_path):
    with patch("app.modules.alerts.channels.local_timezone", _utc):
        path, _ = audit_archive.export(db, BEFORE, tmp_path)
    with zipfile.ZipFile(path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert manifest["format"] == audit_archive.FORMAT and set(manifest["tables"]) == set(audit_archive.TABLES)
