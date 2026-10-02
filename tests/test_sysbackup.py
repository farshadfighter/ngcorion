"""
NGCorion self-backup: the encrypted container, the passphrase and settings,
what a scheduled backup holds, retention, the schedule, re-encrypting
secrets, file paths, maintenance mode, the alerts, the restore guards - and
two real round trips: the restore test against this database, and a full
restore with the schema swap in a scratch database of its own.
"""
import asyncio
import importlib
import io
import json
import os
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core import credential_crypto as cc
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.database import engine as db_engine
from app.core.security import get_password_hash
from app.models import User, UserRole
from app.models.system_backup import BackupDestination, SystemBackup, SystemRestore
from app.models.system_config import SystemConfigSetting
from app.modules.alerts import events as alert_events
from app.modules.sysbackup import container, dbdump, files, maintenance, rekey, restore, service
from app.modules.sysbackup.service import BackupError

api = importlib.import_module("app.modules.sysbackup.router")

PASS = "correct horse battery staple"


@pytest.fixture
def db():
    connection = db_engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


@pytest.fixture
def backup_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "BACKUP_DIR", str(tmp_path / "backups"))
    return tmp_path / "backups"


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


def _admin(db, password="Adm1n-pass!"):
    u = User(username=f"bk_admin_{uuid.uuid4().hex[:8]}", email=f"bk{_n()}@example.com",
             hashed_password=get_password_hash(password), role=UserRole.ADMIN, is_active=True)
    db.add(u)
    db.flush()
    return u


def _clear_settings(db):
    db.query(SystemConfigSetting).filter(SystemConfigSetting.section == service.SECTION).delete()
    db.flush()


# ── container ─────────────────────────────────────────────────────────────

class TestContainer:
    def _archive(self, entries):
        buf = io.BytesIO()
        w = container.Writer(buf, PASS, {"app_version": "t"})
        for name, data in entries:
            w.add(name, data)
        sha = w.close()
        return buf.getvalue(), sha, w

    def _read_all(self, data, passphrase=PASS):
        r = container.Reader(io.BytesIO(data), passphrase)
        return {n: container.read_entry(b, 1 << 30) for n, b in r.entries()}, r

    def test_round_trip_across_chunks(self):
        big = os.urandom(3 * container.CHUNK + 123)
        data, sha, w = self._archive([("a.json", b'{"x": 1}'), ("big", big), ("empty", b"")])
        got, r = self._read_all(data)
        assert got == {"a.json": b'{"x": 1}', "big": big, "empty": b""}
        assert r.entry_hashes == w.entries
        import hashlib
        assert hashlib.sha256(data).hexdigest() == sha

    def test_header_is_readable_without_the_passphrase(self):
        data, _, _ = self._archive([("a", b"1")])
        header, _ = container.read_header(io.BytesIO(data))
        assert header["app_version"] == "t" and header["cipher"] == "AES-256-GCM"

    def test_wrong_passphrase(self):
        data, _, _ = self._archive([("a", b"1")])
        with pytest.raises(container.WrongPassphrase):
            container.Reader(io.BytesIO(data), "not the passphrase")

    @pytest.mark.parametrize("damage", ["truncate", "flip", "append", "drop_tail_chunk"])
    def test_damage_is_detected(self, damage):
        data, _, _ = self._archive([("a", os.urandom(2 * container.CHUNK)), ("b", b"tail")])
        if damage == "truncate":
            data = data[:len(data) // 2]
        elif damage == "flip":
            mutable = bytearray(data)
            mutable[len(mutable) // 2] ^= 0x01
            data = bytes(mutable)
        elif damage == "append":
            data = data + b"x"
        else:
            data = data[:-40]
        with pytest.raises(container.BackupFormatError):
            self._read_all(data)

    def test_not_a_backup(self):
        with pytest.raises(container.BackupFormatError):
            container.read_header(io.BytesIO(b"PK\x03\x04 zip file"))

    def test_unread_entries_are_skipped_but_checked(self):
        data, _, w = self._archive([("a", b"1" * 1000), ("b", b"2")])
        r = container.Reader(io.BytesIO(data), PASS)
        assert [n for n, _ in r.entries()] == ["a", "b"]
        assert r.entry_hashes == w.entries


# ── passphrase and settings ───────────────────────────────────────────────

class TestPassphrase:
    def test_set_check_and_change(self, db):
        _clear_settings(db)
        assert service.get_settings(db)["passphrase_set"] is False
        with pytest.raises(BackupError):
            service.set_passphrase(db, "short", None)
        service.set_passphrase(db, PASS, None, username="admin")
        cfg = service.get_settings(db)
        assert cfg["passphrase_set"] and cfg["passphrase_set_by"] == "admin"
        assert service.check_passphrase(db, PASS) and not service.check_passphrase(db, PASS + "x")
        first_key = cfg["key_id"]
        with pytest.raises(BackupError) as exc:
            service.set_passphrase(db, "another long passphrase", None, current="wrong one")
        assert exc.value.status == 403
        service.set_passphrase(db, "another long passphrase", None, current=PASS)
        # Older backups keep opening without typing the old passphrase.
        assert service.passphrase_for(db, first_key) == PASS
        assert service.current_passphrase(db)[0] == "another long passphrase"

    def test_stored_encrypted(self, db):
        _clear_settings(db)
        service.set_passphrase(db, PASS, None)
        raw = json.dumps(db.query(SystemConfigSetting).filter_by(section=service.SECTION).one().config_json)
        assert PASS not in raw and "enc:v1:" in raw

    def test_settings_validation(self, db):
        _clear_settings(db)
        good = dict(service.DEFAULT_SETTINGS)
        assert service.save_settings(db, good, None)["time"] == "02:00"
        for bad in ({"time": "25:00"}, {"include_cve": "monthly"}, {"keep_daily": 0}, {"frequency": "hourly"}):
            with pytest.raises(BackupError):
                service.save_settings(db, {**good, **bad}, None)

    def test_queue_needs_a_passphrase(self, db):
        _clear_settings(db)
        with pytest.raises(BackupError) as exc:
            service.queue_backup(db, "manual")
        assert exc.value.status == 409


# ── contents, schedule, retention ─────────────────────────────────────────

def _scheduled(db, when, status="ready", contents=("essential", "reports")):
    b = SystemBackup(kind="scheduled", status=status, contents=list(contents), destinations=[],
                     created_at=when, finished_at=when, filename=f"t-{uuid.uuid4().hex}.ngbak")
    db.add(b)
    db.flush()
    return b


class TestScheduleAndRetention:
    def test_weekly_parts_on_the_weekly_day_or_when_overdue(self, db, monkeypatch):
        _clear_settings(db)
        db.query(SystemBackup).delete()
        monkeypatch.setattr(service, "_local_tz", lambda db: None)
        friday = datetime(2026, 10, 2, 2, 0)            # a Friday
        assert friday.weekday() == 4
        assert "cve" in service.contents_for(db, "scheduled", now=friday)
        saturday = friday + timedelta(days=1)
        _scheduled(db, friday, contents=("essential", "reports", "cve"))
        assert service.contents_for(db, "scheduled", now=saturday) == ["essential", "reports"]
        assert "cve" in service.contents_for(db, "scheduled", now=friday + timedelta(days=8, hours=1))
        assert service.contents_for(db, "safety") == ["essential", "reports", "cve", "noc_history"]
        assert service.contents_for(db, "manual", ["cve"]) == ["essential", "cve"]

    def test_due_and_next(self, db, monkeypatch):
        _clear_settings(db)
        db.query(SystemBackup).delete()
        monkeypatch.setattr(service, "_local_tz", lambda db: None)
        service.set_passphrase(db, PASS, None)
        now = datetime(2026, 10, 2, 3, 0)
        assert service.due_scheduled(db, now)
        assert service.last_slot(db, datetime(2026, 10, 2, 1, 59), service.get_settings(db)) == \
            datetime(2026, 10, 1, 2, 0)                  # before 02:00 the slot is yesterday's
        _scheduled(db, datetime(2026, 10, 2, 2, 0, 5))
        assert not service.due_scheduled(db, now)
        assert service.next_scheduled(db, now) == datetime(2026, 10, 3, 2, 0)
        service.save_settings(db, {**service.DEFAULT_SETTINGS, "frequency": "weekly", "weekly_day": 0}, None)
        assert service.next_scheduled(db, now) == datetime(2026, 10, 5, 2, 0)      # Monday

    def test_grandfather_father_son(self, db, monkeypatch):
        _clear_settings(db)
        db.query(SystemBackup).delete()
        monkeypatch.setattr(service, "_local_tz", lambda db: None)
        service.save_settings(db, {**service.DEFAULT_SETTINGS, "keep_daily": 3, "keep_weekly": 2,
                                   "keep_monthly": 2}, None)
        start = datetime(2026, 7, 1, 2, 0)
        rows = [_scheduled(db, start + timedelta(days=i)) for i in range(70)]
        manual = SystemBackup(kind="manual", status="ready", contents=["essential"], destinations=[],
                              created_at=start - timedelta(days=400))
        db.add(manual)
        db.flush()
        doomed, keep = service.retention_plan(db)
        kept = {b.id for b in rows} - {b.id for b in doomed}
        newest = rows[-1]
        assert "daily" in keep[newest.id]
        assert len([k for k, v in keep.items() if "daily" in v]) == 3
        assert len([k for k, v in keep.items() if "weekly" in v]) == 2
        assert len([k for k, v in keep.items() if "monthly" in v]) == 2
        assert len(kept) <= 7 and manual.id not in {b.id for b in doomed}
        # the monthly keeper is the first backup of its month
        first_sept = next(b for b in rows if b.created_at.month == 9)
        assert "monthly" in keep[first_sept.id]


# ── re-encrypting secrets ─────────────────────────────────────────────────

class TestRekey:
    def test_secrets_follow_the_new_key(self):
        old_key = "an-old-server-secret-key-0123456789abcdef"
        schema = f"ngtest_rekey_{uuid.uuid4().hex[:6]}"
        nvd = cc.encrypt("NVD-KEY", cc.PURPOSE_CVE, secret_key=old_key)
        smtp = "enc:v1:" + cc.encrypt("smtp-pass", cc.PURPOSE_SYSTEM_CONFIG, secret_key=old_key)
        mine = "enc:v1:" + cc.encrypt("already-current", cc.PURPOSE_SYSTEM_CONFIG)
        with dbdump.connect(autocommit=True) as conn:
            cur = conn.cursor()
            cur.execute(f'CREATE SCHEMA "{schema}"')
            try:
                cur.execute(f'CREATE TABLE "{schema}".cve_settings (key varchar primary key, value text)')
                cur.execute(f'CREATE TABLE "{schema}".system_config_settings (id int primary key, config_json json)')
                cur.execute(f'INSERT INTO "{schema}".cve_settings VALUES (%s, %s), (%s, %s)',
                            ("nvd_api_key", nvd, "schedule", '"daily"'))
                cur.execute(f'INSERT INTO "{schema}".system_config_settings VALUES (1, %s), (2, %s)',
                            (json.dumps({"password": smtp, "host": "mail"}), json.dumps({"api_key": mine})))
                totals = rekey.rekey(cur, schema, old_key)
                assert totals == {"rekeyed": 2, "current": 1, "unreadable": 0}
                cur.execute(f'SELECT value FROM "{schema}".cve_settings WHERE key = %s', ("nvd_api_key",))
                assert cc.decrypt(cur.fetchone()[0], cc.PURPOSE_CVE) == "NVD-KEY"
                cur.execute(f'SELECT config_json FROM "{schema}".system_config_settings WHERE id = 1')
                row = cur.fetchone()[0]
                assert cc.decrypt(row["password"][7:], cc.PURPOSE_SYSTEM_CONFIG) == "smtp-pass"
                assert row["host"] == "mail"
            finally:
                cur.execute(f'DROP SCHEMA "{schema}" CASCADE')


# ── files, maintenance ────────────────────────────────────────────────────

class TestFiles:
    def test_paths_stay_inside_their_area(self, tmp_path, monkeypatch):
        monkeypatch.setattr(files, "_areas", lambda: {"certs": tmp_path / "certs",
                                                       "known_hosts": tmp_path / "known_hosts"})
        assert files.target("files/certs/server.crt") == tmp_path / "certs" / "server.crt"
        assert files.target("files/known_hosts") == tmp_path / "known_hosts"
        for bad in ("files/certs/../../etc/passwd", "files/other/x", "db/users.copy"):
            with pytest.raises(ValueError):
                files.target(bad)
        path = files.write("files/certs/server.key", b"KEY", 0o600)
        assert path.read_bytes() == b"KEY" and (path.stat().st_mode & 0o777) == 0o600


class TestMaintenance:
    def _call(self, path):
        from starlette.requests import Request
        from starlette.responses import PlainTextResponse

        async def call_next(request):
            return PlainTextResponse("ok")
        mw = maintenance.MaintenanceMiddleware(app=None)
        request = Request({"type": "http", "method": "GET", "path": path, "headers": [], "query_string": b""})
        response = asyncio.run(mw.dispatch(request, call_next))
        body = json.loads(response.body) if response.media_type == "application/json" else None
        return response.status_code, body

    def test_api_answers_503_while_restoring(self, backup_dir):
        assert self._call("/api/x")[0] == 200
        maintenance.on(reason="restore", restore_id=7, step="load", progress=40)
        try:
            code, body = self._call("/api/x")
            assert code == 503 and body["maintenance"]["step"] == "load"
            assert self._call("/index.html")[0] == 200              # the page itself still loads
            code, body = self._call(maintenance.STATUS_PATH)
            assert code == 200 and body["maintenance"]["restore_id"] == 7
        finally:
            maintenance.off()
        assert self._call("/api/x")[0] == 200

    def test_flag_of_a_dead_runner_is_dropped(self, backup_dir):
        maintenance.update(runner="another-server:1:1|1", beat=0)
        path = maintenance.flag_path()
        data = json.loads(path.read_text())
        data["beat"] = 0
        path.write_text(json.dumps(data))
        assert maintenance.state() is None and not path.exists()

    def test_background_tasks_pause(self, backup_dir):
        from app.core import singleton
        events = []

        async def scenario():
            async def stop():
                events.append("stop")
            task = singleton.SingletonTask(f"test-pause-{uuid.uuid4().hex[:6]}", lambda: events.append("start"),
                                           stop, retry_seconds=0.05)
            task.start()
            await asyncio.sleep(0.3)
            maintenance.on(reason="restore")
            await asyncio.sleep(0.3)
            maintenance.off()
            await asyncio.sleep(0.3)
            await task.stop()

        asyncio.run(scenario())
        assert events[:3] == ["start", "stop", "start"]


# ── alerts ────────────────────────────────────────────────────────────────

class TestAlerts:
    def test_failed_and_missing_backups(self, db):
        _clear_settings(db)
        db.query(SystemBackup).delete()
        now = datetime.utcnow()
        ev = alert_events.EVENTS
        assert [p.title for p in ev["system.backup_missing"].evaluate(db, {}, now, now)] == \
            ["NGCorion backups are not set up"]
        service.set_passphrase(db, PASS, None)
        assert ev["system.backup_missing"].evaluate(db, {"hours": 48}, now, now)[0].key == "backup:stale"
        _scheduled(db, now - timedelta(hours=1))
        assert ev["system.backup_missing"].evaluate(db, {"hours": 48}, now, now) == []
        assert ev["system.backup_failed"].evaluate(db, {}, now, now) == []
        _scheduled(db, now, status="failed")
        assert len(ev["system.backup_failed"].evaluate(db, {}, now, now)) == 1

    def test_destination_and_restore_test(self, db):
        db.add(BackupDestination(name="nas", type="smb", host="fs01", share="b", enabled=True,
                                 last_status="failed", last_error="NT_STATUS_ACCESS_DENIED"))
        db.add(SystemRestore(kind="test", status="failed", steps=[], backup_label="x", error="row counts differ"))
        db.flush()
        now = datetime.utcnow()
        assert any("nas" in p.detail for p in
                   alert_events.EVENTS["system.backup_destination"].evaluate(db, {}, now, now))
        assert alert_events.EVENTS["system.restore_test_failed"].evaluate(db, {}, now, now)


# ── API guards ────────────────────────────────────────────────────────────

class TestApiGuards:
    def test_restore_needs_typed_confirmation_and_password(self, db):
        from fastapi import HTTPException
        user = _admin(db)
        with pytest.raises(HTTPException) as exc:
            api.create_restore(api.RestoreIn(backup_id=1, confirm="yes", password="Adm1n-pass!"), db, user)
        assert exc.value.status_code == 400
        with pytest.raises(HTTPException) as exc:
            api.create_restore(api.RestoreIn(backup_id=1, confirm="RESTORE", password="wrong"), db, user)
        assert exc.value.status_code == 403

    def test_routes_are_admin_only(self):
        from app.core.dependencies import require_admin
        for route in api.router.routes:
            deps = [d.call for d in route.dependant.dependencies]
            assert require_admin in deps, route.path

    def test_destination_secret_is_never_returned(self, db):
        user = _admin(db)
        out = api.create_destination(api.DestinationIn(name="sftp", type="sftp", host="10.0.0.5",
                                                       username="bk", secret="s3cret"), db, user)
        assert out["has_secret"] and "s3cret" not in json.dumps(out)
        row = db.get(BackupDestination, out["id"])
        assert "s3cret" not in row.secret_encrypted
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            api.create_destination(api.DestinationIn(name="bad", type="sftp", host="user@host"), db, user)


# ── real round trips ──────────────────────────────────────────────────────

def _cleanup_catalog(ids):
    s = SessionLocal()
    try:
        s.query(SystemRestore).filter(SystemRestore.backup_id.in_(ids)).delete(synchronize_session=False)
        s.query(SystemBackup).filter(SystemBackup.id.in_(ids)).delete(synchronize_session=False)
        s.commit()
    finally:
        s.close()


class TestRoundTrip:
    def test_backup_verify_and_restore_test_on_this_database(self, backup_dir):
        """Export this database, check the file, load it into a scratch
        schema with the migrations and drop it - the weekly restore test."""
        s = SessionLocal()
        try:
            b = SystemBackup(kind="manual", status="running", contents=["essential"], destinations=[],
                             note="pytest")
            s.add(b)
            s.commit()
            bid = b.id
        finally:
            s.close()
        try:
            fields = service.write_backup(bid, PASS, None, ["essential"], "manual")
            path = backup_dir / fields["filename"]
            assert path.is_file() and fields["db_revision"] == dbdump.head_revision()
            result = service.verify_file(path, PASS)
            assert "users" in result["manifest"]["tables"]
            assert "system_backups" not in result["manifest"]["tables"]       # the catalog stays local
            service.update_row(SystemBackup, bid, status="ready", **fields)
            r = restore.run_test(bid, PASS)
            assert r.status == "succeeded", r.error
            assert r.result["tables"] == fields["summary"]["tables"]
            assert dbdump.TEST_STAGING not in dbdump.leftover_schemas()
            bad = restore.run_test(bid, "not the passphrase")
            assert bad.status == "failed" and "passphrase" in bad.error
        finally:
            _cleanup_catalog([bid])


def _scratch_db():
    """A database of its own for the swap, or None when not allowed."""
    url = make_url(settings.DATABASE_URL)
    name = f"ngbk_pytest_{uuid.uuid4().hex[:6]}"
    admin = url.set(drivername="postgresql", database="postgres").render_as_string(hide_password=False)
    try:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{name}"')
    except psycopg.Error:
        return None, None
    return name, admin


@pytest.fixture
def scratch_db(monkeypatch, backup_dir):
    name, admin = _scratch_db()
    if name is None:
        pytest.skip("this database user may not create databases")
    url = make_url(settings.DATABASE_URL).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setattr(settings, "DATABASE_URL", url)
    dbdump.migrate("public", "head")
    try:
        yield name
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s", (name,))
            conn.execute(f'DROP DATABASE IF EXISTS "{name}"')


class _NoProgress:
    def start(self, *a):
        pass

    def tick(self, *a):
        pass

    def detail(self, *a):
        pass


class TestFullRestore:
    def test_restore_swaps_schemas_and_keeps_the_catalog(self, scratch_db):
        with dbdump.connect(autocommit=True) as conn:
            conn.execute("INSERT INTO users (username, email, hashed_password, role, is_active, created_at) "
                         "VALUES ('before', 'before@example.com', 'x', 'ADMIN', true, now())")
        fields = service.write_backup(0, PASS, None, ["essential"], "manual")
        manifest = service.open_manifest(service.backup_dir() / fields["filename"], PASS)
        with dbdump.connect(autocommit=True) as conn:
            conn.execute("UPDATE users SET email = 'changed@example.com' WHERE username = 'before'")
            conn.execute("INSERT INTO users (username, email, hashed_password, role, is_active, created_at) "
                         "VALUES ('after', 'after@example.com', 'x', 'ADMIN', true, now())")
            conn.execute("INSERT INTO system_backups (kind, status, progress, contents, destinations, created_at) "
                         "VALUES ('manual', 'ready', 100, '[]', '[]', now())")
        loaded = restore._stage(dbdump.STAGING, manifest["db_revision"], manifest,
                                service.backup_dir() / fields["filename"], PASS, _NoProgress(),
                                {"staging": 1, "load": 2, "check": 50, "upgrade": 60})
        assert loaded["old_key"] == settings.SECRET_KEY
        restore._carry({"essential"}, manifest["sequences"])
        old = dbdump.swap(dbdump.STAGING)
        dbdump.drop_schema(old)
        with dbdump.connect() as conn:
            users = dict(conn.execute("SELECT username, email FROM users").fetchall())
            assert users.get("before") == "before@example.com" and "after" not in users
            assert conn.execute("SELECT count(*) FROM system_backups").fetchone()[0] == 1   # kept from the server
            # new rows continue after the restored keys
            conn.execute("INSERT INTO users (username, email, hashed_password, role, is_active, created_at) "
                         "VALUES ('next', 'next@example.com', 'x', 'ADMIN', true, now())")
            conn.commit()
        assert dbdump.leftover_schemas() == []
