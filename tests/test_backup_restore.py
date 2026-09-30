"""Backup restore: diff engines, file bundles, risk analysis, the job's safety
sequence (against a scripted fake device) and the API's guard rails.

Device I/O is faked; everything else - diff, planning, the job state machine,
the database rows and the audit trail - is real (Postgres, rolled back)."""
import importlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi import HTTPException
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, DeviceBackup, User, UserRole
from app.models.asset_types import AssetType
from app.models.backup_restore import BackupRestore
from app.modules.backup.restore import config_tree, file_bundle, risk, service
from app.modules.backup.restore.drivers import Credentials, RestoreApplyError, RestorePlan

backup_router = importlib.import_module("app.modules.backup.router")

# --------------------------------------------------------------------------- #
#  Sample configurations                                                      #
# --------------------------------------------------------------------------- #

CISCO_BACKUP = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:00:00 UTC Mon Sep 1 2026
!
hostname Core-SW-01
!
username admin privilege 15 secret 9 $9$OLDHASH
!
interface GigabitEthernet0/1
 description Uplink
 ip address 10.0.1.2 255.255.255.0
!
line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
logging host 10.0.0.9
banner motd ^CAuthorized use only^C
end
"""

FORTI_BACKUP = """#config-version=FGT60F-7.2.5
config system global
    set hostname "FGT-Edge-01"
    set admintimeout 15
    set cfg-save automatic
end
config system admin
    edit "admin"
        set trusthost1 10.0.0.0 255.255.255.0
        set password ENC SH2aaa
    next
end
config firewall policy
    edit 1
        set name "A"
    next
    edit 2
        set name "B"
    next
end"""

FORTI_LIVE = """FGT-Edge-01 # show full-configuration
#config-version=FGT60F-7.2.5
config system global
    set hostname "FGT-Edge-01"
    set admintimeout 480
    set cfg-save revert
end
config system admin
    edit "admin"
        set password ENC SH2bbb
    next
end
config firewall policy
    edit 2
        set name "B"
    next
    edit 27
        set name "Temp-Any-Allow"
        set action accept
    next
    edit 1
        set name "A"
    next
end
FGT-Edge-01 # """


def bundle(files):
    out = "##### LINUX Configuration Backup #####\n# Backup taken at: x\n#\n"
    for path, content in files.items():
        out += f"##### BEGIN FILE: {path} #####\n{content}\n\n##### END FILE: {path} #####\n\n"
    return out


# --------------------------------------------------------------------------- #
#  Cisco diff                                                                 #
# --------------------------------------------------------------------------- #

class TestCiscoDiff:
    def test_unchanged_device_diffs_empty(self):
        assert config_tree.diff_cisco(CISCO_BACKUP, CISCO_BACKUP).is_empty

    def test_capture_noise_is_ignored(self):
        live = CISCO_BACKUP.replace("1234 bytes", "1299 bytes").replace("10:00:00", "11:11:11")
        live = "Core-SW-01#show running-config\n" + live + "\nntp clock-period 36028797\nCore-SW-01#"
        assert config_tree.diff_cisco(CISCO_BACKUP, live).is_empty

    def test_changed_admin_password_never_deletes_the_account(self):
        live = CISCO_BACKUP.replace("$9$OLDHASH", "$9$NEWHASH")
        cmds = config_tree.diff_cisco(CISCO_BACKUP, live).commands
        assert "username admin privilege 15 secret 9 $9$OLDHASH" in cmds
        assert not any(c.strip().startswith("no username") for c in cmds)

    def test_single_value_settings_are_replaced_in_place(self):
        live = (CISCO_BACKUP.replace(" description Uplink", " description TEMP")
                .replace("ip address 10.0.1.2", "ip address 10.0.1.9")
                .replace("exec-timeout 10 0", "exec-timeout 60 0"))
        cmds = config_tree.diff_cisco(CISCO_BACKUP, live).commands
        assert not any(c.strip().startswith(("no description", "no ip address", "no exec-timeout")) for c in cmds)
        assert "ip address 10.0.1.2 255.255.255.0" in cmds

    def test_list_entries_added_after_the_backup_are_removed(self):
        live = CISCO_BACKUP.replace("logging host 10.0.0.9", "logging host 10.0.0.9\nlogging host 6.6.6.6\nip http server")
        cmds = config_tree.diff_cisco(CISCO_BACKUP, live).commands
        assert "no logging host 6.6.6.6" in cmds
        assert "no ip http server" in cmds

    def test_new_interface_block_exits_its_submode(self):
        live = CISCO_BACKUP.replace("interface GigabitEthernet0/1\n description Uplink\n ip address 10.0.1.2 255.255.255.0\n", "")
        cmds = config_tree.diff_cisco(CISCO_BACKUP, live).commands
        i = cmds.index("interface GigabitEthernet0/1")
        assert cmds[i + 1:i + 4] == [" description Uplink", " ip address 10.0.1.2 255.255.255.0", "exit"]

    def test_interface_created_after_the_backup_is_removed(self):
        live = CISCO_BACKUP + "\ninterface Loopback5\n ip address 5.5.5.5 255.255.255.255\n"
        assert "no interface Loopback5" in config_tree.diff_cisco(CISCO_BACKUP, live).commands

    def test_banner_restored_with_a_safe_delimiter(self):
        live = CISCO_BACKUP.replace("Authorized use only", "Hello ^ there")
        cmds = config_tree.diff_cisco(CISCO_BACKUP, live).commands
        i = cmds.index("banner motd ^")
        assert cmds[i:i + 3] == ["banner motd ^", "Authorized use only", "^"]


# --------------------------------------------------------------------------- #
#  FortiOS diff                                                               #
# --------------------------------------------------------------------------- #

class TestFortiDiff:
    def test_unchanged_and_noise(self):
        assert config_tree.diff_fortios(FORTI_BACKUP, FORTI_BACKUP).is_empty
        assert config_tree.diff_fortios(FORTI_BACKUP, "FGT # show full-configuration\n" + FORTI_BACKUP + "\nFGT # ").is_empty

    def test_restore_commands(self):
        d = config_tree.diff_fortios(FORTI_BACKUP, FORTI_LIVE)
        assert d.commands == [
            "config system global", "set admintimeout 15", "end",
            "config system admin", 'edit "admin"', "set trusthost1 10.0.0.0 255.255.255.0", "next", "end",
            "config firewall policy", "delete 27", "move 1 before 2", "end",
        ]

    def test_encrypted_values_are_reported_not_diffed(self):
        d = config_tree.diff_fortios(FORTI_BACKUP, FORTI_LIVE)
        assert not any("ENC" in c for c in d.commands)
        assert any("encrypted value" in s for s in d.skipped)

    def test_revert_mode_toggle_is_not_a_difference(self):
        live = FORTI_BACKUP.replace("set cfg-save automatic", "set cfg-save revert\n    set cfg-revert-timeout 600")
        assert config_tree.diff_fortios(FORTI_BACKUP, live).is_empty

    def test_vdom_wrapped_config(self):
        backup = "config global\nconfig system global\n    set admintimeout 15\nend\nend\nconfig vdom\nedit root\nconfig firewall address\n    edit \"srv\"\n        set subnet 10.0.0.5 255.255.255.255\n    next\nend\nnext\nend"
        live = backup.replace("admintimeout 15", "admintimeout 99").replace('    edit "srv"\n        set subnet 10.0.0.5 255.255.255.255\n    next\n', "")
        cmds = config_tree.diff_fortios(backup, live).commands
        assert cmds[:5] == ["config global", "config system global", "set admintimeout 15", "end", "end"]
        assert cmds[5:] == ["config vdom", "edit root", "config firewall address", 'edit "srv"',
                            "set subnet 10.0.0.5 255.255.255.255", "next", "end", "next", "end"]

    def test_setting_absent_in_backup_is_unset(self):
        live = FORTI_BACKUP.replace('set hostname "FGT-Edge-01"', 'set hostname "FGT-Edge-01"\n    set timezone 41')
        assert "unset timezone" in config_tree.diff_fortios(FORTI_BACKUP, live).commands


# --------------------------------------------------------------------------- #
#  File bundles                                                               #
# --------------------------------------------------------------------------- #

class TestFileBundle:
    def test_parse_is_byte_exact(self):
        files = {"/etc/ssh/sshd_config": "Port 22\nPermitRootLogin no\n", "/etc/issue": "no trailing newline"}
        assert file_bundle.parse_bundle(bundle(files)) == files

    def test_plan_writes_recreates_and_removes(self):
        backup = bundle({"/etc/ssh/sshd_config": "Port 22\n", "/etc/issue": "Authorized\n"})
        live = bundle({"/etc/ssh/sshd_config": "Port 2222\n", "/etc/sysctl.d/99-new.conf": "x=1\n"})
        plan = file_bundle.plan_bundle(backup, live, "linux")
        assert plan.write == {"/etc/ssh/sshd_config": "Port 22\n", "/etc/issue": "Authorized\n"}
        assert plan.remove == ["/etc/sysctl.d/99-new.conf"]

    @pytest.mark.parametrize("path", ["/root/.ssh/authorized_keys", "/etc/ssh/../shadow", "etc/issue", "/etc/sudoers"])
    def test_paths_outside_the_family_allowlist_are_never_written(self, path):
        plan = file_bundle.plan_bundle(bundle({path: "evil\n"}), bundle({}), "linux")
        assert path not in plan.write and path in plan.rejected

    def test_file_paths_and_contents_are_shell_quoted(self):
        cmd = file_bundle.write_command("/etc/issue", "a'; rm -rf / #\n")
        assert "rm -rf" not in cmd  # content travels base64-encoded

    def test_validation_and_reload_follow_touched_files(self):
        plan = file_bundle.plan_bundle(bundle({"/etc/ssh/sshd_config": "Port 22\n"}),
                                       bundle({"/etc/ssh/sshd_config": "Port 23\n"}), "linux")
        assert file_bundle.validate_commands(plan, "linux") == ["sshd -t"]
        assert file_bundle.reload_commands(plan, "linux")
        other = file_bundle.plan_bundle(bundle({"/etc/issue": "a\n"}), bundle({"/etc/issue": "b\n"}), "linux")
        assert file_bundle.validate_commands(other, "linux") == []


# --------------------------------------------------------------------------- #
#  Management-access risk                                                     #
# --------------------------------------------------------------------------- #

class TestRisk:
    def test_fortigate_trusthost_lockout(self):
        d = config_tree.diff_fortios(FORTI_BACKUP, FORTI_LIVE)
        risks = risk.fortios_risks(d, FORTI_BACKUP, "admin", "10.0.9.5", 22)
        assert any(r["severity"] == "lockout" and "10.0.9.5" in r["message"] for r in risks)
        inside = risk.fortios_risks(d, FORTI_BACKUP, "admin", "10.0.0.7", 22)
        assert not any(r["severity"] == "lockout" for r in inside)

    def test_fortigate_missing_account_lockout(self):
        d = config_tree.diff_fortios(FORTI_BACKUP, FORTI_LIVE)
        risks = risk.fortios_risks(d, FORTI_BACKUP, "netops", "10.0.0.7", 22)
        assert any('"netops"' in r["message"] for r in risks)

    def test_linux_allowusers_and_port(self):
        after = {"/etc/ssh/sshd_config": "Port 2222\nAllowUsers alice bob\n"}
        plan = file_bundle.plan_bundle(bundle(after), bundle({"/etc/ssh/sshd_config": "Port 22\n"}), "linux")
        messages = " ".join(r["message"] for r in risk.bundle_risks(plan.diff, after, "linux", "ngc", 22))
        assert "port 2222" in messages and "AllowUsers" in messages


# --------------------------------------------------------------------------- #
#  The restore job (fake device, real database)                               #
# --------------------------------------------------------------------------- #

class FakeDriver:
    """Scripted device. ``lives`` are returned by successive read_live calls."""

    def __init__(self, lives, *, auto_revert=True, apply_error=None, fail_opens_after_apply=0,
                 source_ip="10.0.0.7"):
        self.lives = list(lives)
        self.initial = lives[0]
        self.auto_revert = auto_revert
        self.apply_error = apply_error
        self.fail_opens_after_apply = fail_opens_after_apply
        self.ip = source_ip
        self.applied = False
        self.calls = []

    def open(self):
        if self.applied and self.fail_opens_after_apply > 0:
            self.fail_opens_after_apply -= 1
            raise ConnectionError("unreachable")
        self.calls.append("open")

    def close(self):
        self.calls.append("close")

    def read_live(self):
        return self.lives.pop(0) if len(self.lives) > 1 else self.lives[0]

    def snapshot(self):
        return "# snapshot\n" + self.initial

    def source_ip(self):
        return self.ip

    def auto_revert_available(self):
        return (True, "cfg-save revert") if self.auto_revert else (False, "no archive")

    def plan(self, backup_text, live_text):
        d = config_tree.diff_fortios(backup_text, live_text)
        return RestorePlan(diff=d, commands=d.commands,
                           risks=risk.fortios_risks(d, backup_text, "admin", self.ip, 22))

    def apply(self, plan, minutes):
        self.calls.append(("apply", minutes))
        if self.apply_error:
            raise RestoreApplyError(self.apply_error)
        self.applied = True

    def confirm(self):
        self.calls.append("confirm")

    def revert_now(self):
        self.calls.append("revert_now")


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, transaction):
        if transaction.nested and not transaction._parent.nested:
            sess.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", _restart_savepoint)
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def setup(db):
    user = User(username=f"restore_user_{_n()}", hashed_password="x", role=UserRole.ADMIN)
    db.add(user)
    db.flush()
    atype = AssetType(type_name=f"Firewall_{_n()}", category="network")
    db.add(atype)
    db.flush()
    asset = Asset(asset_name="FGT-Edge-01", ip_address="10.0.0.1", asset_type_id=atype.id, user_id=user.id)
    db.add(asset)
    db.flush()
    backup = DeviceBackup(asset_id=asset.id, asset_name=asset.asset_name, device_ip="10.0.0.1",
                          device_type="fortinet", config_content=FORTI_BACKUP, source="manual", created_by=user.id)
    db.add(backup)
    db.flush()
    return user, asset, backup


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _run(db, setup, driver, monkeypatch, *, live=FORTI_LIVE, acknowledged=True, allow_no_revert=False):
    user, asset, backup = setup
    job = BackupRestore(backup_id=backup.id, asset_id=asset.id, asset_name=asset.asset_name,
                        device_ip="10.0.0.1", device_type="fortinet", status="queued",
                        reason="test restore", revert_minutes=10, events=[], requested_by=user.id)
    db.add(job)
    db.flush()
    clock = FakeClock()
    monkeypatch.setattr(service.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(db, "close", lambda: None)
    service.run_restore(job.id, Credentials(host="10.0.0.1", username="admin", password="x"),
                        service.fingerprint("fortinet", live), acknowledged, allow_no_revert,
                        driver_factory=lambda *a: driver, sleep=clock.sleep, session_factory=lambda: db)
    db.refresh(job)
    return job


class TestRestoreJob:
    def test_success_keeps_an_undo_point_and_confirms_only_after_verifying(self, db, setup, monkeypatch):
        driver = FakeDriver([FORTI_LIVE, FORTI_BACKUP])
        job = _run(db, setup, driver, monkeypatch)
        assert job.status == "succeeded", job.error
        pre = db.get(DeviceBackup, job.pre_restore_backup_id)
        assert pre.source == "pre_restore" and "Temp-Any-Allow" in pre.config_content
        assert driver.calls.index(("apply", 10)) < driver.calls.index("confirm")
        assert job.auto_revert == "armed"
        assert [e["step"] for e in job.events] == ["connect", "backup", "apply", "verify", "verify", "save"]

    def test_device_changed_since_review_writes_nothing(self, db, setup, monkeypatch):
        driver = FakeDriver([FORTI_LIVE.replace("480", "481")])
        job = _run(db, setup, driver, monkeypatch)
        assert job.status == "failed" and "changed after you reviewed" in job.error
        assert not any(isinstance(c, tuple) for c in driver.calls)
        assert job.pre_restore_backup_id is None

    def test_unacknowledged_lockout_writes_nothing(self, db, setup, monkeypatch):
        driver = FakeDriver([FORTI_LIVE], source_ip="10.0.9.5")
        job = _run(db, setup, driver, monkeypatch, acknowledged=False)
        assert job.status == "failed" and "lock NGCorion out" in job.error
        assert not any(isinstance(c, tuple) for c in driver.calls)

    def test_no_auto_revert_requires_explicit_consent(self, db, setup, monkeypatch):
        job = _run(db, setup, FakeDriver([FORTI_LIVE], auto_revert=False), monkeypatch)
        assert job.status == "failed" and "Auto-revert is not available" in job.error
        driver = FakeDriver([FORTI_LIVE, FORTI_BACKUP], auto_revert=False)
        job = _run(db, setup, driver, monkeypatch, allow_no_revert=True)
        assert job.status == "succeeded" and ("apply", None) in driver.calls

    def test_rejected_command_reverts_immediately(self, db, setup, monkeypatch):
        driver = FakeDriver([FORTI_LIVE], apply_error="command parse error")
        job = _run(db, setup, driver, monkeypatch)
        assert job.status == "reverted" and "revert_now" in driver.calls and "confirm" not in driver.calls

    def test_device_error_messages_are_stored_redacted(self, db, setup, monkeypatch):
        driver = FakeDriver([FORTI_LIVE], apply_error="The device rejected 'set passwd S3cretPass!': bad")
        job = _run(db, setup, driver, monkeypatch)
        stored = job.error + " ".join(e["message"] for e in job.events)
        assert "S3cretPass!" not in stored and "<REDACTED>" in stored

    def test_verification_mismatch_reverts(self, db, setup, monkeypatch):
        driver = FakeDriver([FORTI_LIVE, FORTI_LIVE])
        job = _run(db, setup, driver, monkeypatch)
        assert job.status == "reverted" and "revert_now" in driver.calls and "confirm" not in driver.calls

    def test_lost_access_waits_for_the_device_to_revert_itself(self, db, setup, monkeypatch):
        driver = FakeDriver([FORTI_LIVE, FORTI_LIVE], fail_opens_after_apply=service.RECONNECT_ATTEMPTS + 2)
        job = _run(db, setup, driver, monkeypatch)
        assert job.status == "reverted", job.error
        assert "confirm" not in driver.calls and "revert_now" not in driver.calls
        assert "reverted automatically" in job.error

    def test_nothing_to_do(self, db, setup, monkeypatch):
        driver = FakeDriver([FORTI_BACKUP])
        job = _run(db, setup, driver, monkeypatch, live=FORTI_BACKUP)
        assert job.status == "succeeded" and job.pre_restore_backup_id is None


# --------------------------------------------------------------------------- #
#  API guard rails                                                            #
# --------------------------------------------------------------------------- #

def _request(**over):
    base = dict(ssh_username="admin", ssh_password="x", reason="restore test", confirm_name="FGT-Edge-01",
                live_fingerprint="0" * 64)
    base.update(over)
    return backup_router.RestoreRequest(**base)


class TestApi:
    def test_only_admin_or_manager(self, db, setup):
        user, _, backup = setup
        user.role = UserRole.USER
        with pytest.raises(HTTPException) as exc:
            backup_router.start_restore(backup.id, _request(), current_user=user, db=db)
        assert exc.value.status_code == 403

    def test_typed_name_must_match(self, db, setup):
        user, _, backup = setup
        with pytest.raises(HTTPException) as exc:
            backup_router.start_restore(backup.id, _request(confirm_name="FGT-Edge-02"), current_user=user, db=db)
        assert exc.value.status_code == 400

    def test_one_restore_per_asset_at_a_time(self, db, setup, monkeypatch):
        user, asset, backup = setup
        started = []
        monkeypatch.setattr(backup_router.restore_service, "start_restore", lambda *a: started.append(a))
        job = backup_router.start_restore(backup.id, _request(), current_user=user, db=db)
        assert job.status == "queued" and len(started) == 1
        with pytest.raises(HTTPException) as exc:
            backup_router.start_restore(backup.id, _request(), current_user=user, db=db)
        assert exc.value.status_code == 409

    def test_credentials_are_never_stored(self, db, setup, monkeypatch):
        user, asset, backup = setup
        monkeypatch.setattr(backup_router.restore_service, "start_restore", lambda *a: None)
        job = backup_router.start_restore(backup.id, _request(ssh_password="S3cr3t-pw"), current_user=user, db=db)
        row = db.get(BackupRestore, job.id)
        assert "S3cr3t-pw" not in repr({c.name: getattr(row, c.name) for c in row.__table__.columns})

    def test_interrupted_jobs_are_closed_at_startup(self, db, setup):
        user, asset, backup = setup
        job = BackupRestore(backup_id=backup.id, asset_id=asset.id, device_type="fortinet", status="applying",
                            reason="x", events=[], requested_by=user.id)
        db.add(job)
        db.flush()
        assert service.fail_interrupted_restores(db) >= 1
        db.refresh(job)
        assert job.status == "failed" and "restart" in job.error
