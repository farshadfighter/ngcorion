"""
VMware ESXi module (CIS VMware ESXi 7/8), reached over SSH.

No ESXi host is available to the test suite, so two stand-ins are used:

- tests/esxi_sample.py: an ESXi 8.0 U2 host's collector output written by
  hand in esxcli's text formats (tests/mock_data/esxi/ holds the dump);
- tests/fake_esxi.py: an emulator of esxcli, vim-cmd, chkconfig, vmware and
  the init.d scripts, so the module's real shell scripts - awk/sed
  pipelines, loops, read-back verification - run under busybox sh (as on
  ESXi; plain sh when busybox is missing) and change emulated state.

Both must agree: collection through the emulator yields the same verdicts
and evidence as the sample.
"""
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.models import Asset, AuditResult, User
from app.models.asset_types import AssetType
from app.models.audit import CheckStatus, DeviceType
from app.modules.benchmark import connectors
from app.modules.benchmark.connectors import ESXiConnector, SSHConnection
from app.modules.benchmark.audit_service import BenchmarkAuditService
from app.modules.benchmark.hardening_service import BenchmarkHardeningService, run_template
from app.modules.benchmark.rules import evaluate, section
from app.modules.benchmark.templates import PLACEHOLDER_RE
from app.modules.esxi import rules as R
from app.modules.esxi.collect import COMMANDS, collect, esxi_commands
from app.modules.esxi.hardening import TEMPLATES
from app.modules.esxi.spec import SPEC, collect_software, redact

sys.path.insert(0, str(Path(__file__).parent))
import fake_esxi  # noqa: E402
from benchmark_fakes import FakeHost, install  # noqa: E402
from esxi_sample import SECTIONS, advanced, dump  # noqa: E402

DUMP = (Path(__file__).parent / "mock_data" / "esxi" / "esxi8_0_u2_esx01_dump.txt").read_text()
PARAMS = {"CONFIRM": "yes", "NTP_SERVERS": "ntp1.corp.example.com,10.10.0.5",
          "SYSLOG_HOST": "ssl://syslog.corp.example.com:1514", "BANNER_TEXT": "Authorized use only. Activity is monitored."}


def run(d=DUMP):
    report = evaluate(d, R.rules_for(d), frozenset())
    return report, {f["id"]: f["status"] for f in report["findings"]}


def evidence(d, rid):
    return next(f["evidence"] for f in run(d)[0]["findings"] if f["id"] == rid)


class TestRules:
    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 75
        assert sum(r.manual for r in rules) == 12
        assert [r.section for r in rules][:3] == ["1.1", "1.2", "1.3"] and rules[-1].section == "8.15"

    def test_sample_dump_is_current(self):
        assert DUMP == dump()

    def test_sample(self):
        report, _ = run()
        assert report["summary"]["error_checks"] == 0
        assert (report["summary"]["passed_scored"], report["summary"]["failed_scored"]) == (28, 35)
        assert R.describe(DUMP) == "VMware ESXi 8.0.2 build-22380479, 3 VMs, 2 standard vSwitches, 4 port groups"

    @pytest.mark.parametrize("rid, expected", [
        ("ESXI-1.2", "pass"), ("ESXI-1.4", "fail"), ("ESXI-1.6", "fail"), ("ESXI-2.1", "fail"), ("ESXI-2.2", "pass"),
        ("ESXI-2.3", "fail"), ("ESXI-2.4", "pass"), ("ESXI-2.5", "pass"), ("ESXI-2.9", "pass"), ("ESXI-2.10", "fail"),
        ("ESXI-2.11", "pass"), ("ESXI-3.2", "pass"), ("ESXI-3.3", "fail"), ("ESXI-3.4", "fail"), ("ESXI-4.2", "fail"),
        ("ESXI-4.3", "pass"), ("ESXI-4.6", "fail"), ("ESXI-4.10", "pass"), ("ESXI-5.1", "pass"), ("ESXI-5.2", "pass"),
        ("ESXI-5.3", "fail"), ("ESXI-5.4", "fail"), ("ESXI-5.5", "fail"), ("ESXI-5.6", "fail"), ("ESXI-5.13", "fail"),
        ("ESXI-6.1", "fail"), ("ESXI-7.1", "fail"), ("ESXI-7.3", "fail"), ("ESXI-7.4", "fail"), ("ESXI-7.5", "pass"),
        ("ESXI-7.8", "pass"), ("ESXI-8.1", "fail"), ("ESXI-8.2", "pass"), ("ESXI-8.4", "fail"), ("ESXI-8.7", "pass"),
        ("ESXI-8.13", "fail"), ("ESXI-8.14", "fail"), ("ESXI-1.1", "skipped"), ("ESXI-8.15", "skipped"),
    ])
    def test_verdicts(self, rid, expected):
        assert run()[1][rid] == expected

    def test_evidence(self):
        assert evidence(DUMP, "ESXI-5.3").startswith("SSH: startup policy on, SSH is running (this audit connects over SSH")
        assert evidence(DUMP, "ESXI-7.1") == ("Allow Forged Transmits allowed on: vSwitch vSwitch1, port group Backup "
                                               "Network, port group Trunk-Monitor")
        assert evidence(DUMP, "ESXI-7.4") == "port groups on VLAN 4095: Trunk-Monitor (VLAN 4095)"
        assert "vSphereClient" in evidence(DUMP, "ESXI-2.3") and "sshServer" not in evidence(DUMP, "ESXI-2.3")
        assert evidence(DUMP, "ESXI-8.13") == "devices present: lab-nested (usb.present), lab-nested (serial0.present)"
        assert "web01 (not set)" in evidence(DUMP, "ESXI-8.8") and "db01" not in evidence(DUMP, "ESXI-8.8")
        assert "net-usbnic" in evidence(DUMP, "ESXI-1.3")

    def test_hardened_values_pass(self):
        d = dump(ADVANCED=advanced(
            ints={"/UserVars/ESXiShellInteractiveTimeOut": 300, "/UserVars/ESXiShellTimeOut": 3600,
                  "/UserVars/HostClientCEIPOptIn": 2, "/Security/PasswordHistory": 5, "/Security/PasswordMaxDays": 90,
                  "/Net/BlockGuestBPDU": 1},
            strings={"/Security/PasswordQualityControl": "retry=3 min=disabled,disabled,disabled,disabled,15",
                     "/Syslog/global/logHost": "ssl://syslog.corp.example.com:1514", "/Annotations/WelcomeMessage": "x",
                     "/Config/Etc/issue": "Authorized use only"}),
            SERVICES=SECTIONS["SERVICES"].replace("SSH|on|SSH is running", "SSH|off|SSH is not running"),
            LOCKDOWN='lockdownMode = "lockdownNormal"', SSH_KEYS="0")
        st = run(d)[1]
        for rid in ("5.6", "5.7", "5.13", "4.5", "4.6", "2.10", "4.2", "3.3", "5.9", "5.10", "5.3", "5.4", "5.5"):
            assert st[f"ESXI-{rid}"] == "pass", rid

    def test_limits(self):
        too_long = dump(ADVANCED=advanced(ints={"/UserVars/ESXiShellInteractiveTimeOut": 900,
                                                "/Security/AccountLockFailures": 0}))
        st = run(too_long)[1]
        assert st["ESXI-5.6"] == "fail" and st["ESXI-4.3"] == "fail"  # 0 = never lock

    def test_missing_option_and_failed_section(self):
        lines = [ln for ln in advanced().splitlines()]
        i = lines.index("### /Syslog/global/auditRecord/remoteEnable")
        d = dump(ADVANCED="\n".join(lines[:i + 1] + lines[i + 4:]))
        assert evidence(d, "ESXI-3.5") == "Syslog.global.auditRecord.remoteEnable = not present on this host"
        d = dump(NTP="CMD_ERROR: exit 1: Error: Unknown command or namespace system ntp get")
        report, st = run(d)
        assert st["ESXI-2.1"] == "error" and report["summary"]["error_checks"] == 1

    def test_firewall_table_parsing(self):
        _head, enabled, allowed = R.firewall(DUMP)
        assert len(enabled) == 14 and enabled["sshServer"] and not enabled["CIMSLP"]
        assert allowed["sshServer"] == "10.10.0.0/24" and allowed["vSphereClient"] == "All"
        assert "Name" not in enabled and "----" not in "".join(enabled)

    def test_remote_host_none(self):
        assert R.adv(DUMP, "/Syslog/global/logHost") == ""
        assert evidence(DUMP, "ESXI-3.3") == "remote syslog host = none"

    def test_version_gate(self):
        with pytest.raises(ValueError, match="not VMware ESXi"):
            R.rules_for(dump(ESXI_VERSION="NOT_ESXI"))
        with pytest.raises(ValueError, match="ESXi 7 and 8"):
            R.rules_for(dump(ESXI_VERSION="VMware ESXi 6.7.0 build-17700523"))
        assert R.rules_for(dump(ESXI_VERSION="VMware ESXi 7.0.3 build-21930508"))


class TestPrivacy:
    def test_vmx_lines_are_whitelisted(self):
        assert "guestinfo" not in COMMANDS["VMS"] and "isolation" in COMMANDS["VMS"]
        assert "grep -iE '^(" in COMMANDS["VMS"]

    def test_ssh_keys_are_counted_not_read(self):
        assert "grep -c" in COMMANDS["SSH_KEYS"]

    def test_snmp_communities_redacted(self):
        text = "   Communities: public, monitor-ro\n   Enable: true"
        assert redact(text) == "   Communities: *** (2)\n   Enable: true"
        assert redact("   Communities: \n   Enable: false") == "   Communities: \n   Enable: false"
        _, st = run(redact(dump(SNMP=text)))
        assert st["ESXI-2.5"] == "fail"


class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}
        assert len([t for t in TEMPLATES.templates.values() if not t.manual_only]) == 40
        for rid in ("ESXI-5.3", "ESXI-5.4", "ESXI-2.3", "ESXI-8.1", "ESXI-7.4"):
            assert TEMPLATES.templates[rid].manual_only, rid

    def test_parameters(self):
        for rid in ("ESXI-1.2", "ESXI-1.4", "ESXI-1.5", "ESXI-1.6", "ESXI-2.2", "ESXI-2.5", "ESXI-2.6", "ESXI-2.9",
                    "ESXI-4.6", "ESXI-4.10", "ESXI-5.5", "ESXI-5.7", "ESXI-7.1", "ESXI-7.2", "ESXI-7.3"):
            assert TEMPLATES.missing(rid, {}) == ["CONFIRM"], rid
        assert TEMPLATES.missing("ESXI-2.1", {}) == ["NTP_SERVERS"]
        assert TEMPLATES.missing("ESXI-3.3", {}) == ["SYSLOG_HOST"]
        assert TEMPLATES.missing("ESXI-5.9", {}) == ["BANNER_TEXT"]
        for cid, t in TEMPLATES.templates.items():
            leftovers = {m for s in t.statements + t.verify_statements for m in PLACEHOLDER_RE.findall(s)}
            assert leftovers <= {"{" + p + "}" for p in t.parameters}, cid

    @pytest.mark.parametrize("cid, name, value", [
        ("ESXI-2.1", "NTP_SERVERS", "ntp1;reboot"), ("ESXI-2.1", "NTP_SERVERS", "a b"),
        ("ESXI-3.3", "SYSLOG_HOST", "syslog.corp:514"), ("ESXI-3.3", "SYSLOG_HOST", "ssl://x;reboot"),
        ("ESXI-5.9", "BANNER_TEXT", "short"), ("ESXI-5.9", "BANNER_TEXT", "It's authorized use only"),
    ])
    def test_unsafe_values_rejected(self, cid, name, value):
        assert TEMPLATES.validate(cid, {name: value})

    def test_safe_values_accepted(self):
        for cid in ("ESXI-2.1", "ESXI-3.3", "ESXI-5.9"):
            assert TEMPLATES.validate(cid, PARAMS) is None

    def test_scripts_parse(self):
        sh = shutil.which("busybox")
        cmd = [sh, "sh", "-n", "-c"] if sh else ["sh", "-n", "-c"]
        scripts = list(COMMANDS.values())
        for cid in TEMPLATES.templates:
            scripts += TEMPLATES.statements(cid, PARAMS) + TEMPLATES.verify_statements(cid, PARAMS)
        for script in scripts:
            p = subprocess.run(cmd + [script], capture_output=True, text=True)
            assert p.returncode == 0, (script, p.stderr)


# ── the module's scripts against the emulator ───────────────────────────

SHELL = ["busybox", "sh"] if shutil.which("busybox") else ["sh"]


class _LocalRunner:
    """Runs what SSHConnection would send over SSH, in a local shell whose
    PATH has the emulator's commands."""

    def __init__(self, root, env):
        self.root, self.env, self.ip = root, env, "10.10.0.50"

    def run_with_status(self, command, timeout=120):
        assert command.startswith("sh -c ")
        p = subprocess.run(SHELL + ["-c", fake_esxi.rewrite(command, self.root)], env=self.env, capture_output=True,
                           text=True, timeout=timeout)
        return p.stdout + p.stderr, p.returncode

    def send_command_with_status(self, *a, **kw):
        raise AssertionError("ESXi has no sudo")


@pytest.fixture
def emulated(tmp_path):
    env = fake_esxi.install(str(tmp_path))
    return SSHConnection(_LocalRunner(str(tmp_path), env), as_root=True)


class TestEmulator:
    def test_collection_matches_the_sample(self, emulated):
        d = collect(emulated)
        assert "Guest-Secret-7" not in d and "displayName" not in d and "uuid.bios" not in d
        assert "ssh-ed25519" not in d
        got = {f["id"]: (f["status"], f["evidence"]) for f in run(d)[0]["findings"]}
        want = {f["id"]: (f["status"], f["evidence"]) for f in run()[0]["findings"]}
        assert got == want

    def test_every_fix_applies_and_verifies(self, emulated):
        before = run(collect(emulated))[1]
        results = {cid: run_template(SPEC, emulated, cid, PARAMS) for cid, t in TEMPLATES.templates.items()
                   if not t.manual_only}
        # 1.2: esxcli refuses PartnerSupported while a community VIB is installed.
        assert not results.pop("ESXI-1.2")["success"]
        assert all(r["success"] for r in results.values()), {k: r for k, r in results.items() if not r["success"]}
        after = run(collect(emulated))[1]
        assert all(after[cid] == "pass" for cid in results), [cid for cid in results if after[cid] != "pass"]
        assert after["ESXI-1.2"] == before["ESXI-1.2"] == "pass"
        assert sorted(cid for cid, s in after.items() if s == "fail") == sorted(
            ["ESXI-2.3", "ESXI-3.1", "ESXI-5.3", "ESXI-5.4", "ESXI-6.1", "ESXI-7.4", "ESXI-8.1", "ESXI-8.4", "ESXI-8.5",
             "ESXI-8.6", "ESXI-8.8", "ESXI-8.9", "ESXI-8.10", "ESXI-8.13", "ESXI-8.14"])
        # A second run changes nothing and still verifies.
        again = {cid: run_template(SPEC, emulated, cid, PARAMS)["success"] for cid in results}
        assert all(again.values())

    def test_values_read_back(self, emulated):
        run_template(SPEC, emulated, "ESXI-2.1", PARAMS)
        run_template(SPEC, emulated, "ESXI-3.3", PARAMS)
        run_template(SPEC, emulated, "ESXI-5.10", PARAMS)
        d = collect(emulated)
        assert "Server: ntp1.corp.example.com, 10.10.0.5" in section(d, "NTP")
        assert R.adv(d, "/Syslog/global/logHost") == "ssl://syslog.corp.example.com:1514"
        assert R.adv(d, "/Config/Etc/issue") == "Authorized use only. Activity is monitored."

    def test_verification_catches_a_switch_left_open(self, emulated):
        # Port group set fails for one group: the fix is not confirmed.
        emulated.execute("esxcli network vswitch standard portgroup policy security set -p 'Trunk-Monitor' "
                         "--allow-forged-transmits=false")
        verify = TEMPLATES.verify_statements("ESXI-7.1", PARAMS)[0]
        assert "FAIL" in emulated.run(verify)  # vSwitch1 and Backup Network still accept forged transmits
        assert run_template(SPEC, emulated, "ESXI-7.1", PARAMS)["success"]
        assert emulated.run(verify).strip() == "PASS"

    def test_backup_snapshot(self, emulated):
        text = SPEC.backup(emulated)
        for name in ("ADVANCED", "FIREWALL", "VSWITCH", "SERVICES"):
            assert f"##### {name} before hardening #####" in text
        assert "ssh-ed25519" in text  # root's public keys, so 5.5 can be undone

    def test_software(self, emulated):
        item = collect_software(emulated)
        assert (item["name"], item["version"], item["build"], item["kind"]) == (
            "VMware ESXi", "8.0.2", "22380479", "firmware")


# ── the connector ───────────────────────────────────────────────────────

class _Runner:
    answer = "VMware ESXi 8.0.2 build-22380479"
    fail_with = None

    def __init__(self, **kw):
        self.kw, self.ip, self.closed = kw, kw["ip"], False

    def connect(self):
        if self.fail_with:
            raise self.fail_with

    def run_with_status(self, command, timeout=120):
        return self.answer, 0

    def send_command_with_status(self, *a, **kw):
        raise AssertionError("ESXi has no sudo")

    def disconnect(self):
        self.closed = True


@pytest.fixture
def runner(monkeypatch):
    import app.modules.linux.common.fast_ssh_runner as m
    made = []

    class R_(_Runner):
        def __init__(self, **kw):
            super().__init__(**kw)
            made.append(self)

    monkeypatch.setattr(m, "HardeningSSHRunner", R_)
    return R_, made


class TestConnector:
    def test_fields(self):
        c = connectors.CONNECTORS["ssh_esxi"]
        assert isinstance(c, ESXiConnector) and "sudo_password" not in c.request_fields
        assert c.required_for_schedule == {"ssh_username", "ssh_password"}

    def test_opens_without_sudo(self, runner):
        cls, made = runner
        with ESXiConnector().open("10.10.0.50", {"ssh_password": "x"}) as conn:
            assert conn.run("true").startswith("VMware ESXi")
        assert made[0].kw["username"] == "root" and made[0].closed

    def test_not_esxi(self, runner):
        cls, made = runner
        cls.answer = "sh: vmware: not found"
        try:
            with pytest.raises(ConnectionError, match="not an ESXi host"):
                with ESXiConnector().open("10.10.0.51", {"ssh_username": "root", "ssh_password": "x"}):
                    pass
            assert made[0].closed
        finally:
            cls.answer = _Runner.answer

    def test_auth_failure(self, runner):
        from app.core.ssh_exceptions import SSHAuthenticationError
        cls, _made = runner
        cls.fail_with = SSHAuthenticationError("Authentication failed for root@10.10.0.52")
        try:
            with pytest.raises(PermissionError):
                with ESXiConnector().open("10.10.0.52", {"ssh_username": "root", "ssh_password": "bad"}):
                    pass
        finally:
            cls.fail_with = None


# ── through the engine and the database ─────────────────────────────────

@pytest.fixture
def ctx(monkeypatch):
    connection = db_engine.connect()
    trans = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    u = User(username="esxi-tester", email="esxi-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="Hypervisor (test)", category="server")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="ESX01", asset_type_id=t.id, ip_address="10.10.0.50", os_name="VMware ESXi 8.0")
    db.add(a)
    db.flush()
    sections = {**SECTIONS, "ADVANCED": advanced()}
    host = install(monkeypatch, FakeHost(esxi_commands(), sections, TEMPLATES, ip=a.ip_address),
                   connector_key="ssh_esxi", password_field="ssh_password", password="Esx-Pass-1")
    monkeypatch.setattr(SPEC, "save_software", None)
    try:
        yield db, u, a, host
    finally:
        db.close()
        trans.rollback()
        connection.close()


CREDS = {"ssh_username": "root", "ssh_password": "Esx-Pass-1"}


def test_audit_then_fix(ctx):
    db, user, asset, host = ctx
    session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
    assert session.status == "completed" and session.device_type == DeviceType.ESXI
    assert session.passed_checks == 28 and session.failed_checks == 35
    out = BenchmarkHardeningService(SPEC).batch_execute_selected(db, session.id, asset.id, dict(CREDS), [
        {"check_id": "ESXI-5.6", "parameters": {}}, {"check_id": "ESXI-2.1", "parameters": {"NTP_SERVERS": "10.10.0.5"}},
        {"check_id": "ESXI-7.1", "parameters": {"CONFIRM": "yes"}}, {"check_id": "ESXI-5.3", "parameters": {}}])
    assert out["successful"] == 3 and out["failed"] == 1
    rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
    assert rows["ESXI-5.6"] == rows["ESXI-2.1"] == rows["ESXI-7.1"] == CheckStatus.PASS
    assert rows["ESXI-5.3"] == CheckStatus.FAIL


def test_wrong_password_is_reported(ctx):
    db, user, asset, _host = ctx
    with pytest.raises(PermissionError):
        BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, {**CREDS, "ssh_password": "nope"})


def test_integration_and_classification():
    from app.core.target_catalog import target_for_device_type
    from app.modules.benchmark.registry import spec_map
    from app.modules.hardening.harden_all.families import get_family
    from app.modules.scheduling.audit_dispatch import REQUIRED_PARAMS, SUPPORTED_TECHNOLOGIES
    from app.utils.device_classification import family_matches, infer_device_family
    assert spec_map()["esxi"] is SPEC
    t = target_for_device_type("esxi")
    assert t.category == "platforms" and t.icon == "hypervisor" and t.connects_via == "SSH"
    fam = get_family(DeviceType.ESXI)
    assert {f.name for f in fam.credential_fields} == {"ssh_username", "ssh_password", "ssh_port"}
    assert "esxi" in SUPPORTED_TECHNOLOGIES and REQUIRED_PARAMS["esxi"] == {"ssh_username", "ssh_password"}

    def asset(name, os_name, model=None, type_name="Server"):
        return type("A", (), {"manufacturer": None, "os_name": os_name, "os_version": "", "model": model,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()
    assert infer_device_family(asset("esx01", "VMware ESXi 8.0.2")) == "esxi"
    assert infer_device_family(asset("host7", None, type_name="vSphere host")) == "esxi"
    # A virtual machine on ESXi is not the hypervisor.
    assert infer_device_family(asset("web01", "Ubuntu 24.04", model="VMware Virtual Platform")) == "linux"
    assert not family_matches("linux", "esxi")
