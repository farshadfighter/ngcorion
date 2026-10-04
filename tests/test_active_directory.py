"""
Active Directory module: the CIS domain-controller profile and the domain
checks beyond CIS, evaluated on sample collector output of a Windows Server
2022 DC (tests/ad_sample.py - built, not captured from a real DC); collection
failures reported as "not evaluated"; the remediation templates; and the whole
audit -> fix flow through the benchmark engine against a simulated DC.
"""
import json
import re
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.core.hardening_param_security import ParameterSecurityError
from app.models import Asset, AuditResult, AuditSession, User
from app.models.asset_types import AssetType
from app.models.audit import CheckStatus, DeviceType
from app.modules.active_directory import rules as R
from app.modules.active_directory.collect import ad_commands
from app.modules.active_directory.hardening import TEMPLATES
from app.modules.active_directory.spec import SPEC
from app.modules.benchmark import connectors
from app.modules.benchmark.audit_service import BenchmarkAuditService
from app.modules.benchmark.hardening_service import BenchmarkHardeningService, run_template
from app.modules.benchmark.rules import evaluate
from app.modules.windows.audit import rules as W
from app.modules.windows.hardening.command_templates import WINDOWS_HARDENING_TEMPLATES

sys.path.insert(0, str(Path(__file__).parent))
import ad_sample as S  # noqa: E402


def run(dump):
    report = evaluate(dump, R.rules_for(dump), R.JSON_SECTIONS)
    return report, {f["id"]: f for f in report["findings"]}


@pytest.fixture(scope="module")
def sample():
    return run(S.dump())


def status(findings, rule_id):
    return findings[rule_id]["status"]


# ── rule set ───────────────────────────────────────────────────────────────

class TestRuleSet:
    def test_counts_and_unique_ids(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules)
        cis = [r for r in rules if r.id.startswith("AD-CIS-")]
        dom = [r for r in rules if r.id.startswith("AD-DOM-")]
        assert len(cis) + len(dom) == len(rules)
        assert len(dom) == 43
        assert len(cis) >= 250

    def test_cis_part_is_the_windows_dc_profile(self):
        win = W.filter_rules_by_scope(W.build_win2025_cis_rules(), True)
        ids = {r.section for r in R.cis_rules()}
        assert {r.section for r in win} <= ids
        assert not [r for r in R.cis_rules() if r.scope == "MS"], "member-server controls must not apply to a DC"
        # The DC controls the Windows module leaves manual or lacks are automated here.
        by = {r.section: r for r in R.cis_rules()}
        for sec in ("2.2.5", "2.3.5.1", "2.3.10.6", "5.1"):
            assert not by[sec].manual, sec

    def test_sources_label_cis_and_beyond_cis(self):
        for r in R.all_rules():
            assert r.source == ("CIS" if r.id.startswith("AD-CIS-") else "Beyond CIS"), r.id
            assert r.title and r.remediation and r.severity in ("high", "medium", "low")
            if not r.manual:
                assert r.data_sections, r.id

    def test_every_domain_section_is_collected(self):
        cmds = ad_commands()
        needed = {s for r in R.all_rules() for s in r.data_sections}
        assert needed <= set(cmds), needed - set(cmds)

    def test_collection_never_reads_secrets(self):
        text = " ".join(ad_commands().values())
        assert "ms-Mcs-AdmPwd)" not in text and "msLAPS-Password)" not in text
        assert "DefaultPassword" not in text
        # GPP: only file names are reported, never the cpassword value
        assert "Select-String -Pattern 'cpassword" in text and "-List" in text


# ── evaluation on the sample DC ────────────────────────────────────────────

class TestSampleDomain:
    def test_summary(self, sample):
        report, _ = sample
        s = report["summary"]
        assert s["error_checks"] == 0
        assert s["total_rules_scored"] + s["manual_checks"] == len(R.rules_for(S.dump()))
        assert 0 < s["compliance_pct"] < 100

    @pytest.mark.parametrize("rule_id, expected", [
        ("AD-CIS-2.2.5", "fail"),          # Authenticated Users may add workstations
        ("AD-CIS-5.1", "fail"),            # Spooler running on the DC
        ("AD-CIS-2.3.10.6", "pass"),       # LSARPC, NETLOGON, SAMR, BROWSER
        ("AD-CIS-2.3.5.1", "pass"),        # SubmitControl absent = disabled
        ("AD-CIS-1.1.4", "fail"),          # minimum length 7
        ("AD-CIS-17.4.2", "fail"),         # DS changes not audited
        ("AD-DOM-1.1", "pass"),            # Schema Admins: only RID 500
        ("AD-DOM-1.2", "fail"),            # Enterprise Admins: adm.sara too
        ("AD-DOM-1.3", "pass"),            # 5 Domain Admins
        ("AD-DOM-1.4", "fail"),            # helpdesk1 in Account Operators
        ("AD-DOM-1.5", "fail"),            # DnsAdmins not empty
        ("AD-DOM-1.6", "fail"),            # disabled adm.old still in Domain Admins
        ("AD-DOM-1.7", "fail"),
        ("AD-DOM-1.12", "fail"),           # svc_backup has an SPN
        ("AD-DOM-1.13", "pass"),           # only Authenticated Users
        ("AD-DOM-2.1", "fail"),            # krbtgt 1283 days
        ("AD-DOM-2.2", "fail"),
        ("AD-DOM-2.3", "pass"),
        ("AD-DOM-2.7", "pass"),
        ("AD-DOM-3.1", "fail"),
        ("AD-DOM-3.2", "pass"),
        ("AD-DOM-3.4", "fail"),            # MachineAccountQuota 10
        ("AD-DOM-4.1", "fail"),            # 2012 R2 domain level
        ("AD-DOM-4.3", "fail"),            # DC02 on 2012 R2
        ("AD-DOM-4.7", "pass"),
        ("AD-DOM-4.8", "fail"),            # 141 / 318
        ("AD-DOM-4.9", "fail"),            # Groups.xml with cpassword
        ("AD-DOM-4.10", "fail"),           # external trust without quarantine
        ("AD-DOM-4.11", "pass"),
        ("AD-DOM-5.1", "pass"),
        ("AD-DOM-5.2", "pass"),
        ("AD-DOM-5.4", "fail"),            # DsrmAdminLogonBehavior = 2
    ])
    def test_verdicts(self, sample, rule_id, expected):
        assert status(sample[1], rule_id) == expected, sample[1][rule_id]["evidence"]

    def test_evidence_names_what_was_found(self, sample):
        f = sample[1]
        assert "adm.sara" in f["AD-DOM-1.2"]["evidence"]
        assert "1283" in f["AD-DOM-2.1"]["evidence"]
        assert "44.3%" in f["AD-DOM-4.8"]["evidence"]
        assert "Groups.xml" in f["AD-DOM-4.9"]["evidence"]
        assert "DC02 (Windows Server 2012 R2 Standard)" in f["AD-DOM-4.3"]["evidence"]

    def test_hardened_domain_passes_every_domain_check(self):
        admin = dict(S.ADMIN, NotDelegated=True, PwdNeverExpires=False, PwdLastSetDays=20)
        sara = dict(S.DA[1], NotDelegated=True)
        priv = json.loads(S.sections()["AD_PRIVILEGED"])
        for name, g in priv.items():
            if name != "Pre-Windows 2000 Compatible Access":
                g["Members"] = []
        priv["Domain Admins"]["Members"] = [admin, sara]
        priv["Administrators"]["Members"] = [admin, sara]
        priv["Protected Users"]["Members"] = [sara]
        acc = json.loads(S.sections()["AD_ACCOUNTS"])
        for k, v in acc.items():
            if isinstance(v, dict) and "Count" in v and k not in ("UsersEnabled", "WindowsComputers", "ConstrainedDelegation"):
                v.update(Count=0, Sample=[])
        acc["LapsWindowsManaged"] = {"Count": 318, "Sample": []}
        acc["Krbtgt"] = {"PwdLastSetDays": 30}
        acc["BuiltinAdmin"].update(NotDelegated=True)
        dom = json.loads(S.sections()["AD_DOMAIN"])
        dom.update(DomainMode="Windows2016Domain", ForestMode="Windows2016Forest", RecycleBinEnabled=True,
                   MachineAccountQuota=0, DomainControllers=dom["DomainControllers"][:1])
        overrides = {
            "AD_PRIVILEGED": json.dumps(priv), "AD_ACCOUNTS": json.dumps(acc), "AD_DOMAIN": json.dumps(dom),
            "AD_TRUSTS": json.dumps([dict(json.loads(S.sections()["AD_TRUSTS"])[0], SIDFilteringQuarantined=True)]),
            "AD_GPP": json.dumps({"Scanned": "x", "Files": []}),
            "AD_REGISTRY": json.dumps({"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa": '{"DsrmAdminLogonBehavior":0}'}),
        }
        _, f = run(S.dump(overrides))
        failing = [i for i, x in f.items() if i.startswith("AD-DOM-") and x["status"] != "pass"]
        assert failing == []

    def test_ds_heuristics_anonymous_access_fails(self):
        _, f = run(S.dump(S.with_ad("AD_DOMAIN.DsHeuristics", "0000002")))
        assert status(f, "AD-DOM-4.6") == "fail"

    def test_pre_windows_2000_with_anonymous_fails(self):
        _, f = run(S.dump(S.with_ad("AD_PRIVILEGED.Pre-Windows 2000 Compatible Access.Members", ["S-1-5-11", "S-1-5-7"])))
        assert status(f, "AD-DOM-1.13") == "fail"


# ── what cannot be read is not judged ──────────────────────────────────────

class TestNotEvaluated:
    def test_failed_directory_query_marks_its_rules_error(self):
        _, f = run(S.dump({"AD_PRIVILEGED": "PS_ERROR: Unable to find a default server with Active Directory Web Services running."}))
        for n in ("1.1", "1.2", "1.6", "1.9", "1.13"):
            assert status(f, f"AD-DOM-{n}") == "error"
        assert "Active Directory Web Services" in f["AD-DOM-1.1"]["evidence"]
        assert status(f, "AD-DOM-2.1") == "fail"      # other sections still judged

    def test_one_unreadable_group_only_blocks_the_rules_that_need_it(self):
        _, f = run(S.dump(S.with_ad("AD_PRIVILEGED.Enterprise Admins.Error", "The server is not operational")))
        assert status(f, "AD-DOM-1.2") == "error"
        assert status(f, "AD-DOM-1.7") == "error"      # needs every privileged group
        assert status(f, "AD-DOM-1.1") == "pass"
        assert status(f, "AD-DOM-1.5") == "fail"

    def test_missing_dns_admins_group_is_not_a_finding(self):
        _, f = run(S.dump(S.with_ad("AD_PRIVILEGED.DnsAdmins", {"Identity": "DnsAdmins", "Exists": False, "Members": [], "Error": None})))
        assert status(f, "AD-DOM-1.5") == "pass"

    def test_laps_query_missing_is_error_not_zero(self):
        _, f = run(S.dump(S.with_ad("AD_ACCOUNTS.WindowsComputers", None)))
        assert status(f, "AD-DOM-4.8") == "error"

    def test_failed_secedit_still_errors_cis_rights(self):
        _, f = run(S.dump({"SECURITY_POLICY": "SECEDIT_EXPORT_FAILED", "USER_RIGHTS": "SECEDIT_EXPORT_FAILED"}))
        assert status(f, "AD-CIS-2.2.5") == "error"
        assert status(f, "AD-CIS-1.1.4") == "error"

    def test_member_server_is_refused(self):
        d = S.dump({"DOMAIN_ROLE": '{"DomainRole":3,"Domain":"corp.example.com","PartOfDomain":true}'})
        with pytest.raises(ValueError, match="not a domain controller"):
            R.rules_for(d)


# ── remediation templates ──────────────────────────────────────────────────

class TestTemplates:
    def test_templates_belong_to_rules(self):
        ids = {r.id for r in R.all_rules()}
        assert set(TEMPLATES.templates) <= ids

    def test_cis_fixes_are_the_windows_fixes(self):
        for cid, t in TEMPLATES.templates.items():
            if not cid.startswith("AD-CIS-") or t.manual_only:
                continue
            w = WINDOWS_HARDENING_TEMPLATES.get("WIN-2025-" + cid.removeprefix("AD-CIS-"))
            if w is not None:
                assert t.statements == w.statements and t.verify_statements == w.verify_statements, cid

    def test_account_policy_is_manual_on_a_dc(self):
        for sec in ("1.1.1", "1.1.4", "1.2.1"):
            t = TEMPLATES.get(f"AD-CIS-{sec}")
            assert t.manual_only and "Default Domain Policy" in t.description

    @pytest.mark.parametrize("check_id", ["AD-DOM-2.1", "AD-DOM-4.4", "AD-DOM-1.13", "AD-DOM-3.4", "AD-DOM-1.9"])
    def test_side_effects_need_confirmation(self, check_id):
        t = TEMPLATES.get(check_id)
        assert t.warning
        assert not TEMPLATES.auto_fixable(check_id)
        assert TEMPLATES.categorize([check_id])["needs_params"] == [check_id]
        assert TEMPLATES.missing(check_id, {}) == ["CONFIRM"]
        assert TEMPLATES.missing(check_id, {"CONFIRM": "yes"}) == []
        with pytest.raises(ParameterSecurityError):
            TEMPLATES.statements(check_id, {"CONFIRM": "sure"})

    def test_every_automated_fix_verifies(self):
        for cid, t in TEMPLATES.templates.items():
            if not t.manual_only:
                assert t.statements and t.verify_statements, cid
                joined = " ".join(t.verify_statements)
                assert "PASS" in joined and "FAIL" in joined, cid

    def test_krbtgt_reset_never_prints_the_password(self):
        stmt = TEMPLATES.statements("AD-DOM-2.1", {"CONFIRM": "yes"})[0]
        assert "Set-ADAccountPassword -Identity krbtgt -Reset" in stmt
        assert "Write-Output" not in stmt
        assert not re.search(r";\s*\$p\s*(;|$)", stmt), "the generated password must not be emitted"


# ── end to end through the engine, against a simulated DC ─────────────────

class FakeDC:
    """Answers the collection scripts with the sample outputs, and applies
    fixes: a fix's statements mark its check fixed, its verification then
    prints PASS."""

    def __init__(self, sections=None, auth_ok=True):
        self.sections = sections or S.sections()
        self.by_script = {script: name for name, script in ad_commands().items()}
        self.applied = set()
        self.executed = []
        self.auth_ok = auth_ok
        self.ip = "10.10.0.10"

    def run(self, script):
        name = self.by_script.get(script)
        return self.sections.get(name, "(no output)") if name else "(no output)"

    _run_ps = run

    def execute(self, script):
        self.executed.append(script)
        for cid, t in TEMPLATES.templates.items():
            if script in TEMPLATES.statements(cid, {"CONFIRM": "yes"}):
                self.applied.add(cid)
                return "(ok)"
            if script in TEMPLATES.verify_statements(cid, {"CONFIRM": "yes"}):
                return "PASS" if cid in self.applied else "FAIL"
        return "(ok)"


@pytest.fixture
def fake_dc(monkeypatch):
    dc = FakeDC()

    class _Connector(connectors.WinRMConnector):
        @contextmanager
        def open(self, ip, creds):
            if creds.get("windows_password") != "Corp-Pass-1":
                raise PermissionError("WinRM auth failed")
            yield dc

    monkeypatch.setitem(connectors.CONNECTORS, "winrm", _Connector())
    return dc


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
def user(db):
    u = User(username="ad-tester", email="ad-tester@example.com", hashed_password="x", role="admin")
    db.add(u)
    db.flush()
    return u


@pytest.fixture
def asset(db):
    t = AssetType(type_name="Domain Controller (test)", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name="DC01", asset_type_id=t.id, ip_address="10.10.0.10", os_name="Windows Server 2022")
    db.add(a)
    db.flush()
    return a


CREDS = {"windows_username": "CORP\\auditor", "windows_password": "Corp-Pass-1", "winrm_port": 5985, "transport": "ntlm"}


class TestEndToEnd:
    def test_audit_stores_every_result(self, db, user, asset, fake_dc, monkeypatch):
        monkeypatch.setattr(SPEC, "save_software", None)
        session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS), job_name="AD audit")
        assert session.status == "completed"
        assert session.device_type == DeviceType.ACTIVE_DIRECTORY
        rows = db.query(AuditResult).filter(AuditResult.session_id == session.id).all()
        assert len(rows) == len(R.rules_for(S.dump()))
        by = {r.check_number: r for r in rows}
        assert by["AD-DOM-2.1"].status == CheckStatus.FAIL
        assert by["AD-DOM-1.1"].status == CheckStatus.PASS
        assert session.compliance_pct == run(S.dump())[0]["summary"]["compliance_pct"]
        summary = BenchmarkAuditService(SPEC).summary(db, session.id)
        assert summary["device_type"] == "active_directory"

    def test_bad_credentials_fail_the_session(self, db, user, asset, fake_dc):
        with pytest.raises(PermissionError):
            BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS, windows_password="nope"))
        s = db.query(AuditSession).filter(AuditSession.asset_id == asset.id).one()
        assert s.status == "failed" and "auth failed" in s.connection_error

    def test_member_server_fails_with_a_clear_message(self, db, user, asset, fake_dc):
        fake_dc.sections["DOMAIN_ROLE"] = '{"DomainRole":3}'
        with pytest.raises(ValueError, match="not a domain controller"):
            BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))

    def test_fix_flips_the_result_only_when_verified(self, db, user, asset, fake_dc, monkeypatch):
        monkeypatch.setattr(SPEC, "save_software", None)
        session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
        svc = BenchmarkHardeningService(SPEC)
        before = session.compliance_pct

        result = svc.execute_single(db, asset.id, dict(CREDS), "AD-DOM-5.4", session_id=session.id)
        assert result["success"] is True and result["verification_result"] == "PASS"
        row = db.query(AuditResult).filter_by(session_id=session.id, check_number="AD-DOM-5.4").one()
        assert row.status == CheckStatus.PASS
        db.refresh(session)
        assert session.compliance_pct > before

        # a gated fix without its confirmation is refused before anything runs
        n = len(fake_dc.executed)
        result = svc.execute_single(db, asset.id, dict(CREDS), "AD-DOM-2.1", session_id=session.id)
        assert result["success"] is False and "CONFIRM" in result["error_message"]
        assert len(fake_dc.executed) == n

        # manual checks are never run
        result = svc.execute_single(db, asset.id, dict(CREDS), "AD-DOM-1.2")
        assert result["success"] is False and result["manual_only"] is True

    def test_batch_with_backup(self, db, user, asset, fake_dc, monkeypatch):
        monkeypatch.setattr(SPEC, "save_software", None)
        monkeypatch.setattr(SPEC, "backup", lambda conn: "#### snapshot ####")
        session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
        out = BenchmarkHardeningService(SPEC).batch_execute_selected(
            db, session.id, asset.id, dict(CREDS),
            [{"check_id": "AD-CIS-5.1", "parameters": {}}, {"check_id": "AD-DOM-3.4", "parameters": {"CONFIRM": "yes"}}],
            create_backup=True, user_id=user.id)
        assert out["successful"] == 2 and out["backup_created"] is True

    def test_session_of_another_family_is_refused(self, db, user, asset, fake_dc):
        other = AuditSession(user_id=user.id, asset_id=asset.id, target_ip="10.10.0.10",
                             device_type=DeviceType.WINDOWS, status="completed")
        db.add(other)
        db.flush()
        with pytest.raises(ValueError, match="not a Active Directory audit session|not an? Active Directory"):
            BenchmarkHardeningService(SPEC).batch_execute_selected(db, other.id, asset.id, dict(CREDS), [])


# ── the rest of the product knows the module ──────────────────────────────

class TestIntegration:
    def test_harden_all_family(self):
        from app.modules.hardening.harden_all.families import get_family
        fam = get_family(DeviceType.ACTIVE_DIRECTORY)
        assert fam.label == "Active Directory" and fam.capabilities.backup
        assert fam.categorize(["AD-CIS-2.3.5.3", "AD-DOM-2.1", "AD-DOM-1.1"]) == {
            "auto_fixable": ["AD-CIS-2.3.5.3"], "needs_params": ["AD-DOM-2.1"], "not_supported": ["AD-DOM-1.1"]}
        assert "CONFIRM" in fam.aggregate(["AD-DOM-2.1"])

    def test_scheduling_knows_the_technology(self):
        from app.modules.scheduling.audit_dispatch import REQUIRED_PARAMS, SUPPORTED_TECHNOLOGIES
        assert "active_directory" in SUPPORTED_TECHNOLOGIES
        assert REQUIRED_PARAMS["active_directory"] == {"windows_username", "windows_password"}

    def test_report_texts(self):
        from app.modules.reports.rule_text import text_for
        rationale, remediation = text_for("active_directory", "AD-DOM-4.9")
        assert "Group Policy Preferences" in rationale and remediation

    def test_target_catalog_and_classification(self):
        from app.core.target_catalog import target_for_device_type
        from app.utils.device_classification import family_matches, infer_device_family, infer_device_variant
        t = target_for_device_type("active_directory")
        assert t.category == "services" and t.icon == "directory" and t.connects_via == "WinRM"

        class A:
            manufacturer = "Microsoft"
            os_name = "Windows Server 2022"
            os_version = ""
            model = None
            asset_name = "DC01"
            asset_type = type("T", (), {"type_name": "Domain Controller"})()
        assert infer_device_family(A()) == "active_directory"
        assert infer_device_variant(A()) == "windows-2022"
        # a DC stays in the Windows Server list and Windows hosts in the AD list
        assert family_matches("active_directory", "windows")
        assert family_matches("windows", "active_directory")
        assert not family_matches("linux", "active_directory")
