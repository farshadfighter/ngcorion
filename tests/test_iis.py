"""
IIS 10 module (CIS Microsoft IIS 10): rules on sample collector output of a
Windows Server 2022 web server (tests/iis_sample.py - built, not captured),
collection failures, the remediation templates and the audit -> fix flow
through the benchmark engine against a simulated host.
"""
import sys
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.models import Asset, AuditResult, User
from app.models.asset_types import AssetType
from app.models.audit import CheckStatus, DeviceType
from app.modules.benchmark.audit_service import BenchmarkAuditService
from app.modules.benchmark.hardening_service import BenchmarkHardeningService
from app.modules.benchmark.rules import assemble, evaluate
from app.modules.iis import rules as R
from app.modules.iis.collect import iis_commands
from app.modules.iis.hardening import TEMPLATES
from app.modules.iis.spec import SPEC

sys.path.insert(0, str(Path(__file__).parent))
import iis_sample as S  # noqa: E402
from benchmark_fakes import FakeHost, install  # noqa: E402


def run(dump):
    report = evaluate(dump, R.rules_for(dump), R.JSON_SECTIONS)
    return report, {f["id"]: f["status"] for f in report["findings"]}


def evidence(dump, rid):
    report, _ = run(dump)
    return next(f["evidence"] for f in report["findings"] if f["id"] == rid)


class TestRules:
    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 58
        assert sum(r.manual for r in rules) == 3
        assert all(r.source == "CIS" for r in rules)
        sections = [tuple(int(p) for p in r.section.split(".")) for r in rules]
        assert sections == sorted(sections)

    def test_collection_reads_no_content_or_secrets(self):
        text = " ".join(iis_commands().values())
        assert "Get-Content" not in text and "decryptionKey" not in text and "validationKey" not in text

    def test_saved_sample_matches(self):
        saved = (Path(__file__).parent / "mock_data" / "iis" / "web01_2022_dump.txt").read_text()
        assert saved == S.dump()

    @pytest.mark.parametrize("rid, expected", [
        ("IIS-1.1", "fail"), ("IIS-1.2", "fail"), ("IIS-1.3", "fail"), ("IIS-1.4", "fail"), ("IIS-1.5", "fail"),
        ("IIS-1.6", "fail"), ("IIS-1.7", "pass"), ("IIS-2.1", "fail"), ("IIS-2.2", "skipped"), ("IIS-2.4", "fail"),
        ("IIS-2.5", "pass"), ("IIS-2.6", "pass"), ("IIS-2.7", "pass"), ("IIS-2.8", "pass"), ("IIS-3.1", "fail"),
        ("IIS-3.2", "fail"), ("IIS-3.3", "pass"), ("IIS-3.4", "pass"), ("IIS-3.8", "pass"), ("IIS-3.10", "fail"),
        ("IIS-3.11", "fail"), ("IIS-4.1", "pass"), ("IIS-4.4", "fail"), ("IIS-4.6", "fail"), ("IIS-4.8", "pass"),
        ("IIS-4.11", "fail"), ("IIS-5.1", "fail"), ("IIS-5.3", "fail"), ("IIS-6.1", "pass"), ("IIS-6.2", "pass"),
        ("IIS-7.1", "fail"), ("IIS-7.2", "pass"), ("IIS-7.4", "fail"), ("IIS-7.5", "pass"), ("IIS-7.6", "pass"),
        ("IIS-7.8", "fail"), ("IIS-7.12", "pass"), ("IIS-7.13", "fail"), ("IIS-7.14", "pass"), ("IIS-7.15", "fail"),
    ])
    def test_sample_verdicts(self, rid, expected):
        assert run(S.dump())[1][rid] == expected

    def test_site_override_is_seen(self):
        # Debug is off at the server, on in one site's web.config.
        assert "intranet" in evidence(S.dump(), "IIS-3.2") and "server" not in evidence(S.dump(), "IIS-3.2")

    def test_server_level_value_is_seen(self):
        srv = S.with_("IIS_SERVER", ErrorMode="Detailed")
        assert run(S.dump(IIS_SERVER=srv))[1]["IIS-3.4"] == "fail"

    def test_hsts_only_concerns_https_sites(self):
        sites = S.with_("IIS_SITES")
        for s in sites["Sites"]:
            if s["Name"] == "intranet":
                s["Hsts"] = "True"
        assert run(S.dump(IIS_SITES=sites))[1]["IIS-7.1"] == "pass"

    def test_installed_ftp_is_checked(self):
        host = S.with_("IIS_HOST")
        host["Features"] = dict(host["Features"], **{"Web-Ftp-Server": True})
        srv = S.with_("IIS_SERVER", FtpControlChannel="SslAllow", FtpDataChannel="SslRequire", FtpDenyByFailure="True")
        _, st = run(S.dump(IIS_HOST=host, IIS_SERVER=srv))
        assert st["IIS-6.1"] == "fail" and st["IIS-6.2"] == "pass"

    def test_basic_auth_without_ssl(self):
        _, st = run(S.dump(IIS_SERVER=S.with_("IIS_SERVER", BasicAuth="True", AccessSslFlags="")))
        assert st["IIS-2.6"] == "fail"
        _, st = run(S.dump(IIS_SERVER=S.with_("IIS_SERVER", BasicAuth="True", AccessSslFlags="Ssl, Ssl128")))
        assert st["IIS-2.6"] == "pass"

    def test_handler_write_and_script(self):
        _, st = run(S.dump(IIS_SERVER=S.with_("IIS_SERVER", HandlersAccessPolicy="Read, Write, Script")))
        assert st["IIS-4.8"] == "fail"

    def test_missing_section_is_error(self):
        _, st = run(S.dump(IIS_SERVER=S.with_("IIS_SERVER", RemoveServerHeader="N/A")))
        assert st["IIS-3.11"] == "error"

    def test_tls_protocol_needs_both_values(self):
        sch = S.with_("SCHANNEL", **{"Protocols\\TLS 1.0\\Server": {"Enabled": 0}})
        assert run(S.dump(SCHANNEL=sch))[1]["IIS-7.4"] == "fail"
        sch = S.with_("SCHANNEL", **{"Protocols\\TLS 1.0\\Server": {"Enabled": 0, "DisabledByDefault": 1}})
        assert run(S.dump(SCHANNEL=sch))[1]["IIS-7.4"] == "pass"

    def test_failed_section_is_error(self):
        d = assemble(dict(S.sections(), SCHANNEL="PS_ERROR: Access is denied"))
        _, st = run(d)
        assert st["IIS-7.2"] == st["IIS-7.14"] == "error" and st["IIS-1.7"] == "pass"

    def test_host_without_iis_is_refused(self):
        d = assemble(dict(S.sections(), IIS_SERVER="PS_ERROR: The specified module 'WebAdministration' was not loaded"))
        with pytest.raises(ValueError, match="IIS is not installed"):
            R.rules_for(d)

    def test_describe(self):
        assert R.describe(S.dump()) == "IIS 10.0 on Windows Server 2022, 3 sites"


class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}
        automated = [c for c, t in TEMPLATES.templates.items() if t.statements]
        assert len(automated) == 46

    @pytest.mark.parametrize("rid", ["IIS-1.4", "IIS-1.7", "IIS-3.8", "IIS-4.4", "IIS-7.1", "IIS-7.4", "IIS-7.5", "IIS-7.13"])
    def test_breaking_changes_need_confirmation(self, rid):
        assert TEMPLATES.missing(rid, {}) == ["CONFIRM"]

    def test_safe_changes_apply_directly(self):
        assert TEMPLATES.missing("IIS-3.11", {}) == [] and TEMPLATES.missing("IIS-7.8", {}) == []

    def test_schannel_fixes_need_a_restart(self):
        assert all(TEMPLATES.templates[f"IIS-7.{n}"].requires_restart for n in range(2, 16))

    def test_verifications_are_valid_powershell_shapes(self):
        for cid, t in TEMPLATES.templates.items():
            for v in t.verify_statements:
                assert "-not ($v =" not in v, cid
                assert v.count("{") == v.count("}") and v.count("(") == v.count(")"), cid


@pytest.fixture
def ctx(monkeypatch):
    connection = db_engine.connect()
    trans = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    u = User(username="iis-tester", email="iis-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="Web Server (test)", category="server")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="WEB01", asset_type_id=t.id, ip_address="10.10.0.80", os_name="Windows Server 2022")
    db.add(a)
    db.flush()
    host = install(monkeypatch, FakeHost(iis_commands(), S.sections(), TEMPLATES, ip=a.ip_address))
    monkeypatch.setattr(SPEC, "save_software", None)
    try:
        yield db, u, a, host
    finally:
        db.close()
        trans.rollback()
        connection.close()


CREDS = {"windows_username": "CORP\\webaudit", "windows_password": "Corp-Pass-1", "winrm_port": 5985, "transport": "ntlm"}


def test_audit_then_fix(ctx):
    db, user, asset, host = ctx
    session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
    assert session.status == "completed" and session.device_type == DeviceType.IIS
    out = BenchmarkHardeningService(SPEC).batch_execute_selected(db, session.id, asset.id, dict(CREDS), [
        {"check_id": "IIS-3.11", "parameters": {}}, {"check_id": "IIS-1.3", "parameters": {}},
        {"check_id": "IIS-1.4", "parameters": {}}])
    assert out["successful"] == 2 and out["failed"] == 1
    rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
    assert rows["IIS-3.11"] == rows["IIS-1.3"] == CheckStatus.PASS
    assert rows["IIS-1.4"] == CheckStatus.FAIL


def test_wrong_password_is_reported(ctx):
    db, user, asset, host = ctx
    with pytest.raises(Exception):
        BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS, windows_password="wrong"))


def test_integration_and_classification():
    from app.core.target_catalog import target_for_device_type
    from app.modules.hardening.harden_all.families import get_family
    from app.modules.scheduling.audit_dispatch import SUPPORTED_TECHNOLOGIES
    from app.utils.device_classification import family_matches, infer_device_family
    assert target_for_device_type("iis").icon == "web"
    assert get_family(DeviceType.IIS).capabilities.backup
    assert "iis" in SUPPORTED_TECHNOLOGIES

    def asset(name, os_name, type_name):
        return type("A", (), {"manufacturer": None, "os_name": os_name, "os_version": "", "model": None,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()
    assert infer_device_family(asset("WEB01", "Windows Server 2022", "IIS Web Server")) == "iis"
    assert infer_device_family(asset("web2", "Ubuntu 22.04", "Apache Web Server")) == "apache"
    assert family_matches("iis", "windows") and family_matches("windows", "iis")
