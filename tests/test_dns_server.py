"""
Windows DNS Server module (DISA STIG + Microsoft guidance): rules on sample
collector output of a Windows Server 2022 DNS server (tests/dns_sample.py -
built, not captured), collection failures, the remediation templates and
the audit -> fix flow through the benchmark engine against a simulated host.
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
from app.modules.benchmark.rules import evaluate
from app.modules.dns_server import rules as R
from app.modules.dns_server.collect import dns_commands
from app.modules.dns_server.hardening import TEMPLATES
from app.modules.dns_server.spec import SPEC

sys.path.insert(0, str(Path(__file__).parent))
import dns_sample as S  # noqa: E402
from benchmark_fakes import FakeHost, install  # noqa: E402


def run(dump):
    report = evaluate(dump, R.rules_for(dump), R.JSON_SECTIONS)
    return report, {f["id"]: f["status"] for f in report["findings"]}


class TestRules:
    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 32
        assert sum(r.manual for r in rules) == 8
        assert {r.source for r in rules} == {"DISA STIG", "Microsoft"}
        for r in rules:
            assert r.id.startswith("DNS-") and r.severity in ("high", "medium", "low")
            if not r.manual:
                assert set(r.data_sections) <= set(dns_commands())

    def test_collection_reads_no_zone_records_or_keys(self):
        text = " ".join(dns_commands().values())
        assert "Get-DnsServerResourceRecord" not in text
        assert "Export-DnsServerZone" not in text

    @pytest.mark.parametrize("rid, expected", [
        ("DNS-AC-1", "fail"), ("DNS-AC-2", "fail"), ("DNS-AC-3", "pass"),
        ("DNS-AU-1", "pass"), ("DNS-AU-2", "fail"), ("DNS-AU-3", "fail"),
        ("DNS-CM-1", "pass"), ("DNS-CM-2", "fail"), ("DNS-CM-3", "pass"), ("DNS-CM-4", "pass"),
        ("DNS-CM-6", "pass"), ("DNS-CM-7", "pass"), ("DNS-CM-8", "fail"), ("DNS-CM-11", "pass"),
        ("DNS-CM-12", "fail"), ("DNS-SC-1", "fail"), ("DNS-SC-2", "pass"), ("DNS-SC-3", "pass"),
        ("DNS-PR-1", "skipped"),
    ])
    def test_sample_verdicts(self, rid, expected):
        assert run(S.dump())[1][rid] == expected

    def test_reverse_and_secondary_zones_are_not_required_to_be_signed(self):
        names = [z["Name"] for z in R.signable_zones(S.dump())]
        assert "10.in-addr.arpa" not in names and "partner.example.org" not in names

    def test_weak_keys_and_nsec_fail(self):
        zones = S.DATA["DNS_ZONES"][:1]
        weak = [dict(zones[0], Dnssec={"DenialOfExistence": "NSec", "Keys": [
            {"Type": "KeySigningKey", "Algorithm": "RsaSha1", "Length": 2048, "Rollover": False},
            {"Type": "ZoneSigningKey", "Algorithm": "RsaSha256", "Length": 768, "Rollover": True}]})]
        _, st = run(S.dump(DNS_ZONES=weak))
        assert st["DNS-SC-2"] == st["DNS-SC-3"] == st["DNS-SC-4"] == "fail"

    def test_write_access_for_users_fails(self):
        acl = S.DATA["DNS_HOST"]["DnsFolderAcl"] + [{"Identity": "BUILTIN\\Users", "Rights": "CreateFiles, Synchronize", "Type": "Allow"}]
        _, st = run(S.dump(DNS_HOST=S.with_("DNS_HOST", DnsFolderAcl=acl)))
        assert st["DNS-AC-3"] == "fail"

    def test_dhcp_address_fails(self):
        _, st = run(S.dump(DNS_HOST=S.with_("DNS_HOST", Interfaces=[{"Alias": "Ethernet0", "Dhcp": "Enabled"}])))
        assert st["DNS-CM-1"] == "fail"

    def test_rrl_on_2012r2_is_not_evaluated(self):
        _, st = run(S.dump(DNS_SETTINGS=S.with_("DNS_SETTINGS", Rrl="NotSupported")))
        assert st["DNS-CM-8"] == "error"

    def test_failed_section_is_error_not_finding(self):
        from app.modules.benchmark.rules import assemble
        d = assemble(dict(S.sections(), DNS_ZONES="PS_ERROR: Access is denied"))
        _, st = run(d)
        assert st["DNS-AC-1"] == st["DNS-SC-1"] == "error"
        assert st["DNS-CM-6"] == "pass"

    def test_host_without_dns_role_is_refused(self):
        from app.modules.benchmark.rules import assemble
        d = assemble(dict(S.sections(), DNS_SETTINGS="PS_ERROR: The specified module 'DnsServer' was not loaded"))
        with pytest.raises(ValueError, match="DNS Server role is not installed"):
            R.rules_for(d)


class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}

    @pytest.mark.parametrize("cid", ["DNS-AC-1", "DNS-AC-2", "DNS-CM-4", "DNS-SC-1"])
    def test_client_impacting_fixes_need_confirmation(self, cid):
        t = TEMPLATES.get(cid)
        assert t.warning and not TEMPLATES.auto_fixable(cid) and TEMPLATES.missing(cid, {}) == ["CONFIRM"]

    def test_automated_fixes_verify(self):
        for cid, t in TEMPLATES.templates.items():
            if not t.manual_only:
                joined = " ".join(t.verify_statements)
                assert "PASS" in joined and "FAIL" in joined, cid


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
def ctx(db, monkeypatch):
    u = User(username="dns-tester", email="dns-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="DNS Server (test)", category="server")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="DNS01", asset_type_id=t.id, ip_address="10.10.0.53", os_name="Windows Server 2022")
    db.add(a)
    db.flush()
    host = install(monkeypatch, FakeHost(dns_commands(), S.sections(), TEMPLATES, ip=a.ip_address))
    monkeypatch.setattr(SPEC, "save_software", None)
    return db, u, a, host


CREDS = {"windows_username": "CORP\\dnsaudit", "windows_password": "Corp-Pass-1", "winrm_port": 5985, "transport": "ntlm"}


class TestEndToEnd:
    def test_audit_then_fix(self, ctx):
        db, user, asset, host = ctx
        session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
        assert session.status == "completed" and session.device_type == DeviceType.DNS_SERVER
        assert session.compliance_pct == run(S.dump())[0]["summary"]["compliance_pct"]
        before = session.compliance_pct

        svc = BenchmarkHardeningService(SPEC)
        out = svc.batch_execute_selected(db, session.id, asset.id, dict(CREDS), [
            {"check_id": "DNS-AU-3", "parameters": {}},
            {"check_id": "DNS-AC-1", "parameters": {"CONFIRM": "yes"}},
            {"check_id": "DNS-SC-1", "parameters": {}},          # missing confirmation
        ])
        assert out["successful"] == 2 and out["failed"] == 1
        rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
        assert rows["DNS-AU-3"] == rows["DNS-AC-1"] == CheckStatus.PASS
        assert rows["DNS-SC-1"] == CheckStatus.FAIL
        db.refresh(session)
        assert session.compliance_pct > before

    def test_integration(self):
        from app.core.target_catalog import target_for_device_type
        from app.modules.hardening.harden_all.families import get_family
        from app.modules.scheduling.audit_dispatch import SUPPORTED_TECHNOLOGIES
        from app.modules.reports.rule_text import text_for
        assert target_for_device_type("dns_server").icon == "dns"
        assert get_family(DeviceType.DNS_SERVER).label == "Windows DNS Server"
        assert "dns_server" in SUPPORTED_TECHNOLOGIES
        assert text_for("dns_server", "DNS-AC-1")[1]


class TestClassification:
    def _asset(self, name, os_name, type_name):
        return type("A", (), {"manufacturer": None, "os_name": os_name, "os_version": "", "model": None,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()

    def test_windows_dns_server(self):
        from app.utils.device_classification import infer_device_family, infer_device_variant
        a = self._asset("DNS01", "Windows Server 2022", "DNS Server")
        assert infer_device_family(a) == "dns_server" and infer_device_variant(a) == "windows-2022"

    def test_bind_on_linux_stays_linux(self):
        from app.utils.device_classification import infer_device_family
        assert infer_device_family(self._asset("ns1", "Ubuntu 22.04", "DNS Server")) == "linux"

    def test_role_lists(self):
        from app.utils.device_classification import family_matches
        assert family_matches("dns_server", "windows")
        assert family_matches("active_directory", "dns_server")    # DCs usually run DNS
        assert family_matches("windows", "dns_server")
        assert not family_matches("linux", "dns_server")
