"""
Windows DHCP Server module (Microsoft guidance): rules on sample collector
output of a Windows Server 2022 DHCP server (tests/dhcp_sample.py - built,
not captured), collection failures, templates, and the audit -> fix flow
against a simulated host.
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
from app.modules.dhcp_server import rules as R
from app.modules.dhcp_server.collect import dhcp_commands
from app.modules.dhcp_server.hardening import TEMPLATES
from app.modules.dhcp_server.spec import SPEC

sys.path.insert(0, str(Path(__file__).parent))
import dhcp_sample as S  # noqa: E402
from benchmark_fakes import FakeHost, install  # noqa: E402


def run(dump):
    report = evaluate(dump, R.rules_for(dump), R.JSON_SECTIONS)
    return report, {f["id"]: f["status"] for f in report["findings"]}


class TestRules:
    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 22
        assert sum(r.manual for r in rules) == 5
        assert all(r.source == "Microsoft" for r in rules)

    def test_collection_reads_no_leases(self):
        text = " ".join(dhcp_commands().values())
        assert "Get-DhcpServerv4Lease" not in text and "Get-DhcpServerv4Reservation" not in text

    @pytest.mark.parametrize("rid, expected", [
        ("DHCP-AU-1", "pass"), ("DHCP-DN-1", "fail"), ("DHCP-DN-2", "fail"), ("DHCP-DN-3", "fail"),
        ("DHCP-DN-4", "pass"), ("DHCP-LG-1", "pass"), ("DHCP-LG-2", "pass"), ("DHCP-AV-1", "fail"),
        ("DHCP-AV-2", "fail"), ("DHCP-AV-3", "fail"), ("DHCP-AV-4", "fail"), ("DHCP-AV-5", "fail"),
        ("DHCP-AV-6", "pass"), ("DHCP-AC-1", "pass"), ("DHCP-AC-2", "fail"), ("DHCP-AC-3", "pass"),
        ("DHCP-AC-4", "pass"), ("DHCP-PR-2", "skipped"),
    ])
    def test_sample_verdicts(self, rid, expected):
        assert run(S.dump())[1][rid] == expected

    def test_inactive_scopes_need_no_failover(self):
        _, st = run(S.dump())
        report = evaluate(S.dump(), R.rules_for(S.dump()), R.JSON_SECTIONS)
        ev = next(f["evidence"] for f in report["findings"] if f["id"] == "DHCP-AV-1")
        assert "10.30.0.0" in ev and "10.40.0.0" not in ev

    def test_workgroup_server_needs_no_authorisation(self):
        _, st = run(S.dump(DHCP_SETTINGS=S.with_("DHCP_SETTINGS", IsDomainJoined=False, IsAuthorized=False)))
        assert st["DHCP-AU-1"] == "pass"

    def test_unauthorised_domain_server_fails(self):
        _, st = run(S.dump(DHCP_SETTINGS=S.with_("DHCP_SETTINGS", IsAuthorized=False)))
        assert st["DHCP-AU-1"] == "fail"

    def test_on_a_dc(self):
        _, st = run(S.dump(DOMAIN_ROLE={"DomainRole": 5}))
        assert st["DHCP-AC-3"] == "fail"

    def test_unreadable_group_is_not_evaluated(self):
        _, st = run(S.dump(DHCP_HOST=S.with_("DHCP_HOST", DhcpUsers=["ERROR: Access is denied"])))
        assert st["DHCP-AC-2"] == "error" and st["DHCP-AC-1"] == "pass"

    def test_failed_section_is_error(self):
        d = assemble(dict(S.sections(), DHCP_SETTINGS="PS_ERROR: Access is denied"))
        _, st = run(d)
        assert st["DHCP-DN-1"] == st["DHCP-AV-1"] == "error" and st["DHCP-AV-6"] == "pass"

    def test_host_without_dhcp_role_is_refused(self):
        d = assemble(dict(S.sections(), DHCP_SETTINGS="PS_ERROR: The specified module 'DhcpServer' was not loaded"))
        with pytest.raises(ValueError, match="DHCP Server role is not installed"):
            R.rules_for(d)


class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}

    def test_authorisation_needs_confirmation(self):
        assert TEMPLATES.missing("DHCP-AU-1", {}) == ["CONFIRM"]

    def test_no_template_takes_a_secret(self):
        for t in TEMPLATES.templates.values():
            assert "SharedSecret" not in " ".join(t.statements)
            assert "Credential" not in " ".join(t.statements)


@pytest.fixture
def ctx(monkeypatch):
    connection = db_engine.connect()
    trans = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    u = User(username="dhcp-tester", email="dhcp-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="DHCP Server (test)", category="server")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="DHCP01", asset_type_id=t.id, ip_address="10.10.0.67", os_name="Windows Server 2022")
    db.add(a)
    db.flush()
    host = install(monkeypatch, FakeHost(dhcp_commands(), S.sections(), TEMPLATES, ip=a.ip_address))
    monkeypatch.setattr(SPEC, "save_software", None)
    try:
        yield db, u, a, host
    finally:
        db.close()
        trans.rollback()
        connection.close()


CREDS = {"windows_username": "CORP\\dhcpaudit", "windows_password": "Corp-Pass-1", "winrm_port": 5985, "transport": "ntlm"}


def test_audit_then_fix(ctx):
    db, user, asset, host = ctx
    session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
    assert session.status == "completed" and session.device_type == DeviceType.DHCP_SERVER
    out = BenchmarkHardeningService(SPEC).batch_execute_selected(db, session.id, asset.id, dict(CREDS), [
        {"check_id": "DHCP-DN-2", "parameters": {}}, {"check_id": "DHCP-AV-5", "parameters": {}},
        {"check_id": "DHCP-DN-1", "parameters": {}}])
    assert out["successful"] == 2 and out["failed"] == 1
    rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
    assert rows["DHCP-DN-2"] == rows["DHCP-AV-5"] == CheckStatus.PASS
    assert rows["DHCP-DN-1"] == CheckStatus.FAIL


def test_integration_and_classification():
    from app.core.target_catalog import target_for_device_type
    from app.modules.hardening.harden_all.families import get_family
    from app.modules.scheduling.audit_dispatch import SUPPORTED_TECHNOLOGIES
    from app.utils.device_classification import family_matches, infer_device_family
    assert target_for_device_type("dhcp_server").icon == "dhcp"
    assert get_family(DeviceType.DHCP_SERVER).capabilities.backup
    assert "dhcp_server" in SUPPORTED_TECHNOLOGIES

    def asset(name, os_name, type_name):
        return type("A", (), {"manufacturer": None, "os_name": os_name, "os_version": "", "model": None,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()
    assert infer_device_family(asset("DHCP01", "Windows Server 2022", "DHCP Server")) == "dhcp_server"
    assert infer_device_family(asset("dhcp1", "Rocky Linux 9", "DHCP Server")) == "linux"
    assert family_matches("dhcp_server", "windows") and family_matches("windows", "dhcp_server")
