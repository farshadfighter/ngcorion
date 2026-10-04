"""
Sophos Firewall module (Sophos's hardening guidance), through the XML API.

No Sophos Firewall is available to the test suite. tests/fake_sophos.py
serves a simulated XML API over real HTTPS (self-signed certificate) with
the request and answer formats of SFOS: the module's own client, TLS
pinning, collection, edits and verification run against it unchanged.
The configuration it serves (tests/sophos_sample.py, element names from
Sophos's API reference and SDK) was written here, not captured.
"""
import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from sqlalchemy.orm import Session

from app.core import tls_pins
from app.core.database import engine as db_engine
from app.models import Asset, AuditResult, User
from app.models.asset_types import AssetType
from app.models.audit import CheckStatus, DeviceType
from app.modules.benchmark import connectors
from app.modules.benchmark.audit_service import BenchmarkAuditService
from app.modules.benchmark.hardening_service import BenchmarkHardeningService, run_template
from app.modules.benchmark.rules import evaluate, section
from app.modules.benchmark.templates import PLACEHOLDER_RE
from app.modules.sophos import rules as R
from app.modules.sophos.api import SophosAPI, SophosAPIError, parse_xml, sfos_version
from app.modules.sophos.collect import collect, redact, redact_element
from app.modules.sophos.edit import SophosConnection
from app.modules.sophos.hardening import TEMPLATES
from app.modules.sophos.spec import SPEC, collect_software

sys.path.insert(0, str(Path(__file__).parent))
import sophos_sample as S  # noqa: E402
from fake_sophos import FakeSophos  # noqa: E402

DUMP = (Path(__file__).parent / "mock_data" / "sophos" / "sfos20_fw01_sample_dump.txt").read_text()
PARAMS = {"CONFIRM": "yes", "LOCKOUT_ATTEMPTS": "5", "MIN_PASSWORD_LENGTH": "14"}


@pytest.fixture
def pins(tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_PINS_FILE", str(tmp_path / "pins.json"))
    return tmp_path / "pins.json"


@pytest.fixture
def fw(pins):
    server = FakeSophos()
    yield server
    server.close()


def creds(fw, **kw):
    return {"sophos_username": S.USERNAME, "sophos_password": S.PASSWORD, "sophos_port": fw.port, **kw}


def run(d=DUMP):
    report = evaluate(d, R.rules_for(d))
    return report, {f["id"]: f["status"] for f in report["findings"]}


def evidence(d, rid):
    return next(f["evidence"] for f in run(d)[0]["findings"] if f["id"] == rid)


class TestRules:
    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 27
        assert sum(r.manual for r in rules) == 7
        assert {r.source for r in rules} == {"Sophos"}

    def test_sample(self):
        report, _ = run()
        assert report["summary"]["error_checks"] == 0
        assert (report["summary"]["passed_scored"], report["summary"]["failed_scored"]) == (4, 16)
        assert R.describe(DUMP) == "SFOS 20.0 (API 2000.1), 3 zones, 5 firewall rules"

    @pytest.mark.parametrize("rid, expected", [
        ("1.1", "fail"), ("1.2", "fail"), ("1.3", "pass"), ("1.4", "fail"), ("1.5", "fail"), ("1.6", "fail"),
        ("1.7", "fail"), ("1.8", "fail"), ("1.9", "fail"), ("2.1", "pass"), ("2.2", "fail"), ("3.1", "pass"),
        ("3.2", "fail"), ("3.4", "fail"), ("4.1", "fail"), ("4.2", "fail"), ("4.3", "pass"), ("4.5", "fail"),
        ("5.1", "fail"), ("5.2", "fail"), ("1.10", "skipped"), ("4.4", "skipped"),
    ])
    def test_verdicts(self, rid, expected):
        assert run()[1][f"SOPHOS-{rid}"] == expected

    def test_evidence(self):
        assert evidence(DUMP, "SOPHOS-1.1") == "enabled on WAN zones: web admin (HTTPS) on WAN"
        assert evidence(DUMP, "SOPHOS-1.4") == "WAN exceptions for HTTPS/SSH: Allow SSH from WAN (vendor) (SSH from any host)"
        assert evidence(DUMP, "SOPHOS-1.7").startswith("complexity check off; minimum length 8")
        assert evidence(DUMP, "SOPHOS-3.4") == "3 allow rules; not logging: LAN to WAN, Any allow (temporary)"
        assert evidence(DUMP, "SOPHOS-4.1") == "any-to-any allow rules: Any allow (temporary)"
        assert evidence(DUMP, "SOPHOS-4.2") == "WAN allow rules without IPS: Web server inbound"
        assert "netops (Administrator, Active)" in evidence(DUMP, "SOPHOS-1.12")
        assert "SFOS 20.0" in evidence(DUMP, "SOPHOS-2.3")

    def test_api_did_not_answer(self):
        with pytest.raises(ValueError, match="did not answer"):
            R.rules_for("===SECTION:VERSION===\nAPI_ERROR: Sophos API login failed")

    def test_versions(self):
        assert [sfos_version(v) for v in ("1905.1", "2000.1", "2100.1", "2150.1", "x")] == \
            ["19.5", "20.0", "21.0", "21.5", "unknown"]


class TestPrivacy:
    def test_secrets_never_stored(self):
        for secret in ("Fw-Api-Pass-1", "Smtp-Secret-9", "public-ro-2019", "$sfos$7"):
            assert secret not in DUMP
        assert "<CommunityString>***</CommunityString>" in DUMP and "<Password>***</Password>" in DUMP
        # Settings about passwords are kept.
        assert "<MinimumPasswordLengthValue>8</MinimumPasswordLengthValue>" in DUMP

    def test_users_cut_down(self):
        user = section(DUMP, "User").split("</User>")[0]
        assert "<Username>admin</Username>" in user and "EmailID" not in user and "Password" not in user

    def test_redaction_rules(self):
        el = ET.fromstring("<X><EncryptionPassword hashform='mode1'>abc</EncryptionPassword><PresharedKey>k</PresharedKey>"
                           "<PasswordComplexityCheck>Enable</PasswordComplexityCheck><tokenAutoCreation>1</tokenAutoCreation></X>")
        out = ET.tostring(redact_element(el), encoding="unicode")
        assert "abc" not in out and ">k<" not in out and "hashform" not in out
        assert "<PasswordComplexityCheck>Enable" in out and "<tokenAutoCreation>1" in out
        assert redact("<SNMPv3User><AuthenticationPassword>p1</AuthenticationPassword></SNMPv3User>") == \
            "<SNMPv3User><AuthenticationPassword>***</AuthenticationPassword></SNMPv3User>"

    def test_xml_with_dtd_refused(self):
        with pytest.raises(SophosAPIError, match="DTD"):
            parse_xml('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><Response>&a;</Response>')


# ── the API client against the simulated firewall ───────────────────────

class TestClient:
    def test_collection_matches_the_stored_sample(self, fw):
        with connectors.CONNECTORS["sophos_api"].open("127.0.0.1", creds(fw)) as conn:
            assert collect(conn) == DUMP
        # The password went in the POST body, never in a URL.
        assert all(path == "/webconsole/APIController" for path, _line in fw.requests)

    def test_wrong_password_and_api_access(self, fw):
        with pytest.raises(PermissionError, match="login failed"):
            with connectors.CONNECTORS["sophos_api"].open("127.0.0.1", creds(fw, sophos_password="nope")):
                pass
        for mode, text in (("api-disabled", "not allowed"), ("ip-not-allowed", "requester IP")):
            fw.mode = mode
            with pytest.raises(PermissionError, match=text):
                SophosAPI("127.0.0.1", fw.port, S.USERNAME, S.PASSWORD).login()

    def test_certificate_is_pinned(self, fw, pins):
        SophosAPI("127.0.0.1", fw.port, S.USERNAME, S.PASSWORD).login()
        pinned = tls_pins.pinned("127.0.0.1", fw.port)
        assert pinned.startswith("SHA256:") and oct(pins.stat().st_mode)[-3:] == "600"
        # A device on the same address that presents another certificate.
        other = FakeSophos()
        try:
            store = json.loads(pins.read_text())
            store[f"[127.0.0.1]:{other.port}"] = pinned
            pins.write_text(json.dumps(store))
            with pytest.raises(tls_pins.TLSPinMismatchError):
                SophosAPI("127.0.0.1", other.port, S.USERNAME, "secret-never-sent").login()
            assert other.requests == []          # nothing - no password - was sent
            assert tls_pins.forget("127.0.0.1", other.port)
            SophosAPI("127.0.0.1", other.port, S.USERNAME, S.PASSWORD).login()
        finally:
            other.close()

    def test_strict_mode_refuses_unknown_devices(self, fw, monkeypatch):
        from app.core.config import settings
        monkeypatch.setattr(settings, "SSH_HOST_KEY_POLICY", "strict")
        with pytest.raises(tls_pins.TLSPinUnknownError):
            SophosAPI("127.0.0.1", fw.port, S.USERNAME, S.PASSWORD).login()

    def test_no_records(self, fw):
        assert SophosAPI("127.0.0.1", fw.port, S.USERNAME, S.PASSWORD).get("SNMPv3User") == []


# ── fixes against the simulated firewall ────────────────────────────────

class TestFixes:
    def test_every_fix_applies_and_verifies(self, fw):
        with connectors.CONNECTORS["sophos_api"].open("127.0.0.1", creds(fw)) as conn:
            results = {cid: run_template(SPEC, conn, cid, PARAMS) for cid, t in TEMPLATES.templates.items()
                       if not t.manual_only}
            assert all(r["success"] for r in results.values()), {k: r for k, r in results.items() if not r["success"]}
            after = run(collect(conn))[1]
            assert all(after[cid] == "pass" for cid in results)
            assert sorted(k for k, v in after.items() if v == "fail") == [
                "SOPHOS-1.4", "SOPHOS-1.9", "SOPHOS-4.1", "SOPHOS-4.2", "SOPHOS-4.5", "SOPHOS-5.1", "SOPHOS-5.2"]
            # Again: nothing left to change.
            sets = len(fw.sets)
            assert all(run_template(SPEC, conn, cid, PARAMS)["success"] for cid in results)
            assert len(fw.sets) == sets

    def test_only_named_fields_change(self, fw):
        with connectors.CONNECTORS["sophos_api"].open("127.0.0.1", creds(fw)) as conn:
            run_template(SPEC, conn, "SOPHOS-1.1", PARAMS)
        wan = next(z for z in fw.state["Zone"] if z.findtext("Name") == "WAN")
        assert wan.findtext("ApplianceAccess/AdminServices/HTTPS") == "Disable"
        assert wan.findtext("ApplianceAccess/VPNServices/IPsec") == "Enable"      # untouched
        assert wan.findtext("ApplianceAccess/OtherServices/UserPortal") == "Enable"
        lan = next(z for z in fw.state["Zone"] if z.findtext("Name") == "LAN")
        assert lan.findtext("ApplianceAccess/AdminServices/HTTPS") == "Enable"    # other zones too
        # AdminSettings edits send only their section, as the web admin does.
        with connectors.CONNECTORS["sophos_api"].open("127.0.0.1", creds(fw)) as conn:
            run_template(SPEC, conn, "SOPHOS-1.5", PARAMS)
        sent = ET.fromstring(fw.sets[-1])
        assert [c.tag for c in sent] == ["LoginSecurity"]
        assert fw.state["AdminSettings"][0].findtext("WebAdminSettings/HTTPSport") == "4444"

    def test_fields_the_firmware_lacks_are_not_invented(self, fw):
        wan = next(z for z in fw.state["Zone"] if z.findtext("Name") == "WAN")
        other = wan.find("ApplianceAccess/OtherServices")
        other.remove(other.find("SMTPRelay"))      # an older firmware without SMTP relay
        with connectors.CONNECTORS["sophos_api"].open("127.0.0.1", creds(fw)) as conn:
            assert run_template(SPEC, conn, "SOPHOS-1.3", PARAMS)["success"]
        assert wan.find("ApplianceAccess/OtherServices/SMTPRelay") is None

    def test_refused_change_is_reported(self, fw):
        conn = SophosConnection(SophosAPI("127.0.0.1", fw.port, S.USERNAME, S.PASSWORD))
        with pytest.raises(SophosAPIError, match="refused: 500"):
            conn.execute("SFOS:set AdminSettings LoginSecurity NoSuchField=1")
        assert conn.run("SFOS:set Nothing - a=1") == "API_ERROR: Get Nothing: 541 Operation not supported."


class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}
        auto = [cid for cid, t in TEMPLATES.templates.items() if not t.manual_only]
        assert len(auto) == 12
        assert all(TEMPLATES.templates[c].verify_statements == [f"SFOS:check {c}"] for c in auto)
        for rid in ("SOPHOS-1.9", "SOPHOS-1.4", "SOPHOS-4.2", "SOPHOS-1.10"):
            assert TEMPLATES.templates[rid].manual_only

    def test_parameters(self):
        for rid in ("SOPHOS-1.1", "SOPHOS-1.2", "SOPHOS-1.3", "SOPHOS-3.2"):
            assert TEMPLATES.missing(rid, {}) == ["CONFIRM"], rid
        assert TEMPLATES.validate("SOPHOS-1.6", {"LOCKOUT_ATTEMPTS": "9"})
        assert TEMPLATES.validate("SOPHOS-1.7", {"MIN_PASSWORD_LENGTH": "8"})
        for cid, t in TEMPLATES.templates.items():
            leftovers = {m for s in t.statements + t.verify_statements for m in PLACEHOLDER_RE.findall(s)}
            assert leftovers <= {"{" + p + "}" for p in t.parameters}, cid


# ── through the engine and the database ─────────────────────────────────

@pytest.fixture
def ctx(fw, monkeypatch):
    connection = db_engine.connect()
    trans = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    u = User(username="sophos-tester", email="sophos-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="Sophos XGS (test)", category="network")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="FW01", asset_type_id=t.id, ip_address="127.0.0.1", os_name="SFOS 20.0")
    db.add(a)
    db.flush()
    monkeypatch.setattr(SPEC, "save_software", None)
    try:
        yield db, u, a
    finally:
        db.close()
        trans.rollback()
        connection.close()


def test_audit_then_fix(ctx, fw):
    db, user, asset = ctx
    c = creds(fw)
    session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(c))
    assert session.status == "completed" and session.device_type == DeviceType.SOPHOS
    assert session.passed_checks == 4 and session.failed_checks == 16
    out = BenchmarkHardeningService(SPEC).batch_execute_selected(db, session.id, asset.id, dict(c), [
        {"check_id": "SOPHOS-1.5", "parameters": {}}, {"check_id": "SOPHOS-1.1", "parameters": {"CONFIRM": "yes"}},
        {"check_id": "SOPHOS-1.7", "parameters": {"MIN_PASSWORD_LENGTH": "14"}},
        {"check_id": "SOPHOS-1.9", "parameters": {}}])
    assert out["successful"] == 3 and out["failed"] == 1
    rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
    assert rows["SOPHOS-1.5"] == rows["SOPHOS-1.1"] == rows["SOPHOS-1.7"] == CheckStatus.PASS
    assert rows["SOPHOS-1.9"] == CheckStatus.FAIL


def test_software(fw):
    with connectors.CONNECTORS["sophos_api"].open("127.0.0.1", creds(fw)) as conn:
        item = collect_software(conn)
    assert (item["name"], item["version"], item["kind"]) == ("Sophos Firewall OS", "20.0", "firmware")


def test_integration_and_classification():
    from app.core.target_catalog import target_for_device_type
    from app.modules.benchmark.registry import spec_map
    from app.modules.hardening.harden_all.families import get_family
    from app.modules.scheduling.audit_dispatch import REQUIRED_PARAMS, SUPPORTED_TECHNOLOGIES
    from app.utils.device_classification import family_matches, infer_device_family
    assert spec_map()["sophos"] is SPEC
    t = target_for_device_type("sophos")
    assert t.category == "network" and t.icon == "firewall" and t.connects_via == "HTTPS API"
    assert {f.name for f in get_family(DeviceType.SOPHOS).credential_fields} == \
        {"sophos_username", "sophos_password", "sophos_port"}
    assert "sophos" in SUPPORTED_TECHNOLOGIES and REQUIRED_PARAMS["sophos"] == {"sophos_username", "sophos_password"}

    def asset(name, os_name, manufacturer=None, type_name="Firewall"):
        return type("A", (), {"manufacturer": manufacturer, "os_name": os_name, "os_version": "", "model": None,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()
    assert infer_device_family(asset("fw01", "SFOS 20.0", "Sophos")) == "sophos"
    assert infer_device_family(asset("fw02", "FortiOS 7.4", "Fortinet")) == "fortinet"
    assert not family_matches("fortinet", "sophos")
