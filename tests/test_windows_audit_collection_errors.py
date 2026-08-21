"""
Windows CIS audit: unevaluable checks, result persistence and redaction.

Covers the failure mode where a collection command comes back empty or errored:
the rules used to score that as a verdict (a missing ``secedit /export`` made
every "set to No One" user-rights check read as COMPLIANT), and the redaction
pass used to corrupt the registry JSON it was scanning.
"""

import json
import re

import pytest

from app.models.audit import CheckStatus
from app.modules.windows.audit.audit_commands import get_windows_audit_commands
from app.modules.windows.audit.rules import (
    REGISTRY_CHECKS,
    build_win2025_cis_rules,
    evaluate_compliance,
    get_registry_properties,
    rule_data_failure,
    section_failure,
)
from app.modules.windows.audit.service import WindowsAuditService
from app.modules.windows.audit.winrm_client import redact_sensitive_windows_data


# A dump where everything except the two secedit-backed sections collected fine.
SECEDIT_FAILED_DUMP = "\n".join([
    "===SECTION:OS_VERSION===",
    '{"Caption":"Microsoft Windows Server 2025 Standard","BuildNumber":"26100"}',
    "===SECTION:DOMAIN_ROLE===",
    '{"DomainRole":3,"PartOfDomain":true}',
    "===SECTION:SECURITY_POLICY===",
    "SECEDIT_EXPORT_FAILED",
    "===SECTION:USER_RIGHTS===",
    "SECEDIT_EXPORT_FAILED",
    "===SECTION:AUDIT_POLICY===",
    "System,{guid},Credential Validation,{guid},Success and Failure",
    "===SECTION:REGISTRY===",
    json.dumps({
        r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa":
            json.dumps({"LmCompatibilityLevel": 5}),
    }),
    "===SECTION:FIREWALL_PROFILES===",
    '[{"Name":"Domain","Enabled":true,"DefaultInboundAction":4}]',
    "===SECTION:LOCAL_USERS===",
    '[{"Name":"Guest","Enabled":false,"SID":"S-1-5-21-1-1-1-501"}]',
])


@pytest.fixture(scope="module")
def rules():
    return build_win2025_cis_rules()


# ================================================================== #
#  Section health detection                                          #
# ================================================================== #

class TestSectionFailure:

    @pytest.mark.parametrize("payload", [
        "PS_ERROR: Access is denied",
        "CMD_ERROR: boom",
        "COLLECTION_ERROR: timeout",
        "SECEDIT_EXPORT_FAILED",
        "(no output)",
        "(empty)",
        "",
    ])
    def test_failure_markers_are_detected(self, payload):
        dump = f"===SECTION:SECURITY_POLICY===\n{payload}"
        assert section_failure(dump, "SECURITY_POLICY") is not None

    def test_missing_section_is_a_failure(self):
        assert section_failure("===SECTION:REGISTRY===\n{}", "AUDIT_POLICY") is not None

    def test_real_content_is_not_a_failure(self):
        dump = "===SECTION:SECURITY_POLICY===\n[System Access]\nPasswordHistorySize = 24"
        assert section_failure(dump, "SECURITY_POLICY") is None

    def test_json_section_must_parse(self):
        broken = "===SECTION:REGISTRY===\nSome-Cmdlet : The term is not recognized"
        assert section_failure(broken, "REGISTRY") is not None

        good = '===SECTION:REGISTRY===\n{"HKLM:\\\\X": "{}"}'
        assert section_failure(good, "REGISTRY") is None


class TestRuleDataFailure:

    def test_every_automated_rule_declares_its_sections(self, rules):
        untagged = [r.id for r in rules if not r.manual and not r.data_sections]
        assert untagged == [], f"rules that cannot be marked ERROR: {untagged}"

    def test_user_rights_falls_back_to_the_full_export(self, rules):
        """USER_RIGHTS failing is survivable while SECURITY_POLICY still parses."""
        rule = next(r for r in rules if r.id == "WIN-2025-2.2.1")
        assert rule.data_sections == ["USER_RIGHTS", "SECURITY_POLICY"]

        dump = (
            "===SECTION:USER_RIGHTS===\nSECEDIT_EXPORT_FAILED\n"
            "===SECTION:SECURITY_POLICY===\n[Privilege Rights]\n"
            "SeTrustedCredManAccessPrivilege = \n"
        )
        assert rule_data_failure(dump, rule) is None

        both_failed = (
            "===SECTION:USER_RIGHTS===\nSECEDIT_EXPORT_FAILED\n"
            "===SECTION:SECURITY_POLICY===\nSECEDIT_EXPORT_FAILED\n"
        )
        assert rule_data_failure(both_failed, rule) is not None


# ================================================================== #
#  No verdict without data                                           #
# ================================================================== #

class TestNoVerdictWithoutData:

    def test_empty_dump_scores_nothing(self, rules):
        report = evaluate_compliance("", rules)
        summary = report["summary"]

        assert summary["passed_scored"] == 0
        assert summary["failed_scored"] == 0
        assert summary["total_rules_scored"] == 0
        assert summary["error_checks"] > 0
        assert not [f for f in report["findings"] if f["compliant"]]

    def test_no_one_rights_are_not_compliant_by_default(self, rules):
        """The regression: an absent secedit export read as 'nobody holds it'."""
        report = evaluate_compliance(SECEDIT_FAILED_DUMP, rules)
        by_id = {f["id"]: f for f in report["findings"]}

        for check in ("WIN-2025-2.2.1", "WIN-2025-2.2.4", "WIN-2025-2.2.15"):
            assert by_id[check]["status"] == "error"
            assert by_id[check]["compliant"] is False

    def test_healthy_sections_are_still_scored(self, rules):
        """A partial failure must not blank out the rest of the audit."""
        report = evaluate_compliance(SECEDIT_FAILED_DUMP, rules)
        by_id = {f["id"]: f for f in report["findings"]}

        assert by_id["WIN-2025-2.3.11.7"]["status"] == "pass"   # registry
        assert by_id["WIN-2025-17.1.1"]["status"] == "pass"     # auditpol
        assert by_id["WIN-2025-9.1.1"]["status"] == "pass"      # firewall
        assert report["summary"]["total_rules_scored"] > 0

    def test_error_findings_explain_themselves(self, rules):
        report = evaluate_compliance(SECEDIT_FAILED_DUMP, rules)
        errored = [f for f in report["findings"] if f["status"] == "error"]

        assert errored
        assert all(f.get("error") is True for f in errored)
        assert all("not evaluated" in f["evidence"] for f in errored)

    def test_counters_add_up(self, rules):
        report = evaluate_compliance(SECEDIT_FAILED_DUMP, rules)
        summary = report["summary"]
        buckets = summary["passed_scored"] + summary["failed_scored"] \
            + summary["error_checks"] + summary["manual_checks"]

        assert buckets == len(report["findings"])
        assert summary["total_rules_scored"] == (
            summary["passed_scored"] + summary["failed_scored"]
        )


# ================================================================== #
#  Persistence                                                       #
# ================================================================== #

class _FakeSession:
    """Captures what _bulk_insert_results would write."""

    def __init__(self):
        self.saved = []
        self.commits = 0

    def bulk_save_objects(self, objs):
        self.saved.extend(objs)

    def commit(self):
        self.commits += 1


class TestResultPersistence:

    def test_status_mapping(self):
        db = _FakeSession()
        findings = [
            {"id": "A", "title": "pass", "severity": "high", "level": "L1",
             "compliant": True, "evidence": "e"},
            {"id": "B", "title": "fail", "severity": "high", "level": "L1",
             "compliant": False, "evidence": "e"},
            {"id": "C", "title": "manual", "severity": "low", "level": "L1",
             "compliant": False, "manual": True, "evidence": "e"},
            {"id": "D", "title": "unevaluable", "severity": "high", "level": "L1",
             "compliant": False, "error": True, "evidence": "e"},
        ]
        WindowsAuditService._bulk_insert_results(db, 1, findings)

        got = {r.check_number: r.status for r in db.saved}
        assert got == {
            "A": CheckStatus.PASS,
            "B": CheckStatus.FAIL,
            "C": CheckStatus.NOT_APPLICABLE,
            "D": CheckStatus.ERROR,
        }

    def test_error_rows_are_never_passed(self, rules):
        db = _FakeSession()
        report = evaluate_compliance(SECEDIT_FAILED_DUMP, rules)
        WindowsAuditService._bulk_insert_results(db, 1, report["findings"])

        errored = [f["id"] for f in report["findings"] if f["status"] == "error"]
        rows = {r.check_number: r.status for r in db.saved}
        assert all(rows[cid] is CheckStatus.ERROR for cid in errored)
        assert len(db.saved) == len(report["findings"])


# ================================================================== #
#  Redaction                                                         #
# ================================================================== #

class TestRedaction:

    def test_keeps_the_registry_json_parseable(self):
        """A login banner mentioning a password used to corrupt the whole key."""
        inner = json.dumps({
            "LegalNoticeText": "Do not share your password: ever",
            "EnableLUA": 1,
        })
        raw = json.dumps({r"HKLM:\SOFTWARE\X": inner})

        cleaned = redact_sensitive_windows_data(raw)
        outer = json.loads(cleaned)
        props = json.loads(outer[r"HKLM:\SOFTWARE\X"])

        assert props["EnableLUA"] == 1
        assert "<REDACTED>" in props["LegalNoticeText"]

    def test_a_corrupted_key_would_have_errored_not_failed(self, rules):
        """Guards the interaction: unparseable REGISTRY must not score."""
        dump = "===SECTION:REGISTRY===\nnot json at all"
        rule = next(r for r in rules if r.id == "WIN-2025-2.3.11.7")
        assert rule_data_failure(dump, rule) is not None

    @pytest.mark.parametrize("probe,expected", [
        ("password = hunter2", "password = <REDACTED>"),
        ("Password: 'hunter2'", "Password: '<REDACTED>'"),
        ("-Password hunter2", "-Password <REDACTED>"),
        ("secret=abc123", "secret=<REDACTED>"),
    ])
    def test_still_redacts(self, probe, expected):
        assert redact_sensitive_windows_data(probe) == expected


# ================================================================== #
#  Collection scope                                                  #
# ================================================================== #

WINLOGON = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


def _collected_spec() -> dict:
    """Parse the path=prop|prop spec back out of the generated PowerShell."""
    script = get_windows_audit_commands()["REGISTRY"]
    spec = re.search(r"\$spec = @'\n(.*?)\n'@", script, re.S).group(1)
    out = {}
    for line in spec.split("\n"):
        i = line.index("=")
        out[line[:i]] = line[i + 1:].split("|")
    return out


class TestRegistryCollectionScope:

    def test_only_named_values_are_fetched(self):
        script = get_windows_audit_commands()["REGISTRY"]
        assert "Select-Object * -ExcludeProperty" not in script
        assert "-Name $names" in script

    def test_spec_matches_what_the_rules_read(self):
        assert _collected_spec() == get_registry_properties()

    def test_every_rule_lookup_is_collected(self):
        spec = _collected_spec()
        missing = [
            (c["path"], c["prop"]) for c in REGISTRY_CHECKS
            if c["prop"] not in spec.get(c["path"], [])
        ]
        assert missing == []

    def test_autologon_credentials_are_never_collected(self):
        """Winlogon is audited for AutoAdminLogon and also holds the cleartext
        autologon password; only the audited values may leave the host."""
        props = _collected_spec()[WINLOGON]

        assert "AutoAdminLogon" in props
        for secret in ("DefaultPassword", "DefaultUserName", "DefaultDomainName"):
            assert secret not in props


# ================================================================== #
#  Redaction must not eat audited values                             #
# ================================================================== #

_AUDITED_NAMES = sorted(
    {p for props in get_registry_properties().values() for p in props}
    | {
        "PasswordHistorySize", "MaximumPasswordAge", "MinimumPasswordAge",
        "MinimumPasswordLength", "PasswordComplexity", "ClearTextPassword",
        "LockoutDuration", "LockoutBadCount", "ResetLockoutCount",
    }
)


class TestRedactionPrecision:

    @pytest.mark.parametrize("name", _AUDITED_NAMES)
    def test_audited_values_survive(self, name):
        """Substring matching redacted ClearTextPassword's value, which made
        check 1.1.7 report a false NON-COMPLIANT on every compliant host."""
        for form in (f"{name} = 1", f'{{"{name}":1}}', f'{{\\"{name}\\":\\"1\\"}}'):
            assert redact_sensitive_windows_data(form) == form

    def test_clear_text_password_check_passes_on_a_compliant_host(self, rules):
        dump = (
            "===SECTION:SECURITY_POLICY===\n[System Access]\n"
            "ClearTextPassword = 0\nPasswordHistorySize = 24\n"
        )
        rule = next(r for r in rules if r.id == "WIN-2025-1.1.7")
        assert rule.check_fn(redact_sensitive_windows_data(dump)) is True

    @pytest.mark.parametrize("secret", [
        "DefaultPassword", "DefaultUserName", "Password", "Secret", "ApiKey",
    ])
    def test_secret_names_are_redacted_in_both_json_forms(self, secret):
        plain = f'{{"{secret}":"s3cr3t","EnableLUA":1}}'
        assert "s3cr3t" not in redact_sensitive_windows_data(plain)

        escaped = f'{{\\"{secret}\\":\\"s3cr3t\\"}}'
        assert "s3cr3t" not in redact_sensitive_windows_data(escaped)


# ================================================================== #
#  Firewall enum handling (M3)                                       #
# ================================================================== #

def _fw_dump(**profile) -> str:
    profile.setdefault("Name", "Domain")
    return "===SECTION:FIREWALL_PROFILES===\n" + json.dumps([profile])


class TestFirewallEnums:
    """MSFT_NetFirewallProfile stores these as uint16 GpoBoolean enums with no
    published ValueMap. "Non-zero means on" read a disabled firewall as
    compliant; nothing may be inferred from an unrecognised value."""

    def test_collector_sends_member_names_not_integers(self):
        script = get_windows_audit_commands()["FIREWALL_PROFILES"]
        for field in ("Enabled", "LogBlocked", "LogAllowed", "NotifyOnListen",
                      "DefaultInboundAction", "AllowLocalFirewallRules",
                      "AllowLocalIPsecRules"):
            assert f"[string]$_.{field}" in script, field

    @pytest.mark.parametrize("value,compliant", [
        ("True", True),      # what the collector now sends
        ("False", False),
        ("NotConfigured", False),
        (True, True),        # JSON booleans, as used by the fixtures
        (False, False),
    ])
    def test_firewall_state_verdicts(self, rules, value, compliant):
        rule = next(r for r in rules if r.id == "WIN-2025-9.1.1")
        assert rule.check_fn(_fw_dump(Enabled=value)) is compliant

    def test_a_disabled_profile_is_never_compliant(self, rules):
        """The regression: enum integer 2 (False) satisfied `v != 0`."""
        rule = next(r for r in rules if r.id == "WIN-2025-9.1.1")
        assert rule.check_fn(_fw_dump(Enabled=2)) is False

    @pytest.mark.parametrize("value", [0, 3, 7, "", "wat", None])
    def test_unknown_values_fail_closed(self, rules, value):
        rule = next(r for r in rules if r.id == "WIN-2025-9.1.1")
        assert rule.check_fn(_fw_dump(Enabled=value)) is False

    def test_want_false_checks_are_not_inverted(self, rules):
        """9.x.3 wants NotifyOnListen off — the old int path got this backwards."""
        rule = next(r for r in rules if r.id == "WIN-2025-9.1.3")
        assert rule.check_fn(_fw_dump(NotifyOnListen="False")) is True
        assert rule.check_fn(_fw_dump(NotifyOnListen=2)) is True      # False
        assert rule.check_fn(_fw_dump(NotifyOnListen="True")) is False
        assert rule.check_fn(_fw_dump(NotifyOnListen=1)) is False     # True
        assert rule.check_fn(_fw_dump(NotifyOnListen="NotConfigured")) is False

    def test_log_size_not_configured_is_not_compliant(self, rules):
        """LogMaxSizeKilobytes uses MAXUINT64 for Not Configured; comparing it
        with >= 16384 passed a profile that has no size configured at all."""
        rule = next(r for r in rules if r.id == "WIN-2025-9.1.5")
        assert rule.check_fn(_fw_dump(LogMaxSizeKilobytes="16384")) is True
        assert rule.check_fn(_fw_dump(LogMaxSizeKilobytes="4096")) is False
        assert rule.check_fn(_fw_dump(LogMaxSizeKilobytes=str(2**64 - 1))) is False

    def test_inbound_block_accepts_both_encodings(self, rules):
        rule = next(r for r in rules if r.id == "WIN-2025-9.1.2")
        assert rule.check_fn(_fw_dump(DefaultInboundAction="Block")) is True
        assert rule.check_fn(_fw_dump(DefaultInboundAction=4)) is True
        assert rule.check_fn(_fw_dump(DefaultInboundAction="Allow")) is False
        assert rule.check_fn(_fw_dump(DefaultInboundAction="NotConfigured")) is False
