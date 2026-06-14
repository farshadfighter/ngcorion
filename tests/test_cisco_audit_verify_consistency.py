"""
Regression tests for the Cisco audit/hardening consistency bugs.

Symptom reported: a check is hardened, hardening verification reports PASS, but a
fresh audit then reports the same check as FAIL (or, for routing/SNMP, as a
vacuous SUCCESS).

Two root causes were fixed:

1. The audit collected a narrow "show run | include/section ..." grep subset
   while hardening verification evaluated the full "show running-config". Lines
   captured by one view but not the other (e.g. "banner exec", "service
   timestamps debug", interface sub-commands, "ip access-list ...") flipped a
   check's result between verify and the next audit; protocol checks whose
   trigger line ("router eigrp/ospf/bgp") was never grepped reported a vacuous
   PASS. Both sides now share CiscoSSHClient.collect_config_dump() (full
   running-config + the supplemental non-running-config show commands).

2. The audit evaluated checks against the REDACTED dump, so e.g.
   "snmp-server community private" became "snmp-server community <REDACTED>" and
   the no-private/no-public SNMP checks falsely PASSed. Checks now run on the raw
   config; only the stored dump and per-finding evidence are redacted.

Pure-logic tests: no SSH/device, no DB.
"""

import pytest

from app.modules.cisco.audit.ssh_client import (
    CiscoSSHClient,
    redact_sensitive_data,
    CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS,
    CISCO_TURBO_COMMANDS,
)
from app.modules.cisco.audit.rules import build_cis_benchmark_rules

RULES = {r.id: r for r in build_cis_benchmark_rules()}

# A full post-hardening running-config (what the audit now collects), including
# the lines that the old narrow grep set dropped.
POST_FIX_CONFIG = """\
hostname RTR01
ip domain-name example.com
aaa new-model
aaa authentication login VTYAUTH group tacacs+ local
aaa accounting commands 15 default start-stop group tacacs+
service password-encryption
service timestamps debug datetime msec show-timezone
service timestamps log datetime msec show-timezone
no ip source-route
no cdp run
enable secret 9 $9$abcHASH
banner exec ^Authorized access only^
banner motd ^Authorized access only^
logging buffered 16384
logging console critical
logging host 192.0.2.5
logging source-interface Loopback0
ip access-list standard VTY-ACL
 permit 192.0.2.0 0.0.0.255
 deny   any log
ip access-list extended BORDER-IN
 deny   ip 10.0.0.0 0.255.255.255 any log
 permit ip any any
interface GigabitEthernet0/0
 ip access-group BORDER-IN in
 ip verify unicast source reachable-via rx
line vty 0 4
 access-class VTY-ACL in
 transport input ssh
 login authentication VTYAUTH
line vty 5 15
 access-class VTY-ACL in
 transport input ssh
 login authentication VTYAUTH
"""

# An insecure device: routing protocols and SNMP defaults present, unauthenticated.
INSECURE_CONFIG = """\
hostname RTR
interface GigabitEthernet0/0
 ip address 1.2.3.4 255.255.255.0
router eigrp 100
 network 10.0.0.0
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
router bgp 65000
 neighbor 1.1.1.1 remote-as 65001
snmp-server community private RO
snmp-server community public RO
"""


def test_collect_config_dump_exists():
    """The shared collection method that makes audit == verify must exist."""
    assert hasattr(CiscoSSHClient, "collect_config_dump")


def test_supplemental_is_non_running_config_only():
    """Verify's supplemental set must contain only non-'show run' commands; every
    'show run | ...' view is already covered by the full running-config."""
    assert CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS
    assert all(not c.strip().lower().startswith("show run")
               for c in CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS)
    # and it really is a strict subset of the full turbo set
    assert set(CISCO_NON_RUNNING_CONFIG_TURBO_COMMANDS) <= set(CISCO_TURBO_COMMANDS)


# Checks that used to verify PASS but re-audit FAIL because their config line was
# not in the audit's grep subset. They must pass on the full post-fix config.
@pytest.mark.parametrize("check_number", [
    "CIS-1.2.2",   # transport input ssh (line vty)
    "CIS-1.2.4",   # ip access-list standard (vty acl)
    "CIS-1.2.5",   # access-class in (line vty)
    "CIS-1.3.1",   # banner exec  (grep only had motd|login)
    "CIS-2.2.3",   # logging console critical
    "CIS-2.2.6",   # service timestamps debug datetime (grep only had 'log')
    "CIS-2.2.7",   # logging source-interface
    "CIS-3.1.4",   # ip verify unicast (interface sub-command)
    "CIS-3.2.1",   # ip access-list extended
    "CIS-3.2.2",   # ip access-group in (interface sub-command)
])
def test_hardened_checks_pass_on_full_config(check_number):
    assert RULES[check_number].check(POST_FIX_CONFIG) is True


# Routing checks that used to vacuously PASS because the audit never grepped the
# "router ..." trigger line. On an unauthenticated config they must FAIL.
@pytest.mark.parametrize("check_number", [
    "CIS-3.3.1.1",  # eigrp key chain
    "CIS-3.3.1.6",  # eigrp authentication key-chain
    "CIS-3.3.1.7",  # eigrp authentication mode md5
    "CIS-3.3.2.1",  # ospf area authentication message-digest
    "CIS-3.3.4.1",  # bgp neighbor password
])
def test_routing_checks_fail_when_unauthenticated(check_number):
    assert RULES[check_number].check(INSECURE_CONFIG) is False


@pytest.mark.parametrize("check_number", ["CIS-1.5.2", "CIS-1.5.3"])
def test_snmp_default_communities_detected_on_raw_config(check_number):
    """private/public communities must be detected (they used to be masked to
    <REDACTED> before the check ran, producing a false PASS)."""
    assert RULES[check_number].check(INSECURE_CONFIG) is False
    # And redaction would indeed have hidden them — proving the bug was real and
    # why checks must run on the raw config.
    assert RULES[check_number].check(redact_sensitive_data(INSECURE_CONFIG)) is True


def test_redaction_masks_full_config_secrets():
    """The audit now stores the full running-config, so redaction must mask the
    secret-bearing lines a full config exposes."""
    sample = (
        "enable secret 9 $9$abc\n"
        "line con 0\n"
        " password 7 0822455D0A16\n"
        "key chain KC\n"
        " key 1\n"
        "  key-string 7 13061E010803\n"
        "snmp-server community private RO\n"
        "ntp authentication-key 1 md5 sUperSecret\n"
        "crypto isakmp key MyPSK address 1.2.3.4\n"
        "router bgp 65000\n"
        " neighbor 1.1.1.1 password 7 02050D480809\n"
        "ip ftp password 7 070C285F4D06\n"
        "interface Gi0/0\n"
        " ppp chap password 7 121A0C041104\n"
        " ip address 1.2.3.4 255.255.255.0\n"
        " description uplink\n"
    )
    out = redact_sensitive_data(sample)
    for secret in ("$9$abc", "0822455D0A16", "13061E010803", "sUperSecret",
                   "MyPSK", "02050D480809", "070C285F4D06", "121A0C041104"):
        assert secret not in out, f"secret leaked: {secret}"
    # non-secret operational config must be preserved
    assert "ip address 1.2.3.4 255.255.255.0" in out
    assert "description uplink" in out
    # crypto isakmp key masks only the key, not the peer address
    assert "crypto isakmp key <REDACTED> address 1.2.3.4" in out
