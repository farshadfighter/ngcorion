# بر اساس کدی که مهندس علیزاده فرستادن ساخته شده
"""
CIS Cisco IOS 15 Benchmark v4.1.1 - Section Mapping

Maps CIS Benchmark section numbers (1.1.1, 1.1.2, etc.) to the internal rule IDs
produced by the audit engine (build_cis_benchmark_rules), which uses the
"CIS-<section>" id scheme. Each rule_id therefore equals "CIS-" + section.
Based on Appendix: CIS Controls v8 IG 3 Mapped Recommendations (pages 210-213)
"""


from typing import List, Dict, Any, Optional


# CIS Benchmark Version
CIS_BENCHMARK_VERSION = "CIS Cisco IOS 15 Benchmark v4.1.1"


# Complete mapping of all CIS sections from the benchmark.
# rule_id matches the id emitted by build_cis_benchmark_rules() in rules.py
# (always "CIS-" + section), which is what audit results are stored under.
CIS_BENCHMARK_SECTIONS: List[Dict[str, str]] = [
    {
        "section": "1.1.1",
        "recommendation": "Enable 'aaa new-model'",
        "rule_id": "CIS-1.1.1",
    },
    {
        "section": "1.1.2",
        "recommendation": "Enable 'aaa authentication login'",
        "rule_id": "CIS-1.1.2",
    },
    {
        "section": "1.1.3",
        "recommendation": "Enable 'aaa authentication enable default'",
        "rule_id": "CIS-1.1.3",
    },
    {
        "section": "1.1.4",
        "recommendation": "Set 'login authentication for 'line con 0'",
        "rule_id": "CIS-1.1.4",
    },
    {
        "section": "1.1.5",
        "recommendation": "Set 'login authentication for 'line tty'",
        "rule_id": "CIS-1.1.5",
    },
    {
        "section": "1.1.6",
        "recommendation": "Set 'login authentication for 'line vty'",
        "rule_id": "CIS-1.1.6",
    },
    {
        "section": "1.1.7",
        "recommendation": "Set 'aaa accounting' to log all privileged use commands using 'commands 15'",
        "rule_id": "CIS-1.1.7",
    },
    {
        "section": "1.1.8",
        "recommendation": "Set 'aaa accounting connection'",
        "rule_id": "CIS-1.1.8",
    },
    {
        "section": "1.1.9",
        "recommendation": "Set 'aaa accounting exec'",
        "rule_id": "CIS-1.1.9",
    },
    {
        "section": "1.1.10",
        "recommendation": "Set 'aaa accounting network'",
        "rule_id": "CIS-1.1.10",
    },
    {
        "section": "1.1.11",
        "recommendation": "Set 'aaa accounting system'",
        "rule_id": "CIS-1.1.11",
    },
    {
        "section": "1.2.1",
        "recommendation": "Set 'privilege 1' for local users",
        "rule_id": "CIS-1.2.1",
    },
    {
        "section": "1.2.2",
        "recommendation": "Set 'transport input ssh' for 'line vty' connections",
        "rule_id": "CIS-1.2.2",
    },
    {
        "section": "1.2.4",
        "recommendation": "Create 'access-list' for use with 'line vty'",
        "rule_id": "CIS-1.2.4",
    },
    {
        "section": "1.2.5",
        "recommendation": "Set 'access-class' for 'line vty'",
        "rule_id": "CIS-1.2.5",
    },
    {
        "section": "1.3.1",
        "recommendation": "Set the 'banner-text' for 'banner exec'",
        "rule_id": "CIS-1.3.1",
    },
    {
        "section": "1.3.2",
        "recommendation": "Set the 'banner-text' for 'banner login'",
        "rule_id": "CIS-1.3.2",
    },
    {
        "section": "1.3.3",
        "recommendation": "Set the 'banner-text' for 'banner motd'",
        "rule_id": "CIS-1.3.3",
    },
    {
        "section": "1.4.1",
        "recommendation": "Set 'password' for 'enable secret'",
        "rule_id": "CIS-1.4.1",
    },
    {
        "section": "1.4.2",
        "recommendation": "Enable 'service password-encryption'",
        "rule_id": "CIS-1.4.2",
    },
    {
        "section": "1.4.3",
        "recommendation": "Set 'username secret' for all local users",
        "rule_id": "CIS-1.4.3",
    },
    {
        "section": "1.5.1",
        "recommendation": "Set 'no snmp-server' to disable SNMP when unused",
        "rule_id": "CIS-1.5.1",
    },
    {
        "section": "1.5.2",
        "recommendation": "Unset 'private' for 'snmp-server community'",
        "rule_id": "CIS-1.5.2",
    },
    {
        "section": "1.5.3",
        "recommendation": "Unset 'public' for 'snmp-server community'",
        "rule_id": "CIS-1.5.3",
    },
    {
        "section": "1.5.4",
        "recommendation": "Do not set 'RW' for any 'snmp-server community'",
        "rule_id": "CIS-1.5.4",
    },
    {
        "section": "1.5.5",
        "recommendation": "Set the ACL for each 'snmp-server community'",
        "rule_id": "CIS-1.5.5",
    },
    {
        "section": "1.5.6",
        "recommendation": "Create an 'access-list' for use with SNMP",
        "rule_id": "CIS-1.5.6",
    },
    {
        "section": "1.5.7",
        "recommendation": "Set 'snmp-server host' when using SNMP",
        "rule_id": "CIS-1.5.7",
    },
    {
        "section": "1.5.8",
        "recommendation": "Set 'snmp-server enable traps snmp'",
        "rule_id": "CIS-1.5.8",
    },
    {
        "section": "1.5.9",
        "recommendation": "Set 'priv' for each 'snmp-server group' using SNMPv3",
        "rule_id": "CIS-1.5.9",
    },
    {
        "section": "1.5.10",
        "recommendation": "Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3",
        "rule_id": "CIS-1.5.10",
    },
    {
        "section": "2.1.1.1.1",
        "recommendation": "Set the 'hostname'",
        "rule_id": "CIS-2.1.1.1.1",
    },
    {
        "section": "2.1.1.1.2",
        "recommendation": "Set the 'ip domain-name'",
        "rule_id": "CIS-2.1.1.1.2",
    },
    {
        "section": "2.1.1.1.3",
        "recommendation": "Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'",
        "rule_id": "CIS-2.1.1.1.3",
    },
    {
        "section": "2.1.1.1.4",
        "recommendation": "Set 'seconds' for 'ip ssh timeout'",
        "rule_id": "CIS-2.1.1.1.4",
    },
    {
        "section": "2.1.1.1.5",
        "recommendation": "Set maximimum value for 'ip ssh authentication-retries'",
        "rule_id": "CIS-2.1.1.1.5",
    },
    {
        "section": "2.1.1.2",
        "recommendation": "Set version 2 for 'ip ssh version'",
        "rule_id": "CIS-2.1.1.2",
    },
    {
        "section": "2.1.2",
        "recommendation": "Set 'no cdp run'",
        "rule_id": "CIS-2.1.2",
    },
    {
        "section": "2.1.3",
        "recommendation": "Set 'no ip bootp server'",
        "rule_id": "CIS-2.1.3",
    },
    {
        "section": "2.1.4",
        "recommendation": "Set 'no service dhcp'",
        "rule_id": "CIS-2.1.4",
    },
    {
        "section": "2.1.5",
        "recommendation": "Set 'no ip identd'",
        "rule_id": "CIS-2.1.5",
    },
    {
        "section": "2.1.6",
        "recommendation": "Set 'service tcp-keepalives-in'",
        "rule_id": "CIS-2.1.6",
    },
    {
        "section": "2.1.8",
        "recommendation": "Set 'no service pad'",
        "rule_id": "CIS-2.1.8",
    },
    {
        "section": "2.2.1",
        "recommendation": "Set 'logging on'",
        "rule_id": "CIS-2.2.1",
    },
    {
        "section": "2.2.2",
        "recommendation": "Set 'buffer size' for 'logging buffered'",
        "rule_id": "CIS-2.2.2",
    },
    {
        "section": "2.2.3",
        "recommendation": "Set 'logging console critical'",
        "rule_id": "CIS-2.2.3",
    },
    {
        "section": "2.2.4",
        "recommendation": "Set IP address for 'logging host'",
        "rule_id": "CIS-2.2.4",
    },
    {
        "section": "2.2.5",
        "recommendation": "Set 'logging trap informational'",
        "rule_id": "CIS-2.2.5",
    },
    {
        "section": "2.2.6",
        "recommendation": "Set 'service timestamps debug datetime'",
        "rule_id": "CIS-2.2.6",
    },
    {
        "section": "2.2.7",
        "recommendation": "Set 'logging source interface'",
        "rule_id": "CIS-2.2.7",
    },
    {
        "section": "2.3.1.1",
        "recommendation": "Set 'ntp authenticate'",
        "rule_id": "CIS-2.3.1.1",
    },
    {
        "section": "2.3.1.2",
        "recommendation": "Set 'ntp authentication-key'",
        "rule_id": "CIS-2.3.1.2",
    },
    {
        "section": "2.3.1.3",
        "recommendation": "Set the 'ntp trusted-key'",
        "rule_id": "CIS-2.3.1.3",
    },
    {
        "section": "2.3.1.4",
        "recommendation": "Set 'key' for each 'ntp server'",
        "rule_id": "CIS-2.3.1.4",
    },
    {
        "section": "2.3.2",
        "recommendation": "Set 'ip address' for 'ntp server'",
        "rule_id": "CIS-2.3.2",
    },
    {
        "section": "2.4.1",
        "recommendation": "Create a single 'interface loopback'",
        "rule_id": "CIS-2.4.1",
    },
    {
        "section": "2.4.2",
        "recommendation": "Set AAA 'source-interface'",
        "rule_id": "CIS-2.4.2",
    },
    {
        "section": "2.4.3",
        "recommendation": "Set 'ntp source' to Loopback Interface",
        "rule_id": "CIS-2.4.3",
    },
    {
        "section": "2.4.4",
        "recommendation": "Set 'ip tftp source-interface' to the Loopback Interface",
        "rule_id": "CIS-2.4.4",
    },
    {
        "section": "3.1.1",
        "recommendation": "Set 'no ip source-route'",
        "rule_id": "CIS-3.1.1",
    },
    {
        "section": "3.1.2",
        "recommendation": "Set 'no ip proxy-arp'",
        "rule_id": "CIS-3.1.2",
    },
    {
        "section": "3.1.3",
        "recommendation": "Set 'no interface tunnel'",
        "rule_id": "CIS-3.1.3",
    },
    {
        "section": "3.1.4",
        "recommendation": "Set 'ip verify unicast source reachable-via'",
        "rule_id": "CIS-3.1.4",
    },
    {
        "section": "3.2.1",
        "recommendation": "Set 'ip access-list extended' to Forbid Private Source Addresses from External Networks",
        "rule_id": "CIS-3.2.1",
    },
    {
        "section": "3.2.2",
        "recommendation": "Set inbound 'ip access-group' on the External Interface",
        "rule_id": "CIS-3.2.2",
    },
    {
        "section": "3.3.1.1",
        "recommendation": "Set 'key chain'",
        "rule_id": "CIS-3.3.1.1",
    },
    {
        "section": "3.3.1.2",
        "recommendation": "Set 'key'",
        "rule_id": "CIS-3.3.1.2",
    },
    {
        "section": "3.3.1.3",
        "recommendation": "Set 'key-string'",
        "rule_id": "CIS-3.3.1.3",
    },
    {
        "section": "3.3.1.4",
        "recommendation": "Set 'address-family ipv4 autonomous-system'",
        "rule_id": "CIS-3.3.1.4",
    },
    {
        "section": "3.3.1.5",
        "recommendation": "Set 'af-interface default'",
        "rule_id": "CIS-3.3.1.5",
    },
    {
        "section": "3.3.1.6",
        "recommendation": "Set 'authentication key-chain'",
        "rule_id": "CIS-3.3.1.6",
    },
    {
        "section": "3.3.1.7",
        "recommendation": "Set 'authentication mode md5'",
        "rule_id": "CIS-3.3.1.7",
    },
    {
        "section": "3.3.1.8",
        "recommendation": "Set 'ip authentication key-chain eigrp'",
        "rule_id": "CIS-3.3.1.8",
    },
    {
        "section": "3.3.1.9",
        "recommendation": "Set 'ip authentication mode eigrp'",
        "rule_id": "CIS-3.3.1.9",
    },
    {
        "section": "3.3.2.1",
        "recommendation": "Set 'authentication message-digest' for OSPF area",
        "rule_id": "CIS-3.3.2.1",
    },
    {
        "section": "3.3.2.2",
        "recommendation": "Set 'ip ospf message-digest-key md5'",
        "rule_id": "CIS-3.3.2.2",
    },
    {
        "section": "3.3.3.1",
        "recommendation": "Set 'key chain'",
        "rule_id": "CIS-3.3.3.1",
    },
    {
        "section": "3.3.3.2",
        "recommendation": "Set 'key'",
        "rule_id": "CIS-3.3.3.2",
    },
    {
        "section": "3.3.3.3",
        "recommendation": "Set 'key-string'",
        "rule_id": "CIS-3.3.3.3",
    },
    {
        "section": "3.3.3.4",
        "recommendation": "Set 'ip rip authentication key-chain'",
        "rule_id": "CIS-3.3.3.4",
    },
    {
        "section": "3.3.3.5",
        "recommendation": "Set 'ip rip authentication mode' to 'md5'",
        "rule_id": "CIS-3.3.3.5",
    },
    {
        "section": "3.3.4.1",
        "recommendation": "Set 'neighbor password'",
        "rule_id": "CIS-3.3.4.1",
    },
]


def get_all_sections() -> List[Dict[str, str]]:
    """Get all CIS benchmark sections."""
    return CIS_BENCHMARK_SECTIONS


def get_section_by_id(section: str) -> Optional[Dict[str, str]]:
    """Get a specific section by its section number."""
    for s in CIS_BENCHMARK_SECTIONS:
        if s["section"] == section:
            return s
    return None


def get_rule_id_for_section(section: str) -> Optional[str]:
    """Get the internal rule ID for a CIS section number."""
    sec = get_section_by_id(section)
    return sec["rule_id"] if sec else None
