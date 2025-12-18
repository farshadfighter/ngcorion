"""
CIS Cisco IOS 15 Benchmark v4.1.1 - Section Mapping

Maps CIS Benchmark section numbers (1.1.1, 1.1.2, etc.) to internal rule IDs.
Based on Appendix: CIS Controls v8 IG 3 Mapped Recommendations (pages 210-213)
"""

from typing import List, Dict, Any, Optional


# CIS Benchmark Version
CIS_BENCHMARK_VERSION = "CIS Cisco IOS 15 Benchmark v4.1.1"


# Complete mapping of all CIS sections from the PDF
# Maps CIS section numbers to internal rule IDs used in cisco_rules.py
CIS_BENCHMARK_SECTIONS: List[Dict[str, str]] = [
    # ============================================
    # SECTION 1: MANAGEMENT PLANE
    # ============================================

    # 1.1 - AAA Configuration
    {"section": "1.1.1", "recommendation": "Enable 'aaa new-model'", "rule_id": "IOS-L1-020"},
    {"section": "1.1.2", "recommendation": "Enable 'aaa authentication login'", "rule_id": "IOS-L1-021"},
    {"section": "1.1.3", "recommendation": "Enable 'aaa authentication enable default'", "rule_id": "IOS-L1-0211"},
    {"section": "1.1.4", "recommendation": "Set 'login authentication for 'line con 0'", "rule_id": "IOS-L1-0212"},
    {"section": "1.1.5", "recommendation": "Set 'login authentication for 'line tty'", "rule_id": "IOS-L1-0213"},
    {"section": "1.1.6", "recommendation": "Set 'login authentication for 'line vty'", "rule_id": "IOS-L1-004"},
    {"section": "1.1.7", "recommendation": "Set 'aaa accounting' to log all privileged use commands using 'commands 15'", "rule_id": "IOS-L1-022"},
    {"section": "1.1.8", "recommendation": "Set 'aaa accounting connection'", "rule_id": "IOS-L1-0221"},
    {"section": "1.1.9", "recommendation": "Set 'aaa accounting exec'", "rule_id": "IOS-L1-0222"},
    {"section": "1.1.10", "recommendation": "Set 'aaa accounting network'", "rule_id": "IOS-L1-0223"},
    {"section": "1.1.11", "recommendation": "Set 'aaa accounting system'", "rule_id": "IOS-L1-0224"},

    # 1.2 - Access Control
    {"section": "1.2.1", "recommendation": "Set 'privilege 1' for local users", "rule_id": "IOS-L1-0061"},
    {"section": "1.2.2", "recommendation": "Set 'transport input ssh' for 'line vty' connections", "rule_id": "IOS-L1-010"},
    {"section": "1.2.4", "recommendation": "Create 'access-list' for use with 'line vty'", "rule_id": "IOS-L1-0031"},
    {"section": "1.2.5", "recommendation": "Set 'access-class' for 'line vty'", "rule_id": "IOS-L1-003"},

    # 1.3 - Banners
    {"section": "1.3.1", "recommendation": "Set the 'banner-text' for 'banner exec'", "rule_id": "IOS-L1-0052"},
    {"section": "1.3.2", "recommendation": "Set the 'banner-text' for 'banner login'", "rule_id": "IOS-L1-0051"},
    {"section": "1.3.3", "recommendation": "Set the 'banner-text' for 'banner motd'", "rule_id": "IOS-L1-005"},

    # 1.4 - Passwords
    {"section": "1.4.1", "recommendation": "Set 'password' for 'enable secret'", "rule_id": "IOS-L1-001"},
    {"section": "1.4.2", "recommendation": "Enable 'service password-encryption'", "rule_id": "IOS-L1-070"},
    {"section": "1.4.3", "recommendation": "Set 'username secret' for all local users", "rule_id": "IOS-L1-071"},

    # 1.5 - SNMP
    {"section": "1.5.1", "recommendation": "Set 'no snmp-server' to disable SNMP when unused", "rule_id": "IOS-L1-0301"},
    {"section": "1.5.2", "recommendation": "Unset 'private' for 'snmp-server community'", "rule_id": "IOS-L1-0302"},
    {"section": "1.5.3", "recommendation": "Unset 'public' for 'snmp-server community'", "rule_id": "IOS-L1-0303"},
    {"section": "1.5.4", "recommendation": "Do not set 'RW' for any 'snmp-server community'", "rule_id": "IOS-L1-0304"},
    {"section": "1.5.5", "recommendation": "Set the ACL for each 'snmp-server community'", "rule_id": "IOS-L1-030B"},
    {"section": "1.5.6", "recommendation": "Create an 'access-list' for use with SNMP", "rule_id": "IOS-L1-0305"},
    {"section": "1.5.7", "recommendation": "Set 'snmp-server host' when using SNMP", "rule_id": "IOS-L1-0306"},
    {"section": "1.5.8", "recommendation": "Set 'snmp-server enable traps snmp'", "rule_id": "IOS-L1-0307"},
    {"section": "1.5.9", "recommendation": "Set 'priv' for each 'snmp-server group' using SNMPv3", "rule_id": "IOS-L1-030A"},
    {"section": "1.5.10", "recommendation": "Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3", "rule_id": "IOS-L1-0308"},

    # ============================================
    # SECTION 2: CONTROL PLANE
    # ============================================

    # 2.1.1 - SSH Configuration
    {"section": "2.1.1.1.1", "recommendation": "Set the 'hostname'", "rule_id": "IOS-L1-0010"},
    {"section": "2.1.1.1.2", "recommendation": "Set the 'ip domain-name'", "rule_id": "IOS-L1-0011"},
    {"section": "2.1.1.1.3", "recommendation": "Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'", "rule_id": "IOS-L1-0120"},
    {"section": "2.1.1.1.4", "recommendation": "Set 'seconds' for 'ip ssh timeout'", "rule_id": "IOS-L1-0112"},
    {"section": "2.1.1.1.5", "recommendation": "Set maximimum value for 'ip ssh authentication-retries'", "rule_id": "IOS-L1-0113"},
    {"section": "2.1.1.2", "recommendation": "Set version 2 for 'ip ssh version'", "rule_id": "IOS-L1-011"},

    # 2.1 - Services
    {"section": "2.1.2", "recommendation": "Set 'no cdp run'", "rule_id": "IOS-L1-080"},
    {"section": "2.1.3", "recommendation": "Set 'no ip bootp server'", "rule_id": "IOS-L1-081"},
    {"section": "2.1.4", "recommendation": "Set 'no service dhcp'", "rule_id": "IOS-L1-082"},
    {"section": "2.1.5", "recommendation": "Set 'no ip identd'", "rule_id": "IOS-L1-083"},
    {"section": "2.1.6", "recommendation": "Set 'service tcp-keepalives-in'", "rule_id": "IOS-L1-084"},
    {"section": "2.1.8", "recommendation": "Set 'no service pad'", "rule_id": "IOS-L1-085"},

    # 2.2 - Logging
    {"section": "2.2.1", "recommendation": "Set 'logging on'", "rule_id": "IOS-L1-0240"},
    {"section": "2.2.2", "recommendation": "Set 'buffer size' for 'logging buffered'", "rule_id": "IOS-L1-0242"},
    {"section": "2.2.3", "recommendation": "Set 'logging console critical'", "rule_id": "IOS-L1-0245"},
    {"section": "2.2.4", "recommendation": "Set IP address for 'logging host'", "rule_id": "IOS-L1-024"},
    {"section": "2.2.5", "recommendation": "Set 'logging trap informational'", "rule_id": "IOS-L1-0243"},
    {"section": "2.2.6", "recommendation": "Set 'service timestamps debug datetime'", "rule_id": "IOS-L1-0241"},
    {"section": "2.2.7", "recommendation": "Set 'logging source interface'", "rule_id": "IOS-L1-0246"},

    # 2.3 - NTP
    {"section": "2.3.1.1", "recommendation": "Set 'ntp authenticate'", "rule_id": "IOS-L1-061"},
    {"section": "2.3.1.2", "recommendation": "Set 'ntp authentication-key'", "rule_id": "IOS-L1-0611"},
    {"section": "2.3.1.3", "recommendation": "Set the 'ntp trusted-key'", "rule_id": "IOS-L1-0612"},
    {"section": "2.3.1.4", "recommendation": "Set 'key' for each 'ntp server'", "rule_id": "IOS-L1-0613"},
    {"section": "2.3.2", "recommendation": "Set 'ip address' for 'ntp server'", "rule_id": "IOS-L2-091"},

    # 2.4 - Loopback
    {"section": "2.4.1", "recommendation": "Create a single 'interface loopback'", "rule_id": "IOS-L2-110"},
    {"section": "2.4.2", "recommendation": "Set AAA 'source-interface'", "rule_id": "IOS-L2-1101"},
    {"section": "2.4.3", "recommendation": "Set 'ntp source' to Loopback Interface", "rule_id": "IOS-L2-1102"},
    {"section": "2.4.4", "recommendation": "Set 'ip tftp source-interface' to the Loopback Interface", "rule_id": "IOS-L2-1103"},

    # ============================================
    # SECTION 3: DATA PLANE
    # ============================================

    # 3.1 - IP Hardening
    {"section": "3.1.1", "recommendation": "Set 'no ip source-route'", "rule_id": "IOS-L1-090"},
    {"section": "3.1.2", "recommendation": "Set 'no ip proxy-arp'", "rule_id": "IOS-L1-091"},
    {"section": "3.1.3", "recommendation": "Set 'no interface tunnel'", "rule_id": "IOS-L1-092"},
    {"section": "3.1.4", "recommendation": "Set 'ip verify unicast source reachable-via'", "rule_id": "IOS-L1-093"},

    # 3.2 - Access Lists
    {"section": "3.2.1", "recommendation": "Set 'ip access-list extended' to Forbid Private Source Addresses from External Networks", "rule_id": "IOS-L1-094"},
    {"section": "3.2.2", "recommendation": "Set inbound 'ip access-group' on the External Interface", "rule_id": "IOS-L1-095"},

    # 3.3.1 - EIGRP Authentication
    {"section": "3.3.1.1", "recommendation": "Set 'key chain'", "rule_id": "IOS-L2-100"},
    {"section": "3.3.1.2", "recommendation": "Set 'key'", "rule_id": "IOS-L2-1001"},
    {"section": "3.3.1.3", "recommendation": "Set 'key-string'", "rule_id": "IOS-L2-1002"},
    {"section": "3.3.1.4", "recommendation": "Set 'address-family ipv4 autonomous-system'", "rule_id": "IOS-L2-1003"},
    {"section": "3.3.1.5", "recommendation": "Set 'af-interface default'", "rule_id": "IOS-L2-1004"},
    {"section": "3.3.1.6", "recommendation": "Set 'authentication key-chain'", "rule_id": "IOS-L2-1005"},
    {"section": "3.3.1.7", "recommendation": "Set 'authentication mode md5'", "rule_id": "IOS-L2-1006"},
    {"section": "3.3.1.8", "recommendation": "Set 'ip authentication key-chain eigrp'", "rule_id": "IOS-L2-1007"},
    {"section": "3.3.1.9", "recommendation": "Set 'ip authentication mode eigrp'", "rule_id": "IOS-L2-1008"},

    # 3.3.2 - OSPF Authentication
    {"section": "3.3.2.1", "recommendation": "Set 'authentication message-digest' for OSPF area", "rule_id": "IOS-L2-101"},
    {"section": "3.3.2.2", "recommendation": "Set 'ip ospf message-digest-key md5'", "rule_id": "IOS-L2-1011"},

    # 3.3.3 - RIP Authentication
    {"section": "3.3.3.1", "recommendation": "Set 'key chain'", "rule_id": "IOS-L2-102"},
    {"section": "3.3.3.2", "recommendation": "Set 'key'", "rule_id": "IOS-L2-1021"},
    {"section": "3.3.3.3", "recommendation": "Set 'key-string'", "rule_id": "IOS-L2-1022"},
    {"section": "3.3.3.4", "recommendation": "Set 'ip rip authentication key-chain'", "rule_id": "IOS-L2-1023"},
    {"section": "3.3.3.5", "recommendation": "Set 'ip rip authentication mode' to 'md5'", "rule_id": "IOS-L2-1024"},

    # 3.3.4 - BGP Authentication
    {"section": "3.3.4.1", "recommendation": "Set 'neighbor password'", "rule_id": "IOS-L2-103"},
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
