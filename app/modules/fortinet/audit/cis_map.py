"""
FortiGate CIS Benchmark Mapping

Maps FortiGate security controls to CIS Benchmark sections.
Based on CIS FortiGate Benchmark recommendations.
"""

from typing import List, Dict, Any

# CIS Benchmark version
CIS_BENCHMARK_VERSION = "Fortinet FortiGate Best Practices v1.0"

# CIS Benchmark sections mapped to control IDs
CIS_BENCHMARK_SECTIONS: List[Dict[str, str]] = [
    # Management Access
    {"section": "1.1.1", "recommendation": "Ensure HTTPS is enabled for admin access", "rule_id": "FG-BL-001"},
    {"section": "1.1.2", "recommendation": "Ensure HTTP is disabled for admin access", "rule_id": "FG-BL-002"},
    {"section": "1.1.3", "recommendation": "Ensure Telnet is disabled for admin access", "rule_id": "FG-BL-003"},

    # Session Management
    {"section": "1.2.1", "recommendation": "Ensure admin idle timeout is set to 10 minutes or less", "rule_id": "FG-BL-004"},

    # Cryptography
    {"section": "1.3.1", "recommendation": "Ensure TLS 1.0/1.1 is disabled for admin GUI", "rule_id": "FG-BL-005"},
    {"section": "1.3.2", "recommendation": "Ensure weak SSH ciphers are disabled", "rule_id": "FG-BL-006"},
    {"section": "1.4.1", "recommendation": "Ensure strong cryptography is enforced", "rule_id": "FG-BL-090"},

    # Access Control
    {"section": "2.1.1", "recommendation": "Ensure admin trusthosts are configured", "rule_id": "FG-BL-020"},
    {"section": "2.1.2", "recommendation": "Ensure default 'admin' account is disabled or renamed", "rule_id": "FG-BL-021"},

    # Authentication
    {"section": "2.2.1", "recommendation": "Ensure multi-factor authentication is configured", "rule_id": "FG-BL-022"},

    # Password Policy
    {"section": "2.3.1", "recommendation": "Ensure password policy is enabled", "rule_id": "FG-BL-030"},
    {"section": "2.3.2", "recommendation": "Ensure password minimum length is 12 or more", "rule_id": "FG-BL-031"},
    {"section": "2.3.3", "recommendation": "Ensure password must contain uppercase", "rule_id": "FG-BL-032"},
    {"section": "2.3.4", "recommendation": "Ensure password must contain lowercase", "rule_id": "FG-BL-033"},
    {"section": "2.3.5", "recommendation": "Ensure password must contain numbers", "rule_id": "FG-BL-034"},
    {"section": "2.3.6", "recommendation": "Ensure password must contain special characters", "rule_id": "FG-BL-035"},
    {"section": "2.3.7", "recommendation": "Ensure minimum changed characters is 4 or more", "rule_id": "FG-BL-036"},

    # Time Services
    {"section": "3.1.1", "recommendation": "Ensure NTP is enabled", "rule_id": "FG-BL-040"},
    {"section": "3.1.2", "recommendation": "Ensure NTP server is configured", "rule_id": "FG-BL-041"},

    # SNMP
    {"section": "4.1.1", "recommendation": "Ensure SNMPv2 communities are removed", "rule_id": "FG-BL-050"},
    {"section": "4.1.2", "recommendation": "Ensure SNMPv3 is configured", "rule_id": "FG-BL-051"},

    # Logging
    {"section": "5.1.1", "recommendation": "Ensure remote syslog is enabled", "rule_id": "FG-BL-060"},
    {"section": "5.1.2", "recommendation": "Ensure remote syslog server is configured", "rule_id": "FG-BL-061"},

    # Firewall Policy
    {"section": "6.1.1", "recommendation": "Ensure no 'Any/Any/ALL' ACCEPT policies exist", "rule_id": "FG-BL-080"},
    {"section": "6.2.1", "recommendation": "Ensure policy logging is enabled", "rule_id": "FG-BL-082"},

    # Interface Security
    {"section": "7.1.1", "recommendation": "Ensure management services are not accessible from WAN", "rule_id": "FG-BL-WAN-HTTP"},
    {"section": "7.2.1", "recommendation": "Ensure local-in-policy is configured", "rule_id": "FG-LIP-001"},

    # VPN
    {"section": "8.1.1", "recommendation": "Ensure SSL-VPN uses TLS 1.2 or higher", "rule_id": "FG-VPN-SSL-001"},
    {"section": "8.2.1", "recommendation": "Ensure IPsec uses strong encryption proposals", "rule_id": "FG-VPN-IPSEC-001"},

    # UTM
    {"section": "9.1.1", "recommendation": "Ensure UTM profiles are enabled on policies", "rule_id": "FG-UTM-001"},
]


def get_cis_section_by_id(cis_id: str) -> Dict[str, str]:
    """Get CIS benchmark section details by CIS ID"""
    for section in CIS_BENCHMARK_SECTIONS:
        if section["section"] == cis_id:
            return section
    return {}


def get_cis_sections_by_domain(domain: str) -> List[Dict[str, str]]:
    """Get all CIS sections for a domain"""
    # Domain mapping based on section numbers
    domain_prefixes = {
        "Management Access": ["1.1"],
        "Session Management": ["1.2"],
        "Cryptography": ["1.3", "1.4"],
        "Identity & Access": ["2."],
        "Time & Sync": ["3."],
        "Network Services": ["4."],
        "Logging & Monitoring": ["5."],
        "Firewall Policy": ["6."],
        "Management Exposure": ["7."],
        "VPN": ["8."],
        "Security Profiles": ["9."],
    }

    prefixes = domain_prefixes.get(domain, [])
    return [
        section for section in CIS_BENCHMARK_SECTIONS
        if any(section["section"].startswith(prefix) for prefix in prefixes)
    ]


def get_all_cis_controls() -> List[str]:
    """Get list of all control IDs that map to CIS benchmarks"""
    return [section["rule_id"] for section in CIS_BENCHMARK_SECTIONS]


def group_by_cis_section() -> Dict[str, List[Dict[str, str]]]:
    """Group CIS sections by major category"""
    groups = {}
    for section in CIS_BENCHMARK_SECTIONS:
        major = section["section"].split(".")[0]
        category_names = {
            "1": "Management Plane Security",
            "2": "Identity & Access Management",
            "3": "Time Services",
            "4": "Network Services",
            "5": "Logging & Monitoring",
            "6": "Firewall Policy",
            "7": "Interface & Management Exposure",
            "8": "VPN Security",
            "9": "Unified Threat Management"
        }
        category = category_names.get(major, f"Category {major}")

        if category not in groups:
            groups[category] = []
        groups[category].append(section)

    return groups
