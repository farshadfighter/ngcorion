"""
FortiGate CIS Benchmark Mapping

Authoritative mapping of the official CIS FortiGate Benchmark checklist sections
to the internal control IDs that back them (see rules.py). The "type" field is
the benchmark's own classification (Automated / Manual). Manual recommendations
are evidence-only and excluded from the compliance score (see
FortiGateControl.is_manual).
"""

from typing import List, Dict, Any, Optional

# CIS Benchmark version
CIS_BENCHMARK_VERSION = "CIS Fortinet FortiGate Benchmark"

# Official CIS FortiGate Benchmark sections mapped to backing control IDs.
# Each entry: section, recommendation (from the benchmark), type, rule_id.
CIS_BENCHMARK_SECTIONS: List[Dict[str, str]] = [
    # 1 Network Settings
    {"section": "1.1", "recommendation": "Ensure DNS server is configured", "type": "Automated", "rule_id": "FG-BL-043"},
    {"section": "1.2", "recommendation": "Ensure intra-zone traffic is not always allowed", "type": "Manual", "rule_id": "FG-NET-001"},
    {"section": "1.3", "recommendation": "Disable all management related services on WAN port", "type": "Manual", "rule_id": "FG-NET-002"},

    # 2.1 General Settings
    {"section": "2.1.1", "recommendation": "Ensure 'Pre-Login Banner' is set", "type": "Automated", "rule_id": "FG-BL-092"},
    {"section": "2.1.2", "recommendation": "Ensure 'Post-Login-Banner' is set", "type": "Automated", "rule_id": "FG-SYS-001"},
    {"section": "2.1.3", "recommendation": "Ensure timezone is properly configured", "type": "Manual", "rule_id": "FG-SYS-002"},
    {"section": "2.1.4", "recommendation": "Ensure correct system time is configured through NTP", "type": "Automated", "rule_id": "FG-BL-040"},
    {"section": "2.1.5", "recommendation": "Ensure hostname is set", "type": "Automated", "rule_id": "FG-SYS-003"},
    {"section": "2.1.7", "recommendation": "Disable USB Firmware and configuration installation", "type": "Automated", "rule_id": "FG-SYS-005"},
    {"section": "2.1.8", "recommendation": "Disable static keys for TLS", "type": "Automated", "rule_id": "FG-SYS-006"},
    {"section": "2.1.9", "recommendation": "Enable Global Strong Encryption", "type": "Automated", "rule_id": "FG-BL-090"},
    {"section": "2.1.10", "recommendation": "Ensure management GUI listens on secure TLS version", "type": "Manual", "rule_id": "FG-BL-005"},

    # 2.2 Password Policy
    {"section": "2.2.1", "recommendation": "Ensure 'Password Policy' is enabled", "type": "Automated", "rule_id": "FG-BL-030"},
    {"section": "2.2.2", "recommendation": "Ensure administrator password retries and lockout time are configured", "type": "Automated", "rule_id": "FG-PW-001"},

    # 2.3 SNMP
    {"section": "2.3.1", "recommendation": "Ensure only SNMPv3 is enabled", "type": "Automated", "rule_id": "FG-BL-050"},
    {"section": "2.3.2", "recommendation": "Allow only trusted hosts in SNMPv3", "type": "Manual", "rule_id": "FG-SNMP-001"},

    # 2.4 Administrators and Admin Profiles
    {"section": "2.4.1", "recommendation": "Ensure default 'admin' password is changed", "type": "Manual", "rule_id": "FG-BL-021"},
    {"section": "2.4.2", "recommendation": "Ensure all the login accounts having specific trusted hosts enabled", "type": "Manual", "rule_id": "FG-BL-020"},
    {"section": "2.4.3", "recommendation": "Ensure admin accounts with different privileges have their correct profiles assigned", "type": "Manual", "rule_id": "FG-ADM-001"},
    {"section": "2.4.4", "recommendation": "Ensure idle timeout time is configured", "type": "Automated", "rule_id": "FG-BL-004"},
    {"section": "2.4.5", "recommendation": "Ensure only encrypted access channels are enabled", "type": "Automated", "rule_id": "FG-BL-002"},
    {"section": "2.4.6", "recommendation": "Apply Local-in Policies", "type": "Manual", "rule_id": "FG-LIP-001"},
    {"section": "2.4.7", "recommendation": "Ensure default Admin ports are changed", "type": "Manual", "rule_id": "FG-BL-007"},

    # 2.5 High Availability
    {"section": "2.5.1", "recommendation": "Ensure High Availability configuration is enabled", "type": "Automated", "rule_id": "FG-HA-004"},
    {"section": "2.5.2", "recommendation": "Ensure 'Monitor Interfaces' for High Availability devices is enabled", "type": "Automated", "rule_id": "FG-HA-005"},
    {"section": "2.5.3", "recommendation": "Ensure HA Reserved Management Interface is configured", "type": "Manual", "rule_id": "FG-HA-006"},

    # 3 Policy and Objects
    # FG-POL-001 disabled per client request — hidden from audit and UI.
    # {"section": "3.1", "recommendation": "Ensure that unused policies are reviewed regularly", "type": "Manual", "rule_id": "FG-POL-001"},
    {"section": "3.2", "recommendation": "Ensure that policies do not use 'ALL' as Service", "type": "Automated", "rule_id": "FG-BL-080"},
    # FG-POL-002 disabled per client request — hidden from audit and UI.
    # {"section": "3.3", "recommendation": "Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB", "type": "Manual", "rule_id": "FG-POL-002"},
    {"section": "3.4", "recommendation": "Ensure logging is enabled on all firewall policies", "type": "Manual", "rule_id": "FG-BL-082"},

    # 4.1 Intrusion Prevention System (IPS)
    {"section": "4.1.1", "recommendation": "Detect Botnet connections", "type": "Manual", "rule_id": "FG-IPS-001"},
    {"section": "4.1.2", "recommendation": "Apply IPS Security Profile to Policies", "type": "Manual", "rule_id": "FG-UTM-003"},

    # 4.2 Antivirus
    {"section": "4.2.2", "recommendation": "Apply Antivirus Security Profile to Policies", "type": "Manual", "rule_id": "FG-UTM-002"},
    {"section": "4.2.4", "recommendation": "Enable AI/heuristic based malware detection", "type": "Automated", "rule_id": "FG-AV-003"},
    {"section": "4.2.5", "recommendation": "Enable grayware detection on antivirus", "type": "Automated", "rule_id": "FG-AV-004"},

    # 4.3 DNS Filter
    {"section": "4.3.1", "recommendation": "Enable Botnet C&C Domain Blocking DNS Filter", "type": "Automated", "rule_id": "FG-DNS-001"},
    {"section": "4.3.2", "recommendation": "Ensure DNS Filter logs all DNS queries and responses", "type": "Manual", "rule_id": "FG-DNS-002"},
    {"section": "4.3.3", "recommendation": "Apply DNS Filter Security Profile to Policies", "type": "Manual", "rule_id": "FG-DNS-003"},

    # 4.4 Application Control
    {"section": "4.4.1", "recommendation": "Block high risk categories on Application Control", "type": "Manual", "rule_id": "FG-APP-001"},
    {"section": "4.4.2", "recommendation": "Block applications running on non-default ports", "type": "Automated", "rule_id": "FG-APP-002"},
    {"section": "4.4.3", "recommendation": "Ensure all Application Control related traffic is logged", "type": "Manual", "rule_id": "FG-APP-003"},
    {"section": "4.4.4", "recommendation": "Apply Application Control Security Profile to Policies", "type": "Manual", "rule_id": "FG-APP-004"},

    # 5 Security Fabric
    {"section": "5.2.1.1", "recommendation": "Ensure Security Fabric is Configured", "type": "Automated", "rule_id": "FG-FAB-002"},

    # 6 VPN
    {"section": "6.1.1", "recommendation": "Apply a Trusted Signed Certificate for VPN Portal", "type": "Manual", "rule_id": "FG-VPN-SSL-003"},
    {"section": "6.1.2", "recommendation": "Enable Limited TLS Versions for SSL VPN", "type": "Manual", "rule_id": "FG-VPN-SSL-001"},

    # 7 Users and Authentication
    {"section": "7.1", "recommendation": "Configuring the maximum login attempts and lockout period", "type": "Automated", "rule_id": "FG-USER-001"},

    # 8 Logs and Reports
    {"section": "8.1.1", "recommendation": "Enable Event Logging", "type": "Automated", "rule_id": "FG-LOG-001"},
    {"section": "8.2.1", "recommendation": "Encrypt Log Transmission to FortiAnalyzer / FortiManager", "type": "Automated", "rule_id": "FG-LOG-002"},
    {"section": "8.3.1", "recommendation": "Centralized Logging and Reporting", "type": "Automated", "rule_id": "FG-FAZ-001"},
]


def get_all_sections() -> List[Dict[str, str]]:
    """Return all CIS benchmark sections."""
    return CIS_BENCHMARK_SECTIONS


def get_section_by_id(section: str) -> Optional[Dict[str, str]]:
    """Return a specific benchmark section by its section number."""
    for s in CIS_BENCHMARK_SECTIONS:
        if s["section"] == section:
            return s
    return None


def get_rule_id_for_section(section: str) -> Optional[str]:
    """Return the backing control ID for a CIS section number."""
    sec = get_section_by_id(section)
    return sec["rule_id"] if sec else None


def get_benchmark_summary() -> Dict[str, Any]:
    """Return coverage counts for the benchmark (by recommendation type)."""
    automated = sum(1 for s in CIS_BENCHMARK_SECTIONS if s["type"] == "Automated")
    manual = sum(1 for s in CIS_BENCHMARK_SECTIONS if s["type"] == "Manual")
    return {
        "version": CIS_BENCHMARK_VERSION,
        "total_sections": len(CIS_BENCHMARK_SECTIONS),
        "automated": automated,
        "manual": manual,
    }


# Friendly labels for the per-control evaluation scope (see rules.py).
_SCOPE_LABELS: Dict[str, str] = {
    "global": "Global",
    "vdom": "Per-VDOM",
    "vdom_root": "Management VDOM",
}


def _section_sort_key(section: str) -> List[int]:
    """Numeric sort key so 2.1.10 sorts after 2.1.2."""
    return [int(p) for p in section.split(".")]


def get_benchmark_catalog() -> Dict[str, Any]:
    """
    Return the full CIS checklist joined with the backing control catalog.

    Each entry pairs a benchmark section (number / recommendation / type) with
    the control that implements it (id, scope, severity, command, remediation),
    so the whole 49-item checklist can be displayed without running an audit.
    """
    # Imported here to avoid any import-time coupling between the map and the catalog.
    from .rules import get_fortinet_controls

    controls = {c.cis_id: c for c in get_fortinet_controls()}

    items: List[Dict[str, Any]] = []
    for section in sorted(CIS_BENCHMARK_SECTIONS, key=lambda s: _section_sort_key(s["section"])):
        control = controls.get(section["section"])
        items.append({
            "section": section["section"],
            "recommendation": section["recommendation"],
            "type": section["type"],
            "control_id": section["rule_id"],
            "section_group": control.cis_section if control else "",
            "scope": _SCOPE_LABELS.get(control.scope, control.scope) if control else "",
            "severity": control.severity if control else "",
            "command": control.rules[0].cmd if (control and control.rules) else "",
            "remediation": control.remediation if control else "",
        })

    summary = get_benchmark_summary()
    return {
        "version": CIS_BENCHMARK_VERSION,
        "total": summary["total_sections"],
        "automated": summary["automated"],
        "manual": summary["manual"],
        "controls": items,
    }
