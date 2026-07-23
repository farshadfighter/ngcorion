"""
CIS Apache HTTP Server 2.4 Benchmark - Section Mapping

Maps CIS Benchmark section numbers to internal rule IDs.
Based on CIS Apache HTTP Server 2.4 Benchmark v2.0.0.

The mapping is derived from the rule registry in rules.py so the two can
never drift apart.
"""

from typing import List, Dict, Any, Optional

from .rules import build_apache_cis_rules


# CIS Benchmark Version
CIS_BENCHMARK_VERSION = "CIS Apache HTTP Server 2.4 Benchmark v2.0.0"


def _build_sections() -> List[Dict[str, str]]:
    return [
        {
            "section": rule.cis_section,
            "recommendation": rule.title,
            "rule_id": rule.id,
            "level": rule.level,
            "type": "Manual" if rule.manual else "Automated",
        }
        for rule in build_apache_cis_rules()
    ]


# Complete mapping of all CIS sections to internal rule IDs
CIS_BENCHMARK_SECTIONS: List[Dict[str, str]] = _build_sections()


def get_rule_id_by_section(section: str) -> Optional[str]:
    """
    Get the internal rule ID for a CIS section.

    Args:
        section: CIS section number (e.g., "2.3", "7.1")

    Returns:
        Internal rule ID or None if not found
    """
    for mapping in CIS_BENCHMARK_SECTIONS:
        if mapping["section"] == section:
            return mapping["rule_id"]
    return None


def get_section_by_rule_id(rule_id: str) -> Optional[Dict[str, str]]:
    """
    Get the CIS section info for a rule ID.

    Args:
        rule_id: Internal rule ID (e.g., "APACHE-L1-2.3")

    Returns:
        Section mapping dict or None if not found
    """
    for mapping in CIS_BENCHMARK_SECTIONS:
        if mapping["rule_id"] == rule_id:
            return mapping
    return None


def get_all_sections() -> List[Dict[str, str]]:
    """Get all CIS benchmark sections."""
    return CIS_BENCHMARK_SECTIONS


def get_sections_by_category(category_prefix: str) -> List[Dict[str, str]]:
    """
    Get CIS sections by category prefix.

    Args:
        category_prefix: Section prefix (e.g., "2" for modules, "7" for SSL/TLS)

    Returns:
        List of section mappings in that category
    """
    return [
        mapping for mapping in CIS_BENCHMARK_SECTIONS
        if mapping["section"].startswith(category_prefix + ".")
    ]


def get_benchmark_summary() -> Dict[str, Any]:
    """Get summary of the CIS benchmark coverage."""
    l1_rules = [m for m in CIS_BENCHMARK_SECTIONS if m["level"] == "L1"]
    l2_rules = [m for m in CIS_BENCHMARK_SECTIONS if m["level"] == "L2"]
    manual_rules = [m for m in CIS_BENCHMARK_SECTIONS if m["type"] == "Manual"]

    return {
        "benchmark_version": CIS_BENCHMARK_VERSION,
        "total_rules": len(CIS_BENCHMARK_SECTIONS),
        "level_1_rules": len(l1_rules),
        "level_2_rules": len(l2_rules),
        "manual_rules": len(manual_rules),
        "automated_rules": len(CIS_BENCHMARK_SECTIONS) - len(manual_rules),
        "categories": {
            "1.x Planning and Installation": len(get_sections_by_category("1")),
            "2.x Minimize Apache Modules": len(get_sections_by_category("2")),
            "3.x Permissions and Ownership": len(get_sections_by_category("3")),
            "4.x Access Control": len(get_sections_by_category("4")),
            "5.x Features, Content and Options": len(get_sections_by_category("5")),
            "6.x Logging, Monitoring, Maintenance": len(get_sections_by_category("6")),
            "7.x SSL/TLS": len(get_sections_by_category("7")),
            "8.x Information Leakage": len(get_sections_by_category("8")),
            "9.x DoS Mitigations": len(get_sections_by_category("9")),
            "10.x Request Limits": len(get_sections_by_category("10")),
            "11.x SELinux": len(get_sections_by_category("11")),
            "12.x AppArmor": len(get_sections_by_category("12")),
        }
    }
