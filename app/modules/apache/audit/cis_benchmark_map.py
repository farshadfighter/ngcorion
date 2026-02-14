"""
CIS Apache HTTP Server 2.4 Benchmark - Section Mapping

Maps CIS Benchmark section numbers to internal rule IDs.
Based on CIS Apache HTTP Server 2.4 Benchmark
"""

from typing import List, Dict, Any, Optional


# CIS Benchmark Version
CIS_BENCHMARK_VERSION = "CIS Apache HTTP Server 2.4 Benchmark"


# Complete mapping of all CIS sections
# Maps CIS section numbers to internal rule IDs used in rules.py
CIS_BENCHMARK_SECTIONS: List[Dict[str, str]] = [
    # SECTION 2: MINIMIZE APACHE MODULES
    {
        "section": "2.3",
        "recommendation": "Ensure WebDAV modules are disabled",
        "rule_id": "APACHE-L1-2.3",
    },
    {
        "section": "2.4",
        "recommendation": "Ensure mod_status is restricted or disabled",
        "rule_id": "APACHE-L1-2.4",
    },
    {
        "section": "2.5",
        "recommendation": "Ensure mod_info is disabled",
        "rule_id": "APACHE-L1-2.5",
    },
    {
        "section": "2.6",
        "recommendation": "Ensure mod_userdir is disabled",
        "rule_id": "APACHE-L1-2.6",
    },
    {
        "section": "2.7",
        "recommendation": "Ensure mod_autoindex is disabled or Indexes option is off",
        "rule_id": "APACHE-L1-2.7",
    },

    # SECTION 3: PRINCIPLES, PERMISSIONS, AND OWNERSHIP
    {
        "section": "3.1",
        "recommendation": "Ensure Apache runs as a non-root user",
        "rule_id": "APACHE-L1-3.1",
    },
    {
        "section": "3.2",
        "recommendation": "Ensure Apache user is a dedicated system account",
        "rule_id": "APACHE-L1-3.2",
    },
    {
        "section": "3.3",
        "recommendation": "Ensure Apache user has a non-login shell",
        "rule_id": "APACHE-L1-3.3",
    },
    {
        "section": "3.4",
        "recommendation": "Ensure Apache user account is locked",
        "rule_id": "APACHE-L1-3.4",
    },
    {
        "section": "3.5",
        "recommendation": "Ensure Apache config directory has restrictive permissions",
        "rule_id": "APACHE-L1-3.5",
    },
    {
        "section": "3.6",
        "recommendation": "Ensure Apache main config file has restrictive permissions",
        "rule_id": "APACHE-L1-3.6",
    },
    {
        "section": "3.8",
        "recommendation": "Ensure Apache log directory has restrictive permissions",
        "rule_id": "APACHE-L1-3.8",
    },

    # SECTION 4: APACHE ACCESS CONTROL
    {
        "section": "4.1",
        "recommendation": "Ensure default access is denied",
        "rule_id": "APACHE-L1-4.1",
    },
    {
        "section": "4.2",
        "recommendation": "Ensure AllowOverride is set appropriately",
        "rule_id": "APACHE-L1-4.2",
    },
    {
        "section": "4.4",
        "recommendation": "Ensure Options directive is restrictive",
        "rule_id": "APACHE-L1-4.4",
    },

    # SECTION 5: MINIMIZE FEATURES AND CONTENT
    {
        "section": "5.8",
        "recommendation": "Ensure HTTP TRACE method is disabled",
        "rule_id": "APACHE-L1-5.8",
    },

    # SECTION 6: OPERATIONS - LOGGING
    {
        "section": "6.1",
        "recommendation": "Ensure error logging is configured",
        "rule_id": "APACHE-L1-6.1",
    },
    {
        "section": "6.3",
        "recommendation": "Ensure access logging is configured",
        "rule_id": "APACHE-L1-6.3",
    },

    # SECTION 7: REQUEST LIMITS
    {
        "section": "7.1",
        "recommendation": "Ensure Timeout is set appropriately",
        "rule_id": "APACHE-L1-7.1",
    },

    # SECTION 8: SSL/TLS CONFIGURATION
    {
        "section": "8.1",
        "recommendation": "Ensure SSL/TLS module is enabled",
        "rule_id": "APACHE-L1-8.1",
    },
    {
        "section": "8.3",
        "recommendation": "Ensure insecure SSL/TLS protocols are disabled",
        "rule_id": "APACHE-L1-8.3",
    },
    {
        "section": "8.4",
        "recommendation": "Ensure strong SSL cipher suites are configured",
        "rule_id": "APACHE-L1-8.4",
    },
    {
        "section": "8.5",
        "recommendation": "Ensure SSLHonorCipherOrder is enabled",
        "rule_id": "APACHE-L1-8.5",
    },
    {
        "section": "8.6",
        "recommendation": "Ensure SSL compression is disabled",
        "rule_id": "APACHE-L1-8.6",
    },
    {
        "section": "8.8",
        "recommendation": "Ensure HSTS header is configured",
        "rule_id": "APACHE-L1-8.8",
    },

    # SECTION 9: INFORMATION LEAKAGE
    {
        "section": "9.1",
        "recommendation": "Ensure ServerTokens is set to Prod",
        "rule_id": "APACHE-L1-9.1",
    },
    {
        "section": "9.2",
        "recommendation": "Ensure ServerSignature is Off",
        "rule_id": "APACHE-L1-9.2",
    },
    {
        "section": "9.3",
        "recommendation": "Ensure FileETag is configured securely",
        "rule_id": "APACHE-L2-9.3",
    },

    # SECTION 10: HTTP CONFIGURATION OPTIONS
    {
        "section": "10.4",
        "recommendation": "Ensure Content-Security-Policy header is configured",
        "rule_id": "APACHE-L2-10.4",
    },
    {
        "section": "10.5",
        "recommendation": "Ensure X-Content-Type-Options header is configured",
        "rule_id": "APACHE-L1-10.5",
    },
    {
        "section": "10.6",
        "recommendation": "Ensure X-Frame-Options header is configured",
        "rule_id": "APACHE-L1-10.6",
    },
    {
        "section": "10.7",
        "recommendation": "Ensure X-XSS-Protection header is configured",
        "rule_id": "APACHE-L2-10.7",
    },
    {
        "section": "10.8",
        "recommendation": "Ensure Referrer-Policy header is configured",
        "rule_id": "APACHE-L2-10.8",
    },
]


def get_rule_id_by_section(section: str) -> Optional[str]:
    """
    Get the internal rule ID for a CIS section.

    Args:
        section: CIS section number (e.g., "2.3", "8.1")

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
        category_prefix: Section prefix (e.g., "2" for modules, "8" for SSL/TLS)

    Returns:
        List of section mappings in that category
    """
    return [
        mapping for mapping in CIS_BENCHMARK_SECTIONS
        if mapping["section"].startswith(category_prefix + ".")
    ]


def get_benchmark_summary() -> Dict[str, Any]:
    """Get summary of the CIS benchmark coverage."""
    l1_rules = [m for m in CIS_BENCHMARK_SECTIONS if "L1" in m["rule_id"]]
    l2_rules = [m for m in CIS_BENCHMARK_SECTIONS if "L2" in m["rule_id"]]

    return {
        "benchmark_version": CIS_BENCHMARK_VERSION,
        "total_rules": len(CIS_BENCHMARK_SECTIONS),
        "level_1_rules": len(l1_rules),
        "level_2_rules": len(l2_rules),
        "categories": {
            "2.x Modules": len(get_sections_by_category("2")),
            "3.x Permissions": len(get_sections_by_category("3")),
            "4.x Access Control": len(get_sections_by_category("4")),
            "5.x Features": len(get_sections_by_category("5")),
            "6.x Logging": len(get_sections_by_category("6")),
            "7.x Request Limits": len(get_sections_by_category("7")),
            "8.x SSL/TLS": len(get_sections_by_category("8")),
            "9.x Information Leakage": len(get_sections_by_category("9")),
            "10.x HTTP Configuration": len(get_sections_by_category("10")),
        }
    }
