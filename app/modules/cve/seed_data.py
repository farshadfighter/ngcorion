"""
Curated CVE seed data.

Deliberately small: these are real, publicly documented, high-confidence
CVEs (all CISA Known Exploited Vulnerabilities, heavily reported and
patched by the vendor) for the two product families this app's own
audit/hardening modules already know well (Fortinet FortiOS, Apache HTTP
Server) - not a claim of comprehensive coverage. This exists so a fresh
install has real, verifiable data with no internet access; grow it for
real via "Sync from NVD" (app/modules/cve/nvd_sync.py) once the
deployment has connectivity, or by adding more curated rows here.

Each CVE that affects several disjoint version branches (common - a vendor
patches multiple release trains at once) gets one row per branch; see
CveRecord's docstring in app/models/cve.py for why cve_id is not unique.
"""
from datetime import datetime
from typing import Any

SEED_RECORDS: list[dict[str, Any]] = [
    # ------------------------------------------------------------------
    # CVE-2022-42475 - FortiOS SSL-VPN heap-based buffer overflow.
    # Unauthenticated remote code execution via the SSL-VPN daemon.
    # CISA KEV; actively exploited in the wild before/around disclosure.
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2022-42475", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "7.2.0", "affected_version_max": "7.2.2", "fixed_version": "7.2.3",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Heap-based buffer overflow in FortiOS SSL-VPN allows an unauthenticated "
                    "attacker to execute arbitrary code via specially crafted requests.",
        "recommendation": "Upgrade to FortiOS 7.2.3 or later. If upgrading immediately isn't "
                           "possible, disable the SSL-VPN interface until patched.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-22-398",
        "published_date": datetime(2022, 12, 12),
    },
    {
        "cve_id": "CVE-2022-42475", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "7.0.0", "affected_version_max": "7.0.8", "fixed_version": "7.0.9",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Heap-based buffer overflow in FortiOS SSL-VPN allows an unauthenticated "
                    "attacker to execute arbitrary code via specially crafted requests.",
        "recommendation": "Upgrade to FortiOS 7.0.9 or later. If upgrading immediately isn't "
                           "possible, disable the SSL-VPN interface until patched.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-22-398",
        "published_date": datetime(2022, 12, 12),
    },
    {
        "cve_id": "CVE-2022-42475", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "6.4.0", "affected_version_max": "6.4.10", "fixed_version": "6.4.11",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Heap-based buffer overflow in FortiOS SSL-VPN allows an unauthenticated "
                    "attacker to execute arbitrary code via specially crafted requests.",
        "recommendation": "Upgrade to FortiOS 6.4.11 or later. If upgrading immediately isn't "
                           "possible, disable the SSL-VPN interface until patched.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-22-398",
        "published_date": datetime(2022, 12, 12),
    },
    {
        "cve_id": "CVE-2022-42475", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "6.2.0", "affected_version_max": "6.2.11", "fixed_version": "6.2.12",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Heap-based buffer overflow in FortiOS SSL-VPN allows an unauthenticated "
                    "attacker to execute arbitrary code via specially crafted requests.",
        "recommendation": "Upgrade to FortiOS 6.2.12 or later. If upgrading immediately isn't "
                           "possible, disable the SSL-VPN interface until patched.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-22-398",
        "published_date": datetime(2022, 12, 12),
    },

    # ------------------------------------------------------------------
    # CVE-2023-27997 ("Xortigate") - FortiOS/FortiProxy SSL-VPN
    # heap-based buffer overflow. Unauthenticated RCE. CISA KEV.
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2023-27997", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "7.2.0", "affected_version_max": "7.2.4", "fixed_version": "7.2.5",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Heap-based buffer overflow in FortiOS/FortiProxy SSL-VPN may allow a "
                    "remote unauthenticated attacker to execute arbitrary code or commands.",
        "recommendation": "Upgrade to FortiOS 7.2.5 or later.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-23-097",
        "published_date": datetime(2023, 6, 11),
    },
    {
        "cve_id": "CVE-2023-27997", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "7.0.0", "affected_version_max": "7.0.11", "fixed_version": "7.0.12",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Heap-based buffer overflow in FortiOS/FortiProxy SSL-VPN may allow a "
                    "remote unauthenticated attacker to execute arbitrary code or commands.",
        "recommendation": "Upgrade to FortiOS 7.0.12 or later.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-23-097",
        "published_date": datetime(2023, 6, 11),
    },
    {
        "cve_id": "CVE-2023-27997", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "6.4.0", "affected_version_max": "6.4.12", "fixed_version": "6.4.13",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Heap-based buffer overflow in FortiOS/FortiProxy SSL-VPN may allow a "
                    "remote unauthenticated attacker to execute arbitrary code or commands.",
        "recommendation": "Upgrade to FortiOS 6.4.13 or later.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-23-097",
        "published_date": datetime(2023, 6, 11),
    },

    # ------------------------------------------------------------------
    # CVE-2024-21762 - FortiOS SSL-VPN out-of-bounds write. Unauthenticated
    # RCE via crafted HTTP requests. CISA KEV.
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2024-21762", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "7.4.0", "affected_version_max": "7.4.2", "fixed_version": "7.4.3",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Out-of-bounds write in FortiOS SSL-VPN may allow a remote unauthenticated "
                    "attacker to execute arbitrary code or commands via specially crafted "
                    "HTTP requests.",
        "recommendation": "Upgrade to FortiOS 7.4.3 or later. If upgrading immediately isn't "
                           "possible, disable the SSL-VPN interface until patched.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-24-015",
        "published_date": datetime(2024, 2, 8),
    },
    {
        "cve_id": "CVE-2024-21762", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "7.2.0", "affected_version_max": "7.2.6", "fixed_version": "7.2.7",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Out-of-bounds write in FortiOS SSL-VPN may allow a remote unauthenticated "
                    "attacker to execute arbitrary code or commands via specially crafted "
                    "HTTP requests.",
        "recommendation": "Upgrade to FortiOS 7.2.7 or later. If upgrading immediately isn't "
                           "possible, disable the SSL-VPN interface until patched.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-24-015",
        "published_date": datetime(2024, 2, 8),
    },
    {
        "cve_id": "CVE-2024-21762", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "7.0.0", "affected_version_max": "7.0.13", "fixed_version": "7.0.14",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Out-of-bounds write in FortiOS SSL-VPN may allow a remote unauthenticated "
                    "attacker to execute arbitrary code or commands via specially crafted "
                    "HTTP requests.",
        "recommendation": "Upgrade to FortiOS 7.0.14 or later. If upgrading immediately isn't "
                           "possible, disable the SSL-VPN interface until patched.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-24-015",
        "published_date": datetime(2024, 2, 8),
    },
    {
        "cve_id": "CVE-2024-21762", "vendor": "Fortinet", "product": "FortiOS",
        "product_keyword": "fortios",
        "affected_version_min": "6.4.0", "affected_version_max": "6.4.14", "fixed_version": "6.4.15",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "Out-of-bounds write in FortiOS SSL-VPN may allow a remote unauthenticated "
                    "attacker to execute arbitrary code or commands via specially crafted "
                    "HTTP requests.",
        "recommendation": "Upgrade to FortiOS 6.4.15 or later. If upgrading immediately isn't "
                           "possible, disable the SSL-VPN interface until patched.",
        "reference_url": "https://www.fortiguard.com/psirt/FG-IR-24-015",
        "published_date": datetime(2024, 2, 8),
    },

    # ------------------------------------------------------------------
    # CVE-2021-41773 - Apache HTTP Server path traversal / RCE (mod_cgi).
    # Affected exactly 2.4.49; the 2.4.50 fix was itself incomplete
    # (see CVE-2021-42013 below). CISA KEV.
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2021-41773", "vendor": "Apache Software Foundation", "product": "Apache HTTP Server",
        "product_keyword": "apache",
        "affected_version_min": "2.4.49", "affected_version_max": "2.4.49", "fixed_version": "2.4.51",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "A path traversal flaw in Apache HTTP Server 2.4.49 allows mapping URLs to "
                    "files outside the configured document root; if CGI scripts are enabled "
                    "it can also lead to remote code execution.",
        "recommendation": "Upgrade to Apache HTTP Server 2.4.51 or later (2.4.50 alone does "
                           "not fully fix this - see CVE-2021-42013).",
        "reference_url": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "published_date": datetime(2021, 10, 5),
    },

    # ------------------------------------------------------------------
    # CVE-2021-42013 - incomplete fix for CVE-2021-41773 in 2.4.50,
    # re-enabling the same path traversal / RCE. CISA KEV.
    # ------------------------------------------------------------------
    {
        "cve_id": "CVE-2021-42013", "vendor": "Apache Software Foundation", "product": "Apache HTTP Server",
        "product_keyword": "apache",
        "affected_version_min": "2.4.50", "affected_version_max": "2.4.50", "fixed_version": "2.4.51",
        "severity": "critical", "cvss_score": 9.8,
        "summary": "The fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was incomplete: "
                    "an attacker can still use a path traversal attack to map URLs to files "
                    "outside the document root, and to RCE if CGI scripts are enabled.",
        "recommendation": "Upgrade to Apache HTTP Server 2.4.51 or later.",
        "reference_url": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "published_date": datetime(2021, 10, 7),
    },
]


def seed_source_marker() -> str:
    return "seed"
