"""
Cisco Audit Module

CIS compliance auditing for Cisco IOS/IOS-XE devices.
"""
from .router import router
from .audit_logs_router import router as audit_logs_router
from .service import AuditService
from .ssh_client import CiscoSSHClient, redact_sensitive_data
from .rules import build_all_cisco_cis_rules, evaluate_compliance, filter_rules_by_profile, build_cis_benchmark_rules
from .cis_benchmark_map import CIS_BENCHMARK_SECTIONS, CIS_BENCHMARK_VERSION

__all__ = [
    "router",
    "audit_logs_router",
    "AuditService",
    "CiscoSSHClient",
    "redact_sensitive_data",
    "build_all_cisco_cis_rules",
    "evaluate_compliance",
    "filter_rules_by_profile",
    "build_cis_benchmark_rules",
    "CIS_BENCHMARK_SECTIONS",
    "CIS_BENCHMARK_VERSION",
]
