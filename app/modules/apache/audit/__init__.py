"""
Apache Audit Module

CIS compliance auditing for Apache HTTP Server 2.4.x
Based on CIS Apache HTTP Server 2.4 Benchmark
"""
from .router import router
from .service import ApacheAuditService
from .rules import (
    build_apache_cis_rules,
    filter_rules_by_profile,
    evaluate_compliance,
    ApacheCISRule
)
from .audit_commands import get_apache_audit_commands

__all__ = [
    "router",
    "ApacheAuditService",
    "build_apache_cis_rules",
    "filter_rules_by_profile",
    "evaluate_compliance",
    "ApacheCISRule",
    "get_apache_audit_commands",
]
